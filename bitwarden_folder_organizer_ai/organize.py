from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping

from .bw_cli import BwClient
from .categorize import categorize_batch, category_to_label, load_domain_folder_map
from .models import BwItemSafe, is_org_item
from .progress import estimate_eta, format_duration, progress, shorten_id, truncate_name
from .sanitize import normalize_bw_item_for_llm

SECURE_NOTE_TYPE = 2


@dataclass(frozen=True)
class OrganizeArgs:
    provider: str = "openrouter"
    model: str = "claude-3-haiku-20240307"
    batch_size: int = 10
    max_batches: int | None = None
    domain_folder_map: str | None = None
    check_reachability: bool = False
    sync: bool = False
    search: str | None = None
    folderid: str | None = None
    collectionid: str | None = None
    organizationid: str | None = None
    trash: bool = False
    apply: bool = False
    dry_run: bool = True
    sleep_between_batches: float = 5
    item_delay: float = 0.2


def require_unlocked(bw_client: BwClient) -> None:
    status = bw_client.status()
    vault_status = str(status.get("status") or "")
    if vault_status != "unlocked":
        raise SystemExit(
            "Vault is not unlocked.\n\n"
            "Run:\n"
            "  bw login\n"
            '  export BW_SESSION="$(bw unlock --raw)"\n'
            "Then rerun (or pass --session)."
        )


def build_folder_maps(
    folders: list[Mapping[str, Any]],
) -> tuple[dict[str, str], dict[str, str]]:
    id_to_name: dict[str, str] = {}
    name_to_id: dict[str, str] = {}
    for f in folders:
        folder_id = f.get("id")
        name = f.get("name")
        if isinstance(folder_id, str) and isinstance(name, str):
            id_to_name[folder_id] = name
            name_to_id[name] = folder_id
    return id_to_name, name_to_id


def current_folder_name(
    item: Mapping[str, Any], folder_id_to_name: Mapping[str, str]
) -> str:
    folder_id = item.get("folderId")
    if isinstance(folder_id, str) and folder_id.strip() != "":
        return folder_id_to_name.get(folder_id, "")
    return ""


def safe_items_from_bw_items(
    items: list[Mapping[str, Any]],
    folder_id_to_name: Mapping[str, str],
) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for item in items:
        safe_obj: BwItemSafe = normalize_bw_item_for_llm(item, folder_id_to_name)
        safe.append(
            {
                "id": safe_obj.id,
                "name": safe_obj.name,
                "type": safe_obj.type,
                "folder": safe_obj.folder,
                "login_uri": safe_obj.login_uri,
                "login_username": safe_obj.login_username_masked,
                "custom_field_names": safe_obj.custom_field_names,
            }
        )
    return safe


def ensure_folder(
    label: str, name_to_id: dict[str, str], bw_client: BwClient
) -> tuple[str, bool]:
    if label in name_to_id:
        return name_to_id[label], False
    created = bw_client.create_folder(label)
    folder_id = str(created.get("id") or "")
    if not folder_id:
        raise RuntimeError(f"Failed to create folder: {label}")
    name_to_id[label] = folder_id
    return folder_id, True


def organize_vault(
    *,
    bw_client: BwClient,
    llm_client: Any,
    args: OrganizeArgs,
) -> int:
    require_unlocked(bw_client)

    if args.sync:
        bw_client.sync()

    folders = bw_client.list_folders()
    folder_id_to_name, folder_name_to_id = build_folder_maps(folders)

    bw_items = bw_client.list_items(
        search=args.search,
        folderid=args.folderid,
        collectionid=args.collectionid,
        organizationid=args.organizationid,
        trash=args.trash,
    )

    filtered_items: list[Mapping[str, Any]] = []
    skipped_notes = 0
    for item in bw_items:
        item_type = int(item.get("type") or 0)
        if item_type == SECURE_NOTE_TYPE:
            skipped_notes += 1
            continue
        filtered_items.append(item)

    safe_items = safe_items_from_bw_items(filtered_items, folder_id_to_name)

    domain_folder_map = None
    folder_set = None
    if args.domain_folder_map:
        domain_folder_map, folder_set = load_domain_folder_map(args.domain_folder_map)

    domain_cache: dict[str, dict[str, Any]] = {}
    batches = [
        safe_items[i : i + args.batch_size]
        for i in range(0, len(safe_items), args.batch_size)
    ]

    all_results: list[dict[str, Any]] = []
    max_batches = args.max_batches if args.max_batches is not None else len(batches)

    classify_start = time.time()
    source_counts: Counter[str] = Counter()
    label_counts_running: Counter[str] = Counter()

    for idx, batch in enumerate(batches[:max_batches]):
        total = len(safe_items)
        done_before = len(all_results)
        remaining = max(0, total - done_before)

        progress(
            f"[batch {idx + 1}/{max_batches}] start | batch_size={len(batch)} | "
            f"done={done_before}/{total} | remaining={remaining}"
        )

        batch_start = time.time()
        results = categorize_batch(
            batch,
            llm_client=llm_client,
            domain_category_cache=domain_cache,
            domain_folder_map=domain_folder_map,
            folder_set=folder_set,
            check_reachability=args.check_reachability,
        )
        batch_time = time.time() - batch_start

        all_results.extend(results)

        for res in results:
            source_counts[str(res.get("source") or "unknown")] += 1
            category = str(res.get("category") or "")
            if category:
                label_counts_running[category_to_label(category)] += 1

        top_labels = ", ".join(
            f"{label}={count}" for label, count in label_counts_running.most_common(5)
        )
        sources = " ".join(
            f"{k}={v}" for k, v in source_counts.most_common() if k != "unknown"
        )

        done_after = len(all_results)
        progress(
            f"[batch {idx + 1}/{max_batches}] done in {format_duration(batch_time)} | "
            f"done={done_after}/{total} | eta {estimate_eta(classify_start, done_after, total)}"
        )
        if sources:
            progress(f"  sources: {sources}")
        if top_labels:
            progress(f"  labels(top5): {top_labels}")

        if idx < max_batches - 1:
            progress(
                f"[batch {idx + 1}/{max_batches}] sleeping {args.sleep_between_batches:.1f}s"
            )
            time.sleep(args.sleep_between_batches)

    id_to_item = {
        str(i.get("id")): i for i in filtered_items if isinstance(i.get("id"), str)
    }

    planned_personal: dict[str, str] = {}
    planned_org_folders: dict[str, str] = {}

    skipped_already_correct = 0

    for res in all_results:
        item_id = str(res.get("id") or "")
        if not item_id:
            continue
        category = str(res.get("category") or "")
        if not category:
            continue

        label = category_to_label(category)
        if not label:
            continue

        item = id_to_item.get(item_id)
        if not item:
            continue

        current_label = current_folder_name(item, folder_id_to_name)
        if current_label == label:
            skipped_already_correct += 1
            continue

        if is_org_item(item):
            planned_org_folders[item_id] = label
        else:
            planned_personal[item_id] = label

    label_counts = Counter(planned_personal.values())
    label_counts.update(planned_org_folders.values())

    print(f"Scanned: {len(bw_items)} items")
    print(f"Skipped secure notes: {skipped_notes}")
    print(f"Skipped already-correct: {skipped_already_correct}")
    print(f"Planned moves: {len(planned_personal) + len(planned_org_folders)}")
    if label_counts:
        print("Planned by label:")
        for label, count in label_counts.most_common():
            print(f"  {label}: {count}")

    sample = list(planned_personal.items())[:10]
    if sample:
        print("Sample personal moves:")
        for item_id, label in sample:
            item = id_to_item.get(item_id, {})
            print(
                f"  {shorten_id(item_id)}  {truncate_name(item.get('name', ''))} -> {label}"
            )

    sample_org = list(planned_org_folders.items())[:10]
    if sample_org:
        print("Sample org moves:")
        for item_id, label in sample_org:
            item = id_to_item.get(item_id, {})
            org_id = str(item.get("organizationId") or "")
            print(
                f"  {shorten_id(item_id)}  {truncate_name(item.get('name', ''))} (org {shorten_id(org_id)}) -> {label}"
            )

    if args.dry_run and not args.apply:
        return 0

    total_personal = len(planned_personal)
    total_org = len(planned_org_folders)
    failures: list[str] = []

    progress(
        f"[apply] start | personal={total_personal} | org={total_org} | item_delay={args.item_delay:.1f}s"
    )

    needed_labels = set(planned_personal.values()) | set(planned_org_folders.values())
    created_folders: set[str] = set()
    for label in sorted(needed_labels):
        folder_id, created = ensure_folder(label, folder_name_to_id, bw_client)
        if created and label not in created_folders:
            created_folders.add(label)
            progress(f"[create folder] {label} id={shorten_id(folder_id)}")

    apply_personal_start = time.time()
    for i, (item_id, label) in enumerate(planned_personal.items(), start=1):
        item = id_to_item.get(item_id, {})
        item_name = truncate_name(str(item.get("name") or ""))
        try:
            folder_id, _ = ensure_folder(label, folder_name_to_id, bw_client)
            bw_client.set_item_folder(item_id, folder_id)
            progress(
                f"[apply personal {i}/{total_personal}] ok id={shorten_id(item_id)} "
                f"name={item_name} -> {label} | eta {estimate_eta(apply_personal_start, i, total_personal)}"
            )
            time.sleep(args.item_delay)
        except Exception as e:
            failures.append(f"personal {item_id}: {e}")
            progress(
                f"[apply personal {i}/{total_personal}] FAIL id={shorten_id(item_id)} "
                f"name={item_name} -> {label} | failures={len(failures)}"
            )

    apply_org_start = time.time()
    for i, (item_id, label) in enumerate(planned_org_folders.items(), start=1):
        item = id_to_item.get(item_id, {})
        item_name = truncate_name(str(item.get("name") or ""))
        org_id = str(item.get("organizationId") or "")
        try:
            folder_id, _ = ensure_folder(label, folder_name_to_id, bw_client)
            bw_client.set_item_folder(item_id, folder_id)
            progress(
                f"[apply org {i}/{total_org}] ok id={shorten_id(item_id)} org={shorten_id(org_id)} "
                f"name={item_name} -> {label} | eta {estimate_eta(apply_org_start, i, total_org)}"
            )
            time.sleep(args.item_delay)
        except Exception as e:
            failures.append(f"org {item_id}: {e}")
            progress(
                f"[apply org {i}/{total_org}] FAIL id={shorten_id(item_id)} org={shorten_id(org_id)} "
                f"name={item_name} -> {label} | failures={len(failures)}"
            )

    if failures:
        print("Failures:")
        for f in failures:
            print(f"  {f}")
        return 2

    print("Done.")
    return 0
