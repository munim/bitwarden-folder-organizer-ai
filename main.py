"""bw-driven Bitwarden vault organizer.

Reads vault data using the Bitwarden CLI (`bw`), categorizes items in batches
using an LLM, then moves items by updating folderId (personal vault) or replacing
collection assignments (organization items).

Security: NEVER sends passwords, notes, TOTP, or custom field values to the LLM.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Mapping, Optional, Tuple

from classify_bitwarden_vault_items import (
    BwItemSafe,
    bw,
    bw_create_folder,
    bw_create_org_collection,
    bw_list_folders,
    bw_list_items,
    bw_list_org_collections,
    bw_set_item_collections_replace,
    bw_set_item_folder,
    bw_status,
    category_to_label,
    categorize_batch,
    load_domain_folder_map,
    normalize_bw_item_for_llm,
)


# Bitwarden item type codes vary by version; secure notes are commonly type=2.
SECURE_NOTE_TYPE = 2


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Categorize and move Bitwarden items using bw CLI"
    )

    # LLM
    parser.add_argument(
        "--provider", choices=["openrouter", "requesty"], default="openrouter"
    )
    parser.add_argument("--model", default="claude-3-haiku-20240307")
    parser.add_argument("-b", "--batch-size", type=int, default=10)
    parser.add_argument("--max-batches", type=int)
    parser.add_argument("--domain-folder-map")

    # Classification toggles
    parser.add_argument("--check-reachability", action="store_true")

    # Bitwarden access
    parser.add_argument(
        "--session", help="BW session token (otherwise uses BW_SESSION env var)"
    )
    parser.add_argument(
        "--sync", action="store_true", help="Run bw sync before listing items"
    )

    # Filters
    parser.add_argument("--search")
    parser.add_argument("--folderid")
    parser.add_argument("--collectionid")
    parser.add_argument("--organizationid")
    parser.add_argument("--trash", action="store_true")

    # Execution
    parser.add_argument("--apply", action="store_true", help="Apply changes to vault")
    parser.add_argument(
        "--dry-run", action="store_true", help="Only print planned changes (default)"
    )
    parser.add_argument("--sleep-between-batches", type=float, default=5)
    parser.add_argument("--item-delay", type=float, default=0.2)

    args = parser.parse_args(argv)
    if not args.apply:
        args.dry_run = True
    return args


def require_unlocked(session: Optional[str]) -> None:
    status = bw_status(session=session)
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
    folders: List[Mapping[str, Any]],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    id_to_name: Dict[str, str] = {}
    name_to_id: Dict[str, str] = {}
    for f in folders:
        folder_id = f.get("id")
        name = f.get("name")
        if isinstance(folder_id, str) and isinstance(name, str):
            id_to_name[folder_id] = name
            name_to_id[name] = folder_id
    return id_to_name, name_to_id


def is_org_item(item: Mapping[str, Any]) -> bool:
    org_id = item.get("organizationId")
    return isinstance(org_id, str) and org_id.strip() != ""


def item_current_location(
    item: Mapping[str, Any], folder_id_to_name: Mapping[str, str]
) -> str:
    if is_org_item(item):
        return f"org:{item.get('organizationId')}"
    folder_id = item.get("folderId")
    if isinstance(folder_id, str) and folder_id:
        return folder_id_to_name.get(folder_id, "")
    return ""


def safe_items_from_bw_items(
    items: List[Mapping[str, Any]],
    folder_id_to_name: Mapping[str, str],
) -> List[Dict[str, Any]]:
    safe: List[Dict[str, Any]] = []
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
    label: str, name_to_id: Dict[str, str], session: Optional[str]
) -> str:
    if label in name_to_id:
        return name_to_id[label]
    created = bw_create_folder(label, session=session)
    folder_id = str(created.get("id") or "")
    if not folder_id:
        raise RuntimeError(f"Failed to create folder: {label}")
    name_to_id[label] = folder_id
    return folder_id


def ensure_org_collection(
    org_id: str,
    label: str,
    org_collection_maps: Dict[str, Dict[str, str]],
    session: Optional[str],
) -> str:
    if org_id not in org_collection_maps:
        collections = bw_list_org_collections(org_id, session=session)
        org_collection_maps[org_id] = {
            str(c.get("name")): str(c.get("id"))
            for c in collections
            if isinstance(c.get("name"), str) and isinstance(c.get("id"), str)
        }

    name_to_id = org_collection_maps[org_id]
    if label in name_to_id:
        return name_to_id[label]

    created = bw_create_org_collection(org_id, label, session=session)
    cid = str(created.get("id") or "")
    if not cid:
        raise RuntimeError(f"Failed to create org collection: {org_id} {label}")
    name_to_id[label] = cid
    return cid


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    session = args.session or os.environ.get("BW_SESSION")

    require_unlocked(session)

    if args.sync:
        bw(["sync"], session=session)

    folders = bw_list_folders(session=session)
    folder_id_to_name, folder_name_to_id = build_folder_maps(folders)

    bw_items = bw_list_items(
        session=session,
        search=args.search,
        folderid=args.folderid,
        collectionid=args.collectionid,
        organizationid=args.organizationid,
        trash=args.trash,
    )

    # Skip secure notes
    filtered_items: List[Mapping[str, Any]] = []
    skipped = 0
    for item in bw_items:
        item_type = int(item.get("type") or 0)
        if item_type == SECURE_NOTE_TYPE:
            skipped += 1
            continue
        filtered_items.append(item)

    safe_items = safe_items_from_bw_items(filtered_items, folder_id_to_name)

    domain_folder_map = None
    folder_set = None
    if args.domain_folder_map:
        domain_folder_map, folder_set = load_domain_folder_map(args.domain_folder_map)

    # Batch classify
    domain_cache: Dict[str, Dict[str, Any]] = {}
    batches = [
        safe_items[i : i + args.batch_size]
        for i in range(0, len(safe_items), args.batch_size)
    ]

    all_results: List[Dict[str, Any]] = []
    max_batches = args.max_batches if args.max_batches is not None else len(batches)

    for idx, batch in enumerate(batches[:max_batches]):
        results = categorize_batch(
            batch,
            model=args.model,
            provider=args.provider,
            domain_category_cache=domain_cache,
            domain_folder_map=domain_folder_map,
            folder_set=folder_set,
            check_reachability=args.check_reachability,
        )
        all_results.extend(results)

        if idx < max_batches - 1:
            time.sleep(args.sleep_between_batches)

    # Build plan
    id_to_item = {
        str(i.get("id")): i for i in filtered_items if isinstance(i.get("id"), str)
    }

    planned_personal: Dict[str, str] = {}
    planned_org: Dict[str, Tuple[str, str]] = {}  # item_id -> (org_id, label)

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

        if is_org_item(item):
            planned_org[item_id] = (str(item.get("organizationId")), label)
        else:
            planned_personal[item_id] = label

    # Dry-run
    label_counts = Counter(planned_personal.values())
    label_counts.update([lbl for _, lbl in planned_org.values()])

    print(f"Scanned: {len(bw_items)} items")
    print(f"Skipped secure notes: {skipped}")
    print(f"Planned moves: {len(planned_personal) + len(planned_org)}")
    if label_counts:
        print("Planned by label:")
        for label, count in label_counts.most_common():
            print(f"  {label}: {count}")

    sample = list(planned_personal.items())[:10]
    if sample:
        print("Sample personal moves:")
        for item_id, label in sample:
            item = id_to_item.get(item_id, {})
            print(f"  {item_id}  {item.get('name', '')} -> {label}")

    sample_org = list(planned_org.items())[:10]
    if sample_org:
        print("Sample org moves:")
        for item_id, (org_id, label) in sample_org:
            item = id_to_item.get(item_id, {})
            print(f"  {item_id}  {item.get('name', '')} (org {org_id}) -> {label}")

    if args.dry_run and not args.apply:
        return 0

    # Apply
    org_collection_maps: Dict[str, Dict[str, str]] = {}

    # Ensure all needed folders/collections exist first
    for label in set(planned_personal.values()):
        ensure_folder(label, folder_name_to_id, session)

    for item_id, (org_id, label) in planned_org.items():
        ensure_org_collection(org_id, label, org_collection_maps, session)

    failures: List[str] = []

    for item_id, label in planned_personal.items():
        try:
            folder_id = ensure_folder(label, folder_name_to_id, session)
            bw_set_item_folder(item_id, folder_id, session=session)
            time.sleep(args.item_delay)
        except Exception as e:
            failures.append(f"personal {item_id}: {e}")

    for item_id, (org_id, label) in planned_org.items():
        try:
            cid = ensure_org_collection(org_id, label, org_collection_maps, session)
            bw_set_item_collections_replace(item_id, org_id, [cid], session=session)
            time.sleep(args.item_delay)
        except Exception as e:
            failures.append(f"org {item_id}: {e}")

    if failures:
        print("Failures:")
        for f in failures:
            print(f"  {f}")
        return 2

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
