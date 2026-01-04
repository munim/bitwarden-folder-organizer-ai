"""Bitwarden vault categorization library (bw CLI based).

This module contains:
- Helpers to read/mutate Bitwarden vault using the Bitwarden CLI (`bw`).
- Sanitization logic to ensure we NEVER send passwords, notes, TOTP, or custom
  field values to an LLM.
- Categorization logic reused/adapted from the earlier export-based script.

This module intentionally has no CLI entrypoint. Use `main.py`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# -----------------------------------------------------------------------------
# LLM safety
# -----------------------------------------------------------------------------

FORBIDDEN_LLM_KEYS = {
    "password",
    "notes",
    "totp",
    "value",  # custom field values
    "card",
    "identity",
}

FORBIDDEN_VALUE_SUBSTRINGS = [
    # Value-level checks kept narrow to avoid false positives.
    # These indicate a likely secret was accidentally included.
    "begin private key",
    "otp",
]


def mask_email_username(username: str) -> str:
    value = (username or "").strip()
    if "@" not in value:
        return value
    _, domain = value.split("@", 1)
    return f"***@{domain}"


def _walk_json(obj: Any) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            out.append((str(k), v))
            out.extend(_walk_json(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_json(v))
    return out


def assert_llm_payload_safe(payload: str) -> None:
    """Fail-closed safety check.

    This must avoid false positives in normal allowed metadata (e.g. an item name
    that happens to include the word "password"). So we primarily block forbidden
    JSON *keys*, not arbitrary substrings.
    """

    lowered = payload.lower()
    for needle in FORBIDDEN_VALUE_SUBSTRINGS:
        if needle in lowered:
            raise ValueError(f"Refusing to send suspicious value to LLM: {needle}")

    try:
        parsed = json.loads(payload)
    except Exception:
        parsed = None

    if parsed is None:
        return

    for key, _ in _walk_json(parsed):
        if key.lower() in FORBIDDEN_LLM_KEYS:
            raise ValueError(f"Refusing to send forbidden key to LLM: {key}")


def extract_custom_field_names(item: Mapping[str, Any]) -> List[str]:
    names: List[str] = []
    for field in item.get("fields") or []:
        if not isinstance(field, Mapping):
            continue
        name = field.get("name")
        if isinstance(name, str) and name.strip():
            # Defensive: don't leak sensitive custom fields by name.
            lowered = name.strip().lower()
            if any(k in lowered for k in FORBIDDEN_LLM_KEYS):
                continue
            names.append(name.strip())
    return names


@dataclass(frozen=True)
class BwItemSafe:
    id: str
    name: str
    type: int
    folder: str
    login_uri: str
    login_username_masked: str
    custom_field_names: List[str]


def normalize_bw_item_for_llm(
    item: Mapping[str, Any],
    folder_id_to_name: Mapping[str, str],
) -> BwItemSafe:
    item_id = str(item.get("id") or "")
    name = str(item.get("name") or "")
    item_type = int(item.get("type") or 0)

    folder_id = item.get("folderId") or ""
    folder_name = folder_id_to_name.get(folder_id, "")

    login = item.get("login") or {}
    username = str(login.get("username") or "")

    uris_list = login.get("uris") or []
    uris: List[str] = []
    for u in uris_list:
        if not isinstance(u, Mapping):
            continue
        uri_val = u.get("uri")
        if isinstance(uri_val, str) and uri_val.strip():
            uris.append(uri_val.strip())

    login_uri = ",".join(uris)

    return BwItemSafe(
        id=item_id,
        name=name,
        type=item_type,
        folder=folder_name,
        login_uri=login_uri,
        login_username_masked=mask_email_username(username),
        custom_field_names=extract_custom_field_names(item),
    )


# -----------------------------------------------------------------------------
# Bitwarden CLI helpers
# -----------------------------------------------------------------------------


def bw(
    args: List[str], *, session: Optional[str] = None, stdin: Optional[str] = None
) -> str:
    command = ["bw"] + args
    if session:
        command = ["bw", "--session", session] + args

    completed = subprocess.run(
        command,
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        msg = stderr or stdout or f"bw exited with {completed.returncode}"
        raise RuntimeError(f"bw command failed: {' '.join(command)}\n{msg}")

    return completed.stdout


def bw_json(
    args: List[str], *, session: Optional[str] = None, stdin: Optional[str] = None
) -> Any:
    out = bw(args, session=session, stdin=stdin).strip()
    if not out:
        return None
    return json.loads(out)


def bw_status(*, session: Optional[str] = None) -> Mapping[str, Any]:
    status = bw_json(["status"], session=session)
    if not isinstance(status, Mapping):
        raise RuntimeError("Unexpected bw status output")
    return status


def bw_list_folders(*, session: Optional[str] = None) -> List[Mapping[str, Any]]:
    folders = bw_json(["list", "folders"], session=session)
    if not isinstance(folders, list):
        raise RuntimeError("Unexpected bw list folders output")
    return [f for f in folders if isinstance(f, Mapping)]


def bw_create_folder(name: str, *, session: Optional[str] = None) -> Mapping[str, Any]:
    # `bw create folder` requires an encoded JSON payload on stdin/arg.
    payload = {"name": name}
    encoded = bw_encode_json(payload, session=session)
    created = bw_json(["create", "folder", encoded], session=session)
    if not isinstance(created, Mapping):
        raise RuntimeError("Unexpected bw create folder output")
    return created


def bw_list_items(
    *,
    session: Optional[str] = None,
    search: Optional[str] = None,
    folderid: Optional[str] = None,
    collectionid: Optional[str] = None,
    organizationid: Optional[str] = None,
    trash: bool = False,
) -> List[Mapping[str, Any]]:
    args: List[str] = ["list", "items"]
    if search:
        args += ["--search", search]
    if folderid is not None:
        args += ["--folderid", folderid]
    if collectionid is not None:
        args += ["--collectionid", collectionid]
    if organizationid is not None:
        args += ["--organizationid", organizationid]
    if trash:
        args.append("--trash")

    items = bw_json(args, session=session)
    if not isinstance(items, list):
        raise RuntimeError("Unexpected bw list items output")
    return [i for i in items if isinstance(i, Mapping)]


def bw_get_item(item_id: str, *, session: Optional[str] = None) -> Mapping[str, Any]:
    item = bw_json(["get", "item", item_id], session=session)
    if not isinstance(item, Mapping):
        raise RuntimeError("Unexpected bw get item output")
    return item


def bw_encode_json(obj: Any, *, session: Optional[str] = None) -> str:
    payload = json.dumps(obj)
    encoded = bw(["encode"], session=session, stdin=payload).strip()
    if not encoded:
        raise RuntimeError("bw encode returned empty output")
    return encoded


def bw_edit_item(
    item_id: str, item_obj: Mapping[str, Any], *, session: Optional[str] = None
) -> Mapping[str, Any]:
    encoded = bw_encode_json(item_obj, session=session)
    updated = bw_json(["edit", "item", item_id, encoded], session=session)
    if not isinstance(updated, Mapping):
        raise RuntimeError("Unexpected bw edit item output")
    return updated


def bw_set_item_folder(
    item_id: str, folder_id: Optional[str], *, session: Optional[str] = None
) -> None:
    item = dict(bw_get_item(item_id, session=session))
    item["folderId"] = folder_id
    bw_edit_item(item_id, item, session=session)


def bw_list_org_collections(
    org_id: str, *, session: Optional[str] = None
) -> List[Mapping[str, Any]]:
    collections = bw_json(
        ["list", "org-collections", "--organizationid", org_id], session=session
    )
    if not isinstance(collections, list):
        raise RuntimeError("Unexpected bw list org-collections output")
    return [c for c in collections if isinstance(c, Mapping)]


def bw_create_org_collection(
    org_id: str, name: str, *, session: Optional[str] = None
) -> Mapping[str, Any]:
    # Bitwarden CLI expects an org-collection template payload.
    # Template shape (at minimum) includes organizationId, name, externalId,
    # and permission arrays (groups/users).
    payload = {
        "organizationId": org_id,
        "name": name,
        "externalId": None,
        "groups": [],
        "users": [],
    }
    encoded = bw_encode_json(payload, session=session)
    created = bw_json(
        ["create", "org-collection", encoded, "--organizationid", org_id],
        session=session,
    )
    if not isinstance(created, Mapping):
        raise RuntimeError("Unexpected bw create org-collection output")
    return created


def bw_set_item_collections_replace(
    item_id: str,
    org_id: str,
    collection_ids: List[str],
    *,
    session: Optional[str] = None,
) -> None:
    encoded = bw_encode_json(collection_ids, session=session)
    bw_json(
        ["edit", "item-collections", item_id, encoded, "--organizationid", org_id],
        session=session,
    )


# -----------------------------------------------------------------------------
# Categorization helpers (adapted)
# -----------------------------------------------------------------------------


def load_domain_folder_map(yaml_path: str) -> Tuple[Dict[str, str], set[str]]:
    if not yaml:
        raise ImportError("PyYAML is required for --domain-folder-map.")
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    domain_map: Dict[str, str] = {}
    folder_set: set[str] = set()
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, Mapping):
                continue
            domain = entry.get("domain")
            folder = entry.get("folder")
            if (
                isinstance(domain, str)
                and isinstance(folder, str)
                and domain
                and folder
            ):
                domain_map[domain.lower()] = folder
                folder_set.add(folder)
    return domain_map, folder_set


def get_domain_folder_category(
    item: Mapping[str, Any],
    domain_folder_map: Optional[Mapping[str, str]] = None,
    folder_set: Optional[set[str]] = None,
) -> Dict[str, Any]:
    if not domain_folder_map or not folder_set:
        return {"isCompany": False}

    folder = str(item.get("folder") or "")
    if folder in folder_set:
        return {
            "category": folder,
            "confidence": 100,
            "reason": "Mapped folder",
            "isCompany": True,
        }

    username = str(item.get("login_username") or "").lower()
    for domain, mapped_folder in domain_folder_map.items():
        if domain in username:
            return {
                "category": mapped_folder,
                "confidence": 95,
                "reason": "Mapped domain",
                "isCompany": True,
            }
    return {"isCompany": False}


def extract_uris_from_login_uri(login_uri: str) -> Tuple[List[str], List[str]]:
    uris = [u.strip() for u in (login_uri or "").split(",") if u.strip()]
    non_android = [u for u in uris if not u.lower().startswith("androidapp://")]
    android = [u for u in uris if u.lower().startswith("androidapp://")]
    return non_android, android


def extract_domain(item: Mapping[str, Any]) -> str:
    login_uri = str(item.get("login_uri") or "")
    non_android, _ = extract_uris_from_login_uri(login_uri)
    for url in non_android:
        try:
            parsed = urlparse(url if url.startswith("http") else "http://" + url)
            if parsed.hostname:
                return parsed.hostname.lower()
        except Exception:
            pass

    username = str(item.get("login_username") or "")
    if "@" in username:
        return username.split("@")[-1].lower()
    return ""


def is_private_ip_or_cidr(host: str) -> bool:
    try:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private
    except Exception:
        return False


def is_homelab_url(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname if parsed.hostname else url
    if not parsed.scheme and not parsed.hostname:
        url = "http://" + url
        parsed = urlparse(url)
        host = parsed.hostname
    return bool(host and is_private_ip_or_cidr(host))


def is_url_reachable(url: str, timeout: int = 5) -> bool:
    import ssl

    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def try_url(test_url: str) -> Tuple[bool, Optional[int]]:
        try:
            context = ssl._create_unverified_context()
            req = urllib.request.Request(test_url, headers={"User-Agent": user_agent})
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler(),
                urllib.request.HTTPSHandler(context=context),
            )
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
                return (200 <= status < 400), status
        except Exception:
            return False, None

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    reachable, status = try_url(url)
    if reachable:
        return True

    if status is not None and 400 <= status < 600:
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            if domain:
                reachable2, _ = try_url(f"https://{domain}")
                return reachable2
        except Exception:
            pass

    return False


def process_login_uris(
    item: Mapping[str, Any], *, check_reachability: bool
) -> Tuple[bool, bool, bool, List[str]]:
    login_uri = str(item.get("login_uri") or "")
    non_android, _ = extract_uris_from_login_uri(login_uri)
    checked_any = bool(non_android)

    homelab = False
    reachable = False

    for u in non_android:
        if is_homelab_url(u):
            homelab = True
            break
        if check_reachability and is_url_reachable(u):
            reachable = True
            break

    return homelab, reachable, checked_any, non_android


def get_env_var(key: str, env_path: str = ".env") -> str:
    if key in os.environ:
        return os.environ[key]
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() == key:
                        return v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return ""


def _get_api_config(provider: str, model: str) -> Tuple[str, Dict[str, str]]:
    if provider == "openrouter":
        endpoint = "https://openrouter.ai/api/v1/chat/completions"
        api_key = get_env_var("OPENROUTER_API_KEY")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://munim.net",
            "X-Title": "munim.net tools",
        }
    elif provider == "requesty":
        endpoint = "https://router.requesty.ai/v1/chat/completions"
        api_key = get_env_var("REQUESTY_API_KEY")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "munim.net",
        }
    else:
        raise ValueError("Unknown provider")
    return endpoint, headers


def _call_llm_api(
    simplified_batch: List[Dict[str, Any]],
    *,
    model: str,
    provider: str,
    items_for_ai_domains: List[str],
    domain_category_cache: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    endpoint, headers = _get_api_config(provider, model)

    prompt = f"""## Password Vault Item Categorization Prompt

You are a specialized system that categorizes password vault entries into appropriate categories and subcategories.

### Category Structure:
Categories can include subcategories using "/" as a separator.

### Available Categories:
- Financial/Banking
- Financial/Investments
- Financial/Cryptocurrency
- Social
- Email
- Tools/Development
- Tools/Productivity
- Tools/Design
- Tools/Analytics
- Tools/Project Management
- Tools/Communication
- Tools/Marketing
- Shopping
- Entertainment
- Government/Legal
- Utilities
- Education
- Healthcare
- Gaming
- Travel
- Forum
- Cloud/Storage
- Cloud/Computing
- Cloud/Hosting
- Security
- AI
- Personal/Homelab

### Input Format:
For each item, you will receive:
- ID
- Name
- URL (if available)
- Username (masked)
- Type
- Current Folder
- Custom Field Names (names only)

### Items to categorize:
{json.dumps(simplified_batch, indent=2)}

### Output Format:
Respond strictly with a JSON array where each item contains:
- id
- name
- category
- confidence
- reason

Only output valid JSON."""

    assert_llm_payload_safe(prompt)

    data = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")

    req = urllib.request.Request(endpoint, data=data, headers=headers)

    ai_results: List[Dict[str, Any]] = []
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_data = resp.read().decode("utf-8")
                content = json.loads(resp_data)
                message = content["choices"][0]["message"]["content"]
                json_match = re.search(r"\[[\s\S]*\]", message)
                if not json_match:
                    raise ValueError("Invalid response format from LLM")
                ai_results = json.loads(json_match.group(0))
                for idx, result in enumerate(ai_results):
                    domain = items_for_ai_domains[idx]
                    if domain:
                        domain_category_cache[domain] = {
                            "category": result.get("category", ""),
                            "confidence": result.get("confidence", 0),
                            "reason": result.get("reason", ""),
                        }
                return ai_results
        except Exception as e:
            if attempt < max_retries:
                time.sleep(5)
            else:
                raise RuntimeError(f"LLM request failed: {e}")

    return ai_results


def categorize_batch(
    batch: List[Dict[str, Any]],
    *,
    model: str,
    provider: str,
    domain_category_cache: Dict[str, Dict[str, Any]],
    domain_folder_map: Optional[Dict[str, str]] = None,
    folder_set: Optional[set[str]] = None,
    check_reachability: bool,
) -> List[Dict[str, Any]]:
    items_for_ai: List[Dict[str, Any]] = []
    items_for_ai_domains: List[str] = []
    results_by_id: Dict[str, Dict[str, Any]] = {}

    for item in batch:
        item_id = str(item.get("id") or "")

        company_result = get_domain_folder_category(item, domain_folder_map, folder_set)
        if company_result.get("isCompany"):
            results_by_id[item_id] = {
                "id": item_id,
                "name": item.get("name", ""),
                "category": company_result["category"],
                "confidence": company_result["confidence"],
                "reason": company_result["reason"],
                "source": "domain_map",
            }
            continue

        homelab, reachable, checked_any, _ = process_login_uris(
            item, check_reachability=check_reachability
        )
        if homelab:
            results_by_id[item_id] = {
                "id": item_id,
                "name": item.get("name", ""),
                "category": "Personal/Homelab",
                "confidence": 100,
                "reason": "Private IP",
                "source": "homelab",
            }
            continue

        if check_reachability and checked_any and not reachable:
            results_by_id[item_id] = {
                "id": item_id,
                "name": item.get("name", ""),
                "category": "Dead",
                "confidence": 100,
                "reason": "URL unreachable",
                "source": "dead",
            }
            continue

        domain = extract_domain(item)
        if domain and domain in domain_category_cache:
            cached = domain_category_cache[domain]
            results_by_id[item_id] = {
                "id": item_id,
                "name": item.get("name", ""),
                "category": cached.get("category", ""),
                "confidence": cached.get("confidence", 0),
                "reason": cached.get("reason", ""),
                "source": "domain_cache",
            }
            continue

        items_for_ai.append(item)
        items_for_ai_domains.append(domain)

    ai_results: List[Dict[str, Any]] = []
    if items_for_ai:
        simplified_batch: List[Dict[str, Any]] = []
        for item in items_for_ai:
            simplified_batch.append(
                {
                    "id": item.get("id", ""),
                    "name": item.get("name", ""),
                    "url": item.get("login_uri", ""),
                    "username": item.get("login_username", ""),
                    "type": item.get("type", ""),
                    "folder": item.get("folder", ""),
                    "custom_field_names": item.get("custom_field_names", []),
                }
            )
        payload_str = json.dumps(simplified_batch)
        assert_llm_payload_safe(payload_str)

        ai_results = _call_llm_api(
            simplified_batch,
            model=model,
            provider=provider,
            items_for_ai_domains=items_for_ai_domains,
            domain_category_cache=domain_category_cache,
        )

        for result in ai_results:
            item_id = str(result.get("id") or "")
            if not item_id:
                continue
            results_by_id[item_id] = {
                "id": item_id,
                "name": result.get("name", ""),
                "category": result.get("category", ""),
                "confidence": result.get("confidence", 0),
                "reason": result.get("reason", ""),
                "source": "llm",
            }

    ordered: List[Dict[str, Any]] = []
    for item in batch:
        item_id = str(item.get("id") or "")
        ordered.append(
            results_by_id.get(
                item_id,
                {
                    "id": item_id,
                    "name": item.get("name", ""),
                    "category": "",
                    "confidence": 0,
                    "reason": "Uncategorized",
                    "source": "uncategorized",
                },
            )
        )

    return ordered


def category_to_label(category: str) -> str:
    if category == "Dead":
        return "Dead"
    if category == "Personal/Homelab":
        return "Homelab"
    if "/" in category:
        return category.split("/", 1)[0]
    return category
