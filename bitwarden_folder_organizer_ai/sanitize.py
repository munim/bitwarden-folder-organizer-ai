from __future__ import annotations

import json
from typing import Any, Mapping

from .models import BwItemSafe

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


def _walk_json(obj: Any) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
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

    Primarily blocks forbidden JSON *keys* and a small set of suspicious
    value substrings (to avoid breaking on normal metadata).
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


def extract_custom_field_names(item: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
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
    uris: list[str] = []
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
