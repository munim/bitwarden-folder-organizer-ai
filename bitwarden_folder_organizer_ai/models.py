from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class BwItemSafe:
    id: str
    name: str
    type: int
    folder: str
    login_uri: str
    login_username_masked: str
    custom_field_names: list[str]


def is_org_item(item: Mapping[str, Any]) -> bool:
    org_id = item.get("organizationId")
    return isinstance(org_id, str) and org_id.strip() != ""
