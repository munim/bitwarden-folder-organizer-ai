"""Compatibility shim.

This file used to contain the implementation. It now re-exports public helpers
from `bitwarden_folder_organizer_ai` so existing imports keep working.
"""

from __future__ import annotations

from bitwarden_folder_organizer_ai.bw_cli import BwCliClient as _BwCliClient
from bitwarden_folder_organizer_ai.categorize import (
    categorize_batch,
    category_to_label,
    load_domain_folder_map,
)
from bitwarden_folder_organizer_ai.llm_client import OpenAiCompatibleHttpLlmClient
from bitwarden_folder_organizer_ai.models import BwItemSafe
from bitwarden_folder_organizer_ai.sanitize import (
    assert_llm_payload_safe,
    extract_custom_field_names,
    mask_email_username,
    normalize_bw_item_for_llm,
)


def bw(args: list[str], *, session: str | None = None, stdin: str | None = None) -> str:
    return _BwCliClient(session=session)._bw(args, stdin=stdin)


def bw_status(*, session: str | None = None):
    return _BwCliClient(session=session).status()


def bw_list_folders(*, session: str | None = None):
    return _BwCliClient(session=session).list_folders()


def bw_create_folder(name: str, *, session: str | None = None):
    return _BwCliClient(session=session).create_folder(name)


def bw_list_items(
    *,
    session: str | None = None,
    search: str | None = None,
    folderid: str | None = None,
    collectionid: str | None = None,
    organizationid: str | None = None,
    trash: bool = False,
):
    return _BwCliClient(session=session).list_items(
        search=search,
        folderid=folderid,
        collectionid=collectionid,
        organizationid=organizationid,
        trash=trash,
    )


def bw_set_item_folder(
    item_id: str, folder_id: str | None, *, session: str | None = None
) -> None:
    _BwCliClient(session=session).set_item_folder(item_id, folder_id)
