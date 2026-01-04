from __future__ import annotations

import argparse
import os
from typing import Optional

from .bw_cli import BwCliClient
from .llm_client import OpenAiCompatibleHttpLlmClient
from .organize import OrganizeArgs, organize_vault


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Categorize and move Bitwarden items using bw CLI"
    )

    parser.add_argument(
        "--provider", choices=["openrouter", "requesty"], default="openrouter"
    )
    parser.add_argument("--model", default="claude-3-haiku-20240307")
    parser.add_argument("-b", "--batch-size", type=int, default=10)
    parser.add_argument("--max-batches", type=int)
    parser.add_argument("--domain-folder-map")

    parser.add_argument("--check-reachability", action="store_true")

    parser.add_argument(
        "--session", help="BW session token (otherwise uses BW_SESSION env var)"
    )
    parser.add_argument(
        "--sync", action="store_true", help="Run bw sync before listing items"
    )

    parser.add_argument("--search")
    parser.add_argument("--folderid")
    parser.add_argument("--collectionid")
    parser.add_argument("--organizationid")
    parser.add_argument("--trash", action="store_true")

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


def main(argv: Optional[list[str]] = None) -> int:
    args_ns = parse_args(argv)
    session = args_ns.session or os.environ.get("BW_SESSION")

    bw_client = BwCliClient(session=session)
    llm_client = OpenAiCompatibleHttpLlmClient(
        model=args_ns.model, provider=args_ns.provider
    )

    args = OrganizeArgs(
        provider=args_ns.provider,
        model=args_ns.model,
        batch_size=args_ns.batch_size,
        max_batches=args_ns.max_batches,
        domain_folder_map=args_ns.domain_folder_map,
        check_reachability=args_ns.check_reachability,
        sync=args_ns.sync,
        search=args_ns.search,
        folderid=args_ns.folderid,
        collectionid=args_ns.collectionid,
        organizationid=args_ns.organizationid,
        trash=args_ns.trash,
        apply=args_ns.apply,
        dry_run=args_ns.dry_run,
        sleep_between_batches=args_ns.sleep_between_batches,
        item_delay=args_ns.item_delay,
    )

    return organize_vault(bw_client=bw_client, llm_client=llm_client, args=args)
