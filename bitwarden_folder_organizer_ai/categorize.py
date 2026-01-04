from __future__ import annotations

import ipaddress
import socket
import time
import urllib.request
from typing import Any, Mapping
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from .llm_client import LlmClient


def load_domain_folder_map(yaml_path: str) -> tuple[dict[str, str], set[str]]:
    if not yaml:
        raise ImportError("PyYAML is required for --domain-folder-map.")
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    domain_map: dict[str, str] = {}
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
    domain_folder_map: Mapping[str, str] | None = None,
    folder_set: set[str] | None = None,
) -> dict[str, Any]:
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


def extract_uris_from_login_uri(login_uri: str) -> tuple[list[str], list[str]]:
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

    def try_url(test_url: str) -> tuple[bool, int | None]:
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
) -> tuple[bool, bool, bool, list[str]]:
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


def category_to_label(category: str) -> str:
    if category == "Dead":
        return "Dead"
    if category == "Personal/Homelab":
        return "Homelab"
    if "/" in category:
        return category.split("/", 1)[0]
    return category


def categorize_batch(
    batch: list[dict[str, Any]],
    *,
    llm_client: LlmClient,
    domain_category_cache: dict[str, dict[str, Any]],
    domain_folder_map: dict[str, str] | None = None,
    folder_set: set[str] | None = None,
    check_reachability: bool,
) -> list[dict[str, Any]]:
    items_for_ai: list[dict[str, Any]] = []
    items_for_ai_domains: list[str] = []
    results_by_id: dict[str, dict[str, Any]] = {}

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

    if items_for_ai:
        simplified_batch: list[dict[str, Any]] = []
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

        ai_results = llm_client.categorize(simplified_batch=simplified_batch)

        for idx, result in enumerate(ai_results):
            domain = (
                items_for_ai_domains[idx] if idx < len(items_for_ai_domains) else ""
            )
            if domain:
                domain_category_cache[domain] = {
                    "category": result.get("category", ""),
                    "confidence": result.get("confidence", 0),
                    "reason": result.get("reason", ""),
                }

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

    ordered: list[dict[str, Any]] = []
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
