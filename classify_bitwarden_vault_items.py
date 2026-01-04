#!/usr/bin/env python3
# bitwarden_categorizer.py

import os
import json
import time
import argparse
import csv
from typing import List, Dict, Any
import urllib.request
import urllib.error
import re
from urllib.parse import urlparse
import socket
import ipaddress
# Add PyYAML for domain-folder mapping
try:
    import yaml
except ImportError:
    yaml = None  # Will check at runtime if needed

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Categorize Bitwarden vault items using LLM API")
    parser.add_argument("-i", "--input", required=True, help="Input Bitwarden export JSON file")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file for categorized data")
    parser.add_argument("-m", "--model", default="claude-3-haiku-20240307", help="LLM model to use")
    parser.add_argument("-b", "--batch-size", type=int, default=10, help="Number of items to process in each LLM request")
    parser.add_argument("--provider", choices=["openrouter", "requesty"], default="openrouter", help="LLM provider to use (openrouter or requesty)")
    parser.add_argument("--domain-folder-map", help="Optional YAML file mapping domains to folders")
    return parser.parse_args()

# Read and parse the input CSV file
def read_bitwarden_json(input_file: str) -> List[Dict[str, Any]]:
    """
    Parse Bitwarden export JSON and normalize items for downstream processing.
    Maps folderId to folder name, flattens login fields, and extracts uris/usernames.
    """
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    folders = {f["id"]: f["name"] for f in data.get("folders", [])}
    items = []
    for item in data.get("items", []):
        folder_name = folders.get(item.get("folderId", ""), "")
        login = item.get("login", {}) or {}
        uris = login.get("uris", [])
        # uris is a list of dicts with "uri" key
        login_uris = ",".join([u["uri"] for u in uris if u.get("uri")]) if uris else ""
        username = login.get("username", "")
        normalized = {
            "name": item.get("name", ""),
            "login_uri": login_uris,
            "login_username": username,
            "type": item.get("type", ""),
            "folder": folder_name,
            "notes": item.get("notes", ""),
            "id": item.get("id", ""),
        }
        items.append(normalized)
    return items

# Prepare items for LLM processing
def prepare_batches(items: List[Dict[str, Any]], batch_size: int) -> List[List[Dict[str, Any]]]:
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]

def load_domain_folder_map(yaml_path: str):
    """
    Load domain to folder mapping from a YAML file.
    Returns a tuple: (domain_to_folder_dict, set_of_folders)
    """
    if not yaml:
        raise ImportError("PyYAML is required for --domain-folder-map. Install with `pip install pyyaml`.")
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        domain_map = {}
        folder_set = set()
        if isinstance(data, list):
            for entry in data:
                domain = entry.get("domain")
                folder = entry.get("folder")
                if domain and folder:
                    domain_map[domain.lower()] = folder
                    folder_set.add(folder)
        return domain_map, folder_set
    except Exception as e:
        print(f"Error loading domain-folder map: {e}")
        return {{}}, set()

# Company mapping and detection
def get_domain_folder_category(item: Dict[str, Any], domain_folder_map=None, folder_set=None) -> Dict[str, Any]:
    """Check if item belongs to a mapped folder based on folder or email domain."""
    if not domain_folder_map or not folder_set:
        return {"isCompany": False}
    folder = item.get("folder", "")
    if folder in folder_set:
        return {
            "category": folder,
            "confidence": 100,
            "reason": "Mapped folder",
            "isCompany": True
        }
    username = item.get("login_username", "").lower()
    for domain, mapped_folder in domain_folder_map.items():
        if domain in username:
            return {
                "category": mapped_folder,
                "confidence": 95,
                "reason": "Mapped domain",
                "isCompany": True
            }
    return {"isCompany": False}

def extract_uris_from_login_uri(login_uri: str):
    """Extract non-android and android URIs from login_uri string."""
    uris = [u.strip() for u in login_uri.split(",") if u.strip()]
    non_android_uris = [u for u in uris if not u.lower().startswith("androidapp://")]
    android_uris = [u for u in uris if u.lower().startswith("androidapp://")]
    return non_android_uris, android_uris

def extract_domain(item: Dict[str, Any]) -> str:
    """Extract domain from login_uri or login_username."""
    login_uri = item.get("login_uri", "")
    non_android_uris, _ = extract_uris_from_login_uri(login_uri)
    for url in non_android_uris:
        try:
            parsed = urlparse(url if url.startswith("http") else "http://" + url)
            if parsed.hostname:
                return parsed.hostname.lower()
        except Exception:
            pass
    username = item.get("login_username", "")
    if "@" in username:
        return username.split("@")[-1].lower()
    return ""

def is_url_reachable(url: str, timeout: int = 5) -> bool:
    """Check if a URL is reachable with Chrome User-Agent, ignoring SSL errors.
    If the response is 4xx or 5xx, try the domain as fallback."""
    import ssl
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    def try_url(test_url):
        try:
            context = ssl._create_unverified_context()
            req = urllib.request.Request(test_url, headers={"User-Agent": user_agent})
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler(),
                urllib.request.HTTPSHandler(context=context)
            )
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
                if 200 <= status < 400:
                    print(f"URL reachable: {test_url}")
                    return True, status
                else:
                    print(f"URL returned status {status}: {test_url}")
                    return False, status
        except Exception as e:
            print(f"Error accessing {test_url}: {str(e)}")
            return False, None

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    reachable, status = try_url(url)
    if reachable:
        return True
    # If 4xx or 5xx, try the domain as fallback
    if status is not None and 400 <= status < 600:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.hostname
            if domain:
                fallback_url = f"https://{domain}"
                fallback_reachable, _ = try_url(fallback_url)
                return fallback_reachable
        except Exception:
            pass
    return False

def is_private_ip_or_cidr(host: str) -> bool:
    """Check if host is a private IP or resolves to a private IP."""
    try:
        # If host is already an IP
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # Not an IP, try to resolve
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private
    except Exception:
        return False

def is_homelab_url(url: str) -> bool:
    """Check if URL points to a homelab/private IP."""
    parsed = urlparse(url)
    host = parsed.hostname if parsed.hostname else url
    if not parsed.scheme and not parsed.hostname:
        url = "http://" + url
        parsed = urlparse(url)
        host = parsed.hostname
    
    return host and is_private_ip_or_cidr(host)

def process_login_uris(item: Dict[str, Any]) -> tuple[bool, bool, bool, List[str]]:
    """Process login URIs from an item, check for homelab and reachability.
    
    Returns:
        Tuple containing (homelab, reachable, checked_any, non_android_uris)
    """
    login_uri = item.get("login_uri", "")
    non_android_uris, _ = extract_uris_from_login_uri(login_uri)
    checked_any = bool(non_android_uris)
    reachable = False
    homelab = False

    for idx, u in enumerate(non_android_uris):
        if is_homelab_url(u):
            homelab = True
            break
        if is_url_reachable(u):
            reachable = True
            break

    return homelab, reachable, checked_any, non_android_uris

def _get_api_config(provider: str, model: str):
    if provider == "openrouter":
        endpoint = "https://openrouter.ai/api/v1/chat/completions"
        api_key = get_env_var("OPENROUTER_API_KEY")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://munim.net",
            "X-Title": "munim.net tools"
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

def _split_items_for_processing(batch, domain_category_cache, domain_folder_map=None, folder_set=None):
    company_items = []
    items_for_ai = []
    items_for_ai_domains = []
    cached_items = []
    dead_items = []
    for item in batch:
        company_result = get_domain_folder_category(item, domain_folder_map, folder_set)
        if company_result.get("isCompany"):
            company_items.append({
                "name": item.get("name", ""),
                "category": company_result["category"],
                "confidence": company_result["confidence"],
                "reason": company_result["reason"]
            })
        else:
            homelab, reachable, checked_any, _ = process_login_uris(item)
            if homelab:
                company_items.append({
                    "name": item.get("name", ""),
                    "category": "Personal/Homelab",
                    "confidence": 100,
                    "reason": "Private IP",
                })
                continue
            if checked_any and not reachable:
                dead_items.append({
                    "name": item.get("name", ""),
                    "category": "Dead",
                    "confidence": 100,
                    "reason": "URL unreachable"
                })
                continue
            domain = extract_domain(item)
            if domain and domain in domain_category_cache:
                cached = domain_category_cache[domain].copy()
                cached["name"] = item.get("name", "")
                cached_items.append(cached)
            else:
                items_for_ai.append(item)
                items_for_ai_domains.append(domain)
    return company_items, dead_items, cached_items, items_for_ai, items_for_ai_domains

def _call_llm_api(simplified_batch, model, provider, endpoint, headers, items_for_ai_domains, domain_category_cache):
    prompt = f"""## Password Vault Item Categorization Prompt

You are a specialized system that categorizes password vault entries into appropriate categories and subcategories. You will be given information about password vault items, and your task is to assign each to the most appropriate category using a hierarchical structure.

### Category Structure:
Categories can include subcategories using "/" as a separator. For example, "Tools/Development" means this item belongs to the "Development" subcategory within the "Tools" main category.

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
For each item, you will receive the following information:
- ID: The unique id of the item
- Name: The title of the item
- URL: The website URL or the package name of android app (if available)
- Username: The username (if available)
- Type: The type of item (login, secure note, card, etc.)
- Current Folder: The company folder it belongs to (if any)

### Items to categorize:
{json.dumps(simplified_batch, indent=2)}

### Output Format:
Respond strictly with a JSON array where each item contains:
1. The original item"s id (as "id")
2. The original item"s name
3. The assigned category (must be one from the provided list, using "/" for subcategories)
4. A confidence score (0-100)
5. A brief explanation (2-3 words) of why this category was chosen
6. This will be processed by a script, so ensure the output is valid JSON and only output the JSON.

Example response:
```json
[
  {{
    "id": "51e7100b-0c56-44ac-afd5-ace000215975",
    "name": "Chase Bank",
    "category": "Financial/Banking",
    "confidence": 95,
    "reason": "Banking service"
  }},
  {{
    "id": "c66a7383-9ea8-4a37-be3c-ace000215976",
    "name": "Facebook",
    "category": "Social/Facebook",
    "confidence": 98,
    "reason": "Social network"
  }},
  {{
    "id": "c3bd51dc-592d-4d63-b253-afd700988e0e",
    "name": "GitHub",
    "category": "Tools/Development",
    "confidence": 96,
    "reason": "Code hosting"
  }}
]
```

Do not include any explanatory text outside the JSON array. The response must be valid JSON that can be parsed programmatically."""

    ai_results = []
    try:
        data = json.dumps({
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers=headers)
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    resp_data = resp.read().decode("utf-8")
                    content = json.loads(resp_data)
                    print(content)
                    content = content["choices"][0]["message"]["content"]
                    json_match = re.search(r"\[[\s\S]*\]", content)
                    if not json_match:
                        raise ValueError("Invalid response format from LLM")
                    ai_results = json.loads(json_match.group(0))
                    _update_domain_cache(ai_results, items_for_ai_domains, domain_category_cache)
                    break
            except Exception as e:
                if attempt < max_retries:
                    print(f"Error processing AI batch (attempt {attempt+1}): {str(e)}. Retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    print(f"Error processing AI batch (final attempt): {str(e)}")
                    ai_results = []
    except Exception as e:
        print(f"Error preparing AI batch: {str(e)}")
        ai_results = []
    return ai_results

def _update_domain_cache(ai_results, items_for_ai_domains, domain_category_cache):
    for idx, result in enumerate(ai_results):
        domain = items_for_ai_domains[idx]
        if domain:
            domain_category_cache[domain] = {
                "category": result.get("category", ""),
                "confidence": result.get("confidence", 0),
                "reason": result.get("reason", "")
            }

def process_batch(batch: List[Dict[str, Any]], model: str, provider: str, domain_category_cache: Dict[str, Dict[str, Any]] = None, domain_folder_map=None, folder_set=None) -> List[Dict[str, Any]]:
    if domain_category_cache is None:
        domain_category_cache = {}
    endpoint, headers = _get_api_config(provider, model)
    company_items, dead_items, cached_items, items_for_ai, items_for_ai_domains = _split_items_for_processing(batch, domain_category_cache, domain_folder_map, folder_set)
    ai_results = []
    if items_for_ai:
        simplified_batch = []
        for item in items_for_ai:
            simplified_item = {
                "id": item.get("id", ""),
                "name": item.get("name", ""),
                "url": item.get("login_uri", ""),
                "username": item.get("login_username", ""),
                "type": item.get("type", ""),
                "folder": item.get("folder", "")
            }
            simplified_batch.append(simplified_item)
        ai_results = _call_llm_api(simplified_batch, model, provider, endpoint, headers, items_for_ai_domains, domain_category_cache)
    final_results = []
    ai_idx = 0
    for item in batch:
        company_result = get_domain_folder_category(item, domain_folder_map, folder_set)
        if company_result.get("isCompany"):
            final_results.append(create_result_item(
                item, 
                company_result["category"],
                company_result["confidence"],
                company_result["reason"]
            ))
        else:
            homelab, reachable, checked_any, _ = process_login_uris(item)
            if homelab:
                final_results.append(create_result_item(
                    item,
                    "Personal/Homelab",
                    100,
                    "Private IP"
                ))
                continue
            if checked_any and not reachable:
                final_results.append(create_result_item(
                    item,
                    "Dead",
                    100,
                    "URL unreachable"
                ))
                continue
            result, ai_idx = categorize_item(item, domain_category_cache, ai_results, ai_idx)
            final_results.append(result)
    return final_results

def categorize_item(item: Dict[str, Any], domain_category_cache: Dict[str, Dict[str, Any]], ai_results: List[Dict[str, Any]], ai_idx: int) -> tuple[Dict[str, Any], int]:
    """Categorize a single item based on domain cache or AI results.
    Returns:
        Tuple containing (categorization_result, new_ai_index)
    """
    domain = extract_domain(item)
    if domain and domain in domain_category_cache:
        cached = domain_category_cache[domain].copy()
        cached["name"] = item.get("name", "")
        cached["id"] = item.get("id", "")
        return cached, ai_idx
    elif ai_idx < len(ai_results):
        result = ai_results[ai_idx]
        # Ensure id and name are set from LLM output
        result["id"] = result.get("id", item.get("id", ""))
        result["name"] = result.get("name", item.get("name", ""))
        return result, ai_idx + 1
    else:
        return {"id": item.get("id", ""), "name": item.get("name", ""), "category": "", "confidence": 0, "reason": "Uncategorized"}, ai_idx

# Merge all categorized items
def merge_results(batch_results: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    merged = []
    for batch in batch_results:
        merged.extend(batch)
    return merged

# Write results to output CSV
def write_output_csv(items: List[Dict[str, Any]], original_items: List[Dict[str, Any]], output_file: str) -> None:
    # Only update the "folder" field, keep all other fields as in input
    output_items = []
    for orig, cat in zip(original_items, items):
        output_item = dict(orig)
        if "category" in cat and cat["category"]:
            output_item["folder"] = cat["category"]
        output_items.append(output_item)

    fieldnames = list(original_items[0].keys())
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_items)

# Load a single environment variable from a .env file if not already set
def get_env_var(key: str, env_path: str = ".env") -> str:
    """Load a single environment variable from a .env file if not already set."""
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
                        return v.strip().strip(""").strip(""")
    except FileNotFoundError:
        pass
    return ""

def create_result_item(item: Dict[str, Any], category: str, confidence: int, reason: str) -> Dict[str, Any]:
    """Create a result item with standard format."""
    return {
        "name": item.get("name", ""),
        "category": category,
        "confidence": confidence,
        "reason": reason
    }

# Main function
def main():
    args = parse_args()
    domain_folder_map = None
    folder_set = None
    if args.domain_folder_map:
        domain_folder_map, folder_set = load_domain_folder_map(args.domain_folder_map)
    try:
        print(f"Reading input file: {args.input}")
        items = read_bitwarden_json(args.input)
        print(f"Found {len(items)} items to categorize")
        batches = prepare_batches(items, args.batch_size)
        print(f"Split into {len(batches)} batches of {args.batch_size} items")
        all_results = []
        for i, batch in enumerate(batches):
            print(f"Processing batch {i+1}/{len(batches)}...")
            batch_results = process_batch(batch, args.model, args.provider, domain_folder_map=domain_folder_map, folder_set=folder_set)
            all_results.append(batch_results)
            break
            if i < len(batches) - 1:
                print("Waiting 5 seconds before next batch...")
                time.sleep(5)
            # if i  == 2:
            #     break
        merged_results = merge_results(all_results)
        print(f"Successfully categorized {len(merged_results)} items")
        write_output_csv(merged_results, items, args.output)
        print(f"Results written to {args.output}")
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()