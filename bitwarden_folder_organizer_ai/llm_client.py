from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .sanitize import assert_llm_payload_safe


def get_env_var(key: str, env_path: str = ".env") -> str:
    """Reads env var with .env fallback.

    Kept small and dependency-free (project already uses python-dotenv, but this
    keeps the core logic identical to the previous script).
    """

    import os

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


def _get_api_config(provider: str) -> tuple[str, dict[str, str]]:
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


class LlmClient(Protocol):
    def categorize(
        self, *, simplified_batch: list[dict[str, Any]]
    ) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class OpenAiCompatibleHttpLlmClient:
    model: str
    provider: str

    def categorize(
        self, *, simplified_batch: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        endpoint, headers = _get_api_config(self.provider)

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
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode("utf-8")

        req = urllib.request.Request(endpoint, data=data, headers=headers)

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
                    return json.loads(json_match.group(0))
            except Exception as e:
                if attempt < max_retries:
                    time.sleep(5)
                    continue
                raise RuntimeError(f"LLM request failed: {e}")

        return []
