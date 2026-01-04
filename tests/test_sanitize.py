import json

import pytest

from bitwarden_folder_organizer_ai.sanitize import assert_llm_payload_safe


def test_assert_llm_payload_safe_allows_password_word_in_value() -> None:
    payload = json.dumps(
        [{"id": "1", "name": "My password manager", "url": "example.com"}]
    )
    assert_llm_payload_safe(payload)


def test_assert_llm_payload_safe_blocks_password_key() -> None:
    payload = json.dumps({"password": "secret"})
    with pytest.raises(ValueError):
        assert_llm_payload_safe(payload)
