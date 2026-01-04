"""Compatibility shim.

The implementation moved to `bitwarden_folder_organizer_ai.cli`.
"""

from __future__ import annotations

from bitwarden_folder_organizer_ai.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
