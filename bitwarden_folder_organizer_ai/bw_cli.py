from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


def _redact_session(argv: Sequence[str], session: str | None) -> list[str]:
    if not session:
        return list(argv)

    redacted: list[str] = []
    skip_next = False
    for part in argv:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        if part == "--session":
            redacted.append(part)
            skip_next = True
            continue
        redacted.append(part)
    return redacted


def _format_bw_error(
    *,
    argv: Sequence[str],
    session: str | None,
    stdout: str,
    stderr: str,
    returncode: int,
) -> str:
    safe_argv = " ".join(_redact_session(argv, session))

    # The CLI can include encoded blobs in stdout/stderr; truncate hard.
    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()
    if len(stdout) > 500:
        stdout = stdout[:500] + "...<truncated>"
    if len(stderr) > 500:
        stderr = stderr[:500] + "...<truncated>"

    msg = stderr or stdout or f"bw exited with {returncode}"
    return f"bw command failed: {safe_argv}\n{msg}"


class BwClient(Protocol):
    def status(self) -> Mapping[str, Any]: ...

    def sync(self) -> None: ...

    def list_folders(self) -> list[Mapping[str, Any]]: ...

    def create_folder(self, name: str) -> Mapping[str, Any]: ...

    def list_items(
        self,
        *,
        search: str | None = None,
        folderid: str | None = None,
        collectionid: str | None = None,
        organizationid: str | None = None,
        trash: bool = False,
    ) -> list[Mapping[str, Any]]: ...

    def get_item(self, item_id: str) -> Mapping[str, Any]: ...

    def set_item_folder(self, item_id: str, folder_id: str | None) -> None: ...


@dataclass(frozen=True)
class BwCliClient:
    session: str | None = None

    def _bw(self, args: list[str], *, stdin: str | None = None) -> str:
        command = ["bw"] + args
        if self.session:
            command = ["bw", "--session", self.session] + args

        completed = subprocess.run(
            command,
            input=stdin,
            text=True,
            capture_output=True,
            check=False,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                _format_bw_error(
                    argv=command,
                    session=self.session,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    returncode=completed.returncode,
                )
            )

        return completed.stdout

    def _bw_json(self, args: list[str], *, stdin: str | None = None) -> Any:
        out = self._bw(args, stdin=stdin).strip()
        if not out:
            return None
        return json.loads(out)

    def _bw_encode_json(self, obj: Any) -> str:
        payload = json.dumps(obj)
        encoded = self._bw(["encode"], stdin=payload).strip()
        if not encoded:
            raise RuntimeError("bw encode returned empty output")
        return encoded

    def status(self) -> Mapping[str, Any]:
        status = self._bw_json(["status"])
        if not isinstance(status, Mapping):
            raise RuntimeError("Unexpected bw status output")
        return status

    def sync(self) -> None:
        self._bw(["sync"])

    def list_folders(self) -> list[Mapping[str, Any]]:
        folders = self._bw_json(["list", "folders"])
        if not isinstance(folders, list):
            raise RuntimeError("Unexpected bw list folders output")
        return [f for f in folders if isinstance(f, Mapping)]

    def create_folder(self, name: str) -> Mapping[str, Any]:
        payload = {"name": name}
        encoded = self._bw_encode_json(payload)
        created = self._bw_json(["create", "folder", encoded])
        if not isinstance(created, Mapping):
            raise RuntimeError("Unexpected bw create folder output")
        return created

    def list_items(
        self,
        *,
        search: str | None = None,
        folderid: str | None = None,
        collectionid: str | None = None,
        organizationid: str | None = None,
        trash: bool = False,
    ) -> list[Mapping[str, Any]]:
        args: list[str] = ["list", "items"]
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

        items = self._bw_json(args)
        if not isinstance(items, list):
            raise RuntimeError("Unexpected bw list items output")
        return [i for i in items if isinstance(i, Mapping)]

    def get_item(self, item_id: str) -> Mapping[str, Any]:
        item = self._bw_json(["get", "item", item_id])
        if not isinstance(item, Mapping):
            raise RuntimeError("Unexpected bw get item output")
        return item

    def set_item_folder(self, item_id: str, folder_id: str | None) -> None:
        item = dict(self.get_item(item_id))
        item["folderId"] = folder_id
        encoded = self._bw_encode_json(item)
        updated = self._bw_json(["edit", "item", item_id, encoded])
        if not isinstance(updated, Mapping):
            raise RuntimeError("Unexpected bw edit item output")
