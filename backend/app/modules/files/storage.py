"""Safe file storage.

Uploads are written outside the web root under randomised identifiers. Path
traversal is prevented by never using user-supplied names for the stored file
and by verifying the resolved path stays within the configured base directory.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

from app.core.config import settings

_SAFE_EXT_RE = re.compile(r"^[A-Za-z0-9]{1,12}$")


class FileStorage:
    def __init__(self, base: Path | None = None):
        self.base = Path(base) if base else settings.quarantine_path
        self.base.mkdir(parents=True, exist_ok=True)

    def _safe_extension(self, filename: str) -> str:
        name = filename or ""
        if "." not in name:
            return ""
        ext = name.rsplit(".", 1)[-1]
        if _SAFE_EXT_RE.match(ext):
            return "." + ext.lower()
        return ""

    def _resolve(self, stored_name: str) -> Path:
        candidate = (self.base / stored_name).resolve()
        base_resolved = self.base.resolve()
        if base_resolved != candidate and base_resolved not in candidate.parents:
            raise ValueError("Attempted path traversal outside storage base")
        return candidate

    def save_bytes(self, data: bytes, original_name: str) -> tuple[str, Path, int]:
        stored_name = f"{uuid.uuid4().hex}{self._safe_extension(original_name)}"
        path = self._resolve(stored_name)
        # Write with exclusive creation and restrictive permissions.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return stored_name, path, len(data)

    def read_bytes(self, stored_name: str, max_bytes: int | None = None) -> bytes:
        path = self._resolve(stored_name)
        if max_bytes is not None and path.stat().st_size > max_bytes:
            raise ValueError("File exceeds read limit")
        with open(path, "rb") as fh:
            return fh.read()

    def delete(self, stored_name: str) -> None:
        try:
            self._resolve(stored_name).unlink(missing_ok=True)
        except ValueError:
            pass

    @staticmethod
    def sha256_of(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }
