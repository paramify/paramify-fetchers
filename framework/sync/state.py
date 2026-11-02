"""Per-run upload state: a batch-id cache and a run lock.

The cache records each batch id the moment the API returns it, so a re-run
reuses the batch instead of creating another. The lock keeps two uploads of
one run from running at once.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from framework.run_files import UPLOAD_LOCK_FILE, UPLOAD_STATE_FILE

logger = logging.getLogger(__name__)


class RunLocked(RuntimeError):
    """Another upload of this run holds the lock."""


class RunState:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)

    @property
    def _path(self) -> Path:
        return self.run_dir / UPLOAD_STATE_FILE

    def _read(self) -> dict[str, str]:
        try:
            data = json.loads(self._path.read_text())
            batches = data["batches"]
            if not isinstance(batches, dict):
                raise ValueError("batches is not an object")
            return {str(k): str(v) for k, v in batches.items()}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("ignoring unreadable upload state %s: %s", self._path, exc)
            return {}

    def batch_for(self, entry_key: str) -> Optional[str]:
        return self._read().get(entry_key)

    def record_batch(self, entry_key: str, batch_id: str) -> None:
        batches = self._read()
        batches[entry_key] = batch_id
        fd, tmp = tempfile.mkstemp(dir=self.run_dir, prefix=".upload_state.")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump({"batches": batches}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    @contextmanager
    def lock(self) -> Iterator[None]:
        # Imported here, so the facade still imports on native Windows (no fcntl).
        try:
            import fcntl
        except ImportError:
            raise RuntimeError("run locking needs a POSIX system (use WSL)") from None
        fd = os.open(self.run_dir / UPLOAD_LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RunLocked("another upload of this run is in progress") from None
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
