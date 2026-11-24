"""Confined, digest-pinned original files accompanying an evidence envelope."""

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath


def read_original(root, relative, sha256, size):
    if (not isinstance(relative, str) or '\\' in relative
            or not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', sha256)
            or type(size) is not int or size < 0):
        raise OSError('invalid original-file descriptor')
    rel = PurePosixPath(relative)
    if rel.is_absolute() or '..' in rel.parts or len(rel.parts) < 3 or rel.parts[0] != '_attachments':
        raise OSError('original must be below the run _attachments directory')
    root = Path(root).resolve()
    path = root
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            raise OSError('original-file symlinks are not allowed')
    try:
        with path.open('rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size:
                raise OSError('original-file type or length changed')
            content = handle.read(size + 1)
    except (OSError, ValueError) as exc:
        raise OSError('original file is unavailable or changed') from exc
    if len(content) != size or hashlib.sha256(content).hexdigest() != sha256:
        raise OSError('original-file digest or length changed')
    return content


def originals(root, items):
    if not isinstance(items, list):
        raise OSError('attachments must be a list')
    seen, names = set(), set()
    for item in items:
        if not isinstance(item, dict):
            raise OSError('attachment must be a descriptor')
        relative, digest, size = (item.get(k) for k in ('path', 'sha256', 'bytes'))
        read_original(root, relative, digest, size)
        name = PurePosixPath(relative).name
        if relative in seen or name in names:
            raise OSError('duplicate attachment path or basename')
        seen.add(relative)
        names.add(name)
    return items
