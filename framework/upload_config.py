"""Reading the uploader config (upload.yaml), the same way for every stage."""
from pathlib import Path
from typing import Any, Dict, Optional

from framework import yaml_io


def load(path: Optional[Path]) -> Dict[str, Any]:
    """The config as a mapping; {} when there is no path or the file is empty.

    Raises ValueError when it is not a mapping, and lets OSError and
    yaml.YAMLError through, so a broken config fails where it is read instead
    of reading as "no config".
    """
    if not path:
        return {}
    data = yaml_io.load_path(Path(path)) or {}
    if not isinstance(data, dict):
        raise ValueError(f"the uploader config {path} is not a mapping")
    return data
