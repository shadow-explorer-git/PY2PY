import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Any


def save_json_atomically(filepath: Path, data: Dict[str, Any]):
    """
    Saves a dictionary to a JSON file atomically to prevent data corruption.
    It writes to a temporary file first, then replaces the original file.
    """
    filepath.parent.mkdir(parents=True, exist_ok=True)
    tmp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            delete=False,
            dir=str(filepath.parent),
            suffix='.tmp',
        ) as fh:
            tmp_file_path = fh.name
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_file_path, filepath)
    except Exception:
        if tmp_file_path and os.path.exists(tmp_file_path):
            try:
                os.remove(tmp_file_path)
            except Exception:
                pass
