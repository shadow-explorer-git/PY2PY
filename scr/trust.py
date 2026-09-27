import json
import time
from pathlib import Path
from typing import Dict, Optional

from .identity import IDENTITY_DIR
from .file_utils import save_json_atomically

TRUST_FILE = IDENTITY_DIR / "trusted.json"


def _load() -> Dict[str, Dict]:
    try:
        if TRUST_FILE.exists():
            return json.loads(TRUST_FILE.read_text())
    except Exception:
        pass
    return {}


def _save(data: Dict[str, Dict]):
    save_json_atomically(TRUST_FILE, data)


def is_trusted(fingerprint: str) -> bool:
    store = _load()
    return fingerprint in store


def add_trust(fingerprint: str, name: Optional[str] = None):
    store = _load()
    store[fingerprint] = {
        "name": name or "",
        "added": int(time.time()),
    }
    _save(store)


def remove_trust(fingerprint: str):
    store = _load()
    if fingerprint in store:
        del store[fingerprint]
        _save(store)

def list_trusted() -> Dict[str, Dict]:
    return _load()
