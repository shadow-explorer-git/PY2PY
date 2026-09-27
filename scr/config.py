import json
import copy
import sys
from pathlib import Path
from typing import Dict

from .identity import IDENTITY_DIR
from .file_utils import save_json_atomically

CONFIG_FILE = IDENTITY_DIR / "config.json"


def get_default_config() -> Dict:
    """Returns the default configuration dictionary."""
    # A more user-friendly default location
    default_receive_path = Path.home() / "Downloads" / "PY2PY_Received"

    return {
        "language": "en",
        "network": {
            "chunk_size": 65536,
            "port": 35000,
        },
        "firewall": {
            "mode": "lan_only",  # "lan_only", "high_security", "public"
            "whitelist": [],
        },
        "receive": {
            "mode": "fixed",  # "fixed" or "ask"
            "location": str(default_receive_path),
        },
        "ui": {
            "show_only_recommended_interfaces": False,
        },
    }


def get_config() -> Dict:
    """
    Loads the configuration from disk, creating it from defaults if it doesn't exist.
    This function is designed to be robust against malformed or incomplete config files.
    """
    defaults = get_default_config()
    if not CONFIG_FILE.exists():
        save_config(defaults)
        return defaults

    try:
        user_config_raw = CONFIG_FILE.read_text()
        # Handle empty file case, which json.loads would otherwise accept as null
        if not user_config_raw.strip():
            raise ValueError("Config file is empty.")

        user_config = json.loads(user_config_raw)
        if not isinstance(user_config, dict):
            raise ValueError("User config is not a dictionary.")

        # Start with a deep copy of defaults, then selectively overwrite with valid user values.
        config = copy.deepcopy(defaults)

        # Robustly merge user settings, validating types along the way.
        for key, default_value in config.items():
            if key not in user_config:
                continue  # Use default value

            user_value = user_config[key]
            if isinstance(default_value, dict):
                # For nested dictionaries, merge them key by key to validate types.
                # This prevents injecting unexpected keys or wrong-typed values.
                if isinstance(user_value, dict):
                    for sub_key, sub_default_value in default_value.items():
                        if sub_key in user_value and isinstance(user_value.get(sub_key), type(sub_default_value)):
                            config[key][sub_key] = user_value[sub_key]
            elif isinstance(user_value, type(default_value)):
                # For top-level values, just check type and overwrite.
                config[key] = user_value

        # --- Post-merge validation for specific value ranges ---
        # This ensures that even if the type is correct, the value is sane.

        # Validate port number
        if not (1024 <= config["network"]["port"] <= 65535):
            config["network"]["port"] = defaults["network"]["port"]

        # Validate chunk size (e.g., 4KB to 1MB)
        if not (4096 <= config["network"]["chunk_size"] <= 1024 * 1024):
            config["network"]["chunk_size"] = defaults["network"]["chunk_size"]

        # Validate firewall mode
        if config["firewall"]["mode"] not in ["lan_only", "high_security", "public"]:
            config["firewall"]["mode"] = defaults["firewall"]["mode"]

        # Validate receive mode
        if config["receive"]["mode"] not in ["fixed", "ask"]:
            config["receive"]["mode"] = defaults["receive"]["mode"]

        return config

    except (json.JSONDecodeError, IOError, ValueError, TypeError, KeyError) as e:
        # If file is corrupt, unreadable, or malformed, log the error,
        # use the clean default config, and save it to fix the file.
        print(f"Warning: Could not load user configuration ('{e}'). Resetting to default settings.", file=sys.stderr)
        save_config(defaults)
        return defaults


def save_config(data: Dict):
    """Saves the configuration dictionary to disk atomically."""
    save_json_atomically(CONFIG_FILE, data)
