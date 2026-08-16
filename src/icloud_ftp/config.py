"""TOML configuration loading and safe, atomic persistence."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


DEFAULT_CONFIG_PATH = Path("icloud-webdav.toml")

DEFAULT_CONFIG: dict[str, dict[str, Any] | int] = {
    "version": 1,
    "icloud": {
        "session_dir": ".state/icloudpy",
        "region": "global",
        "auth_method": "ask",
        "apple_password_env": "ICLOUD_PASSWORD",
        "drive_cache_seconds": 5,
    },
    "webdav": {
        "host": "127.0.0.1",
        "port": 8080,
        "user": "icloud",
        "password_env": "ICLOUD_WEBDAV_PASSWORD",
    },
    "database": {
        "url_env": "DATABASE_URL",
    },
    "valkey": {
        "url_env": "VALKEY_URL",
        "namespace": "default",
        "lock_ttl": 120,
        "change_limit": 1000,
        "delete_ratio_percent": 20,
    },
    "key_broker": {
        "endpoint": "unix:///run/keybroker/keybroker.sock",
    },
    "encryption": {
        "enabled": False,
        "recovery_public_file": ".state/recovery-public.json",
        "vault_folder": ".icloud-ftp-vault",
        "strict_plaintext": True,
        "kem": "ML-KEM-768",
        "hybrid_x25519": False,
        "chunk_size_mb": 8,
        "retention_days": 30,
        "small_versions": 10,
        "medium_versions": 5,
        "large_versions": 3,
        "medium_threshold_mb": 100,
        "large_threshold_mb": 1024,
        "capacity_limit_gb": 0,
    },
}

SECTIONS = ("icloud", "webdav", "database", "valkey", "key_broker", "encryption")


def load_config(path: Path) -> dict[str, Any]:
    """Load a config file, returning defaults when it does not exist."""
    if not path.exists():
        return {
            "version": DEFAULT_CONFIG["version"],
            "icloud": dict(DEFAULT_CONFIG["icloud"]),
            "webdav": dict(DEFAULT_CONFIG["webdav"]),
            "database": dict(DEFAULT_CONFIG["database"]),
            "valkey": dict(DEFAULT_CONFIG["valkey"]),
            "key_broker": dict(DEFAULT_CONFIG["key_broker"]),
            "encryption": dict(DEFAULT_CONFIG["encryption"]),
        }
    with path.open("rb") as stream:
        loaded = tomllib.load(stream)
    if not isinstance(loaded, dict):
        raise ValueError("configuration root must be a TOML table")
    merged = {
        "version": loaded.get("version", DEFAULT_CONFIG["version"]),
        "icloud": dict(DEFAULT_CONFIG["icloud"]),
        "webdav": dict(DEFAULT_CONFIG["webdav"]),
        "database": dict(DEFAULT_CONFIG["database"]),
        "valkey": dict(DEFAULT_CONFIG["valkey"]),
        "key_broker": dict(DEFAULT_CONFIG["key_broker"]),
        "encryption": dict(DEFAULT_CONFIG["encryption"]),
    }
    for section in SECTIONS:
        values = loaded.get(section, {})
        if not isinstance(values, dict):
            raise ValueError(f"[{section}] must be a TOML table")
        merged[section].update(values)
    return merged


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # JSON string syntax is valid TOML basic-string syntax for our values.
        return json.dumps(value, ensure_ascii=False)
    raise TypeError(f"unsupported configuration value: {type(value).__name__}")


def _render(config: dict[str, Any]) -> str:
    lines = [f"version = {_toml_value(int(config.get('version', 1)))}", ""]
    for section in SECTIONS:
        lines.append(f"[{section}]")
        values = config.get(section, {})
        for key in sorted(values):
            value = values[key]
            if value is not None:
                lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


def save_config(path: Path, config: dict[str, Any]) -> None:
    """Atomically save configuration with owner-only permissions on POSIX."""
    path = path.expanduser().resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(_render(config))
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def config_from_auth_args(args, existing: dict[str, Any]) -> dict[str, Any]:
    """Update non-secret login settings while preserving gateway preferences."""
    config = {
        "version": 1,
        "icloud": dict(existing.get("icloud", {})),
        "webdav": dict(existing.get("webdav", {})),
        "database": dict(existing.get("database", {})),
        "valkey": dict(existing.get("valkey", {})),
        "key_broker": dict(existing.get("key_broker", {})),
        "encryption": dict(existing.get("encryption", {})),
    }
    config["icloud"].update(
        {
            "apple_id": args.apple_id,
            "session_dir": args.session_dir,
            "region": args.region,
            "auth_method": args.auth_method,
            "apple_password_env": args.apple_password_env,
        }
    )
    return config
