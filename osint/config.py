from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

KEY_FIELDS = (
    "HIBP_API_KEY",
    "EMAILREP_API_KEY",
    "GITHUB_TOKEN",
    "VIRUSTOTAL_API_KEY",
    "OTX_API_KEY",
    "IPINFO_TOKEN",
)


def default_env_path() -> Path:
    return Path(__file__).resolve().parent.parent / ".env"


def load_config(env_path: str | Path | None = None) -> dict[str, str]:
    """Load API keys from .env (or env vars). Returns dict of key->value or empty string."""
    if env_path is None:
        env_path = default_env_path()
    if Path(env_path).exists():
        load_dotenv(Path(env_path))
    return {k: (os.getenv(k) or "").strip() for k in KEY_FIELDS}