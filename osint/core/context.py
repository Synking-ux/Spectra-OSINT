"""Process-wide runtime context handed to modules by the CLI."""

from __future__ import annotations

from typing import Any, Optional

_active_client = None
_active_config: dict[str, str] = {}
_active_args: Optional[Any] = None


def client():
    return _active_client


def config() -> dict[str, str]:
    return _active_config


def args() -> Optional[Any]:
    return _active_args


def _set(client, config, args) -> None:
    global _active_client, _active_config, _active_args
    _active_client = client
    _active_config = config
    _active_args = args