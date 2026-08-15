from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import osint.modules as modules_pkg

TARGET_TYPES = ("email", "username", "domain", "ip")


@dataclass
class ModuleInfo:
    name: str
    target_type: str
    description: str
    requires_key: Optional[str]
    run: Callable

    @property
    def needs_key(self) -> bool:
        return bool(self.requires_key)


_registry: dict[str, list[ModuleInfo]] | None = None


def discover() -> dict[str, list[ModuleInfo]]:
    """Auto-discover modules from osint.modules.<type>.<file>. Callable idempotently."""
    global _registry
    if _registry is not None:
        return _registry

    reg: dict[str, list[ModuleInfo]] = {t: [] for t in TARGET_TYPES}
    pkg = importlib.import_module("osint.modules")
    for _, tname, ispkg in pkgutil.iter_modules(pkg.__path__):
        if not ispkg or tname not in TARGET_TYPES:
            continue
        sub = importlib.import_module(f"osint.modules.{tname}")
        for _, fname, _ in pkgutil.iter_modules(sub.__path__):
            if fname.startswith("_"):
                continue
            mod = importlib.import_module(f"osint.modules.{tname}.{fname}")
            meta = getattr(mod, "META", None)
            if not meta or not callable(getattr(mod, "run", None)):
                continue
            reg[meta["target_type"]].append(
                ModuleInfo(
                    name=meta.get("name", fname),
                    target_type=meta["target_type"],
                    description=meta.get("description", ""),
                    requires_key=meta.get("requires_key"),
                    run=mod.run,
                )
            )
    _registry = reg
    return reg


def all_modules() -> list[ModuleInfo]:
    reg = discover()
    return [m for ms in reg.values() for m in ms]