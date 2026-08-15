from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single OSINT observation produced by a module."""

    source: str
    category: str
    value: str
    detail: str = ""
    target_type: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)