from __future__ import annotations

import asyncio
from datetime import datetime

from ...core.models import Finding

META = {
    "name": "whois",
    "target_type": "domain",
    "description": "WHOIS registration details (registrar, dates, contacts)",
    "requires_key": None,
}


def _fmt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_fmt(v) for v in value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


def parse_whois(w) -> list[tuple[str, str]]:
    fields = [
        ("registrar", getattr(w, "registrar", None)),
        ("creation_date", getattr(w, "creation_date", None)),
        ("expiration_date", getattr(w, "expiration_date", None)),
        ("updated_date", getattr(w, "updated_date", None)),
        ("name_servers", getattr(w, "name_servers", None)),
        ("status", getattr(w, "status", None)),
        ("org", getattr(w, "org", None)),
        ("country", getattr(w, "country", None)),
        ("emails", getattr(w, "emails", None)),
    ]
    return [(k, _fmt(v)) for k, v in fields if v]


async def run(target: str, config: dict) -> list[Finding]:
    try:
        import whois
    except ImportError:
        return []

    def _lookup():
        try:
            return whois.whois(target)
        except Exception:
            return None

    w = await asyncio.to_thread(_lookup)
    if w is None:
        return []
    findings = []
    for key, val in parse_whois(w):
        findings.append(
            Finding(
                source="whois",
                category=key,
                value=val,
                target_type="domain",
            )
        )
    return findings