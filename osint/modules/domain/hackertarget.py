from __future__ import annotations

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "hackertarget",
    "target_type": "domain",
    "description": "HackerTarget hostsearch for known subdomains",
    "requires_key": None,
}


def parse_hostsearch(text) -> list[tuple[str, str]]:
    if not text or not isinstance(text, str):
        return []
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            rows.append((parts[0].strip(), parts[1].strip()))
    return rows


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    text = await c.fetch(
        "hackertarget",
        "https://api.hackertarget.com/hostsearch/",
        params={"q": target},
        as_text=True,
        cached=True,
    )
    if isinstance(text, (dict, list)):
        return []
    findings = []
    for host, ip in parse_hostsearch(text):
        findings.append(
            Finding(
                source="hackertarget",
                category="known_subdomain",
                value=host,
                detail=ip,
                target_type="domain",
            )
        )
    return findings