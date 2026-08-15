from __future__ import annotations

from urllib.parse import quote

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "hibp",
    "target_type": "email",
    "description": "HaveIBeenPwned breach report (requires HIBP_API_KEY)",
    "requires_key": "HIBP_API_KEY",
}


def parse_breaches(data) -> list[dict]:
    if not isinstance(data, list):
        return []
    return [
        {
            "name": b.get("Name", ""),
            "date": b.get("BreachDate", ""),
            "domain": b.get("Domain", ""),
            "classes": ", ".join(b.get("DataClasses", []) or []),
        }
        for b in data
    ]


async def run(target: str, config: dict) -> list[Finding]:
    key = config.get("HIBP_API_KEY", "")
    if not key:
        return []
    c = get_client()
    data = await c.fetch(
        "hibp",
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target)}",
        headers={
            "hibp-api-key": key,
            "accept": "application/json",
        },
    )
    if not data:
        return []
    findings = []
    for b in parse_breaches(data):
        findings.append(
            Finding(
                source="hibp",
                category="breach",
                value=b["name"],
                detail=f"{b['date']} | {b['domain']} | {b['classes']}",
                target_type="email",
            )
        )
    return findings