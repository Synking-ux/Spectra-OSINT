from __future__ import annotations

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "ipapi",
    "target_type": "ip",
    "description": "ip-api.com geolocation, ISP and ASN (free, no key)",
    "requires_key": None,
}

FIELDS = (
    "country",
    "regionName",
    "city",
    "zip",
    "isp",
    "org",
    "as",
    "lat",
    "lon",
    "timezone",
)


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    data = await c.fetch("ipapi", f"http://ip-api.com/json/{target}")
    if not isinstance(data, dict) or data.get("status") != "success":
        return []
    findings = []
    for field in FIELDS:
        val = data.get(field)
        if val not in (None, ""):
            findings.append(
                Finding(
                    source="ip-api",
                    category=f"geo_{field}",
                    value=str(val),
                    target_type="ip",
                )
            )
    return findings