from __future__ import annotations

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "ipinfo",
    "target_type": "ip",
    "description": "ipinfo.io details (optional IPINFO_TOKEN)",
    "requires_key": "IPINFO_TOKEN",
}

FIELDS = ("city", "region", "country", "postal", "org", "asn", "hostname", "timezone", "loc")


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    token = config.get("IPINFO_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    data = await c.fetch("ipinfo", f"https://ipinfo.io/{target}/json", headers=headers)
    if not isinstance(data, dict):
        return []
    findings = []
    for field in FIELDS:
        val = data.get(field)
        if val not in (None, ""):
            findings.append(
                Finding(
                    source="ipinfo",
                    category=f"info_{field}",
                    value=str(val),
                    target_type="ip",
                )
            )
    company = data.get("company")
    if isinstance(company, dict) and company.get("name"):
        findings.append(
            Finding(
                source="ipinfo",
                category="info_company",
                value=company["name"],
                detail=company.get("domain", ""),
                target_type="ip",
            )
        )
    return findings