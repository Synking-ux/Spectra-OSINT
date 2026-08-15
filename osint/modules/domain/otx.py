from __future__ import annotations

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "otx",
    "target_type": "domain",
    "description": "AlienVault OTX passive DNS (requires OTX_API_KEY)",
    "requires_key": "OTX_API_KEY",
}


def parse_otx(data) -> list[tuple[str, str]]:
    if not isinstance(data, dict):
        return []
    out = []
    for row in data.get("passive_dns", []) or []:
        host = row.get("hostname")
        addr = row.get("address")
        if host and addr:
            out.append((host, addr))
    return out


async def run(target: str, config: dict) -> list[Finding]:
    key = config.get("OTX_API_KEY", "")
    if not key:
        return []
    c = get_client()
    data = await c.fetch(
        "otx",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
        headers={"X-OTX-API-KEY": key},
    )
    findings = []
    for host, addr in parse_otx(data):
        findings.append(
            Finding(
                source="otx",
                category="passive_dns",
                value=host,
                detail=addr,
                target_type="domain",
            )
        )
    return findings