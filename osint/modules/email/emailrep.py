from __future__ import annotations

from urllib.parse import quote

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "emailrep",
    "target_type": "email",
    "description": "EmailRep.io reputation score (optional EMAILREP_API_KEY)",
    "requires_key": "EMAILREP_API_KEY",
}


def parse_emailrep(data) -> list[dict]:
    if not isinstance(data, dict) or data.get("status") not in (None, "ok"):
        return []
    out = []
    score = data.get("reputation")
    if score is not None:
        out.append(("reputation", str(score)))
    if data.get("suspicious") is not None:
        out.append(("suspicious", str(data["suspicious"])))
    if data.get("references"):
        out.append(("references", str(data["references"])))
    if data.get("details", {}).get("breached"):
        out.append(("breached", str(data["details"]["breached"])))
    if data.get("details", {}).get("malicious_activity"):
        out.append(("malicious_activity", str(data["details"]["malicious_activity"])))
    return out


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    key = config.get("EMAILREP_API_KEY", "")
    headers = {"Key": key} if key else {}
    data = await c.fetch(
        "emailrep", f"https://emailrep.io/{quote(target)}", headers=headers
    )
    if not data:
        return []
    findings = []
    for cat, val in parse_emailrep(data):
        findings.append(
            Finding(source="emailrep", category=cat, value=val, target_type="email")
        )
    return findings