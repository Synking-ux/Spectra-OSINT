from __future__ import annotations

import asyncio

from ...core.models import Finding

META = {
    "name": "rdap",
    "target_type": "ip",
    "description": "RDAP/WHOIS registration data for the IP and its prefix",
    "requires_key": None,
}


async def run(target: str, config: dict) -> list[Finding]:
    try:
        from ipwhois import IPWhois
    except ImportError:
        return []

    def _lookup():
        try:
            obj = IPWhois(target)
            return obj.lookup_rdap(depth=1)
        except Exception:
            return None

    res = await asyncio.to_thread(_lookup)
    if not res:
        return []
    findings = []
    asn = res.get("asn")
    if asn:
        findings.append(
            Finding(
                source="rdap",
                category="asn",
                value=str(asn),
                detail=res.get("asn_description", ""),
                target_type="ip",
            )
        )
    if res.get("asn_country_code"):
        findings.append(
            Finding(
                source="rdap",
                category="asn_country",
                value=res["asn_country_code"],
                target_type="ip",
            )
        )
    network = res.get("network") or {}
    if isinstance(network, dict):
        for field in ("name", "handle", "start_address", "end_address", "cidr", "country"):
            val = network.get(field)
            if val:
                findings.append(
                    Finding(
                        source="rdap",
                        category=f"net_{field}",
                        value=str(val),
                        target_type="ip",
                    )
                )
    entities = res.get("entities") or []
    if isinstance(entities, str):
        entities = [entities]
    for ent in entities[:5]:
        if not isinstance(ent, dict):
            findings.append(
                Finding(
                    source="rdap",
                    category="entity",
                    value=str(ent),
                    detail="raw handle",
                    target_type="ip",
                )
            )
            continue
        roles = ent.get("roles", [])
        if isinstance(roles, str):
            roles = [roles]
        handle = ent.get("handle", "")
        vcard = ent.get("vcardArray", [])
        name = ""
        if len(vcard) >= 2 and isinstance(vcard[1], list):
            for entry in vcard[1]:
                if isinstance(entry, list) and len(entry) > 3 and entry[0] == "fn":
                    name = entry[3] or ""
        findings.append(
            Finding(
                source="rdap",
                category="entity",
                value=name or handle or (roles[0] if roles else ""),
                detail=", ".join(roles),
                target_type="ip",
            )
        )
    return findings