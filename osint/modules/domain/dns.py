from __future__ import annotations

import asyncio

from ...core.context import args as get_args
from ...core.models import Finding

META = {
    "name": "dns",
    "target_type": "domain",
    "description": "DNS records (A, AAAA, NS, MX, TXT, SOA, CNAME)",
    "requires_key": None,
}

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME")


async def resolve_records(domain: str) -> dict[str, list[str]]:
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 4.0
    resolver.timeout = 4.0
    args = get_args()
    if args and getattr(args, "resolver", None):
        try:
            resolver.nameservers = [args.resolver]
        except Exception:
            pass

    def _query(rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(domain, rtype)
            return [str(a) for a in answers]
        except Exception:
            return []

    out: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        out[rtype] = await asyncio.to_thread(_query, rtype)
    return out


async def run(target: str, config: dict) -> list[Finding]:
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return []
    records = await resolve_records(target)
    findings: list[Finding] = []
    for rtype, values in records.items():
        for v in values:
            findings.append(
                Finding(
                    source="dns",
                    category=f"dns_{rtype.lower()}",
                    value=v,
                    target_type="domain",
                )
            )
    return findings