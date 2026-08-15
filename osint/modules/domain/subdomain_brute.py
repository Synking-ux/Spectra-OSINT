from __future__ import annotations

import asyncio
from pathlib import Path

from ...core.context import args as get_args
from ...core.models import Finding

META = {
    "name": "subdomain_brute",
    "target_type": "domain",
    "description": "DNS dictionary brute force for common subdomains",
    "requires_key": None,
}

DEFAULT_WORDS = (
    "www mail smtp pop imap ftp ssh remote dev staging test api app m mobile wap web "
    "portal admin adm cpanel webmail vpn ns1 ns2 mx dns dns1 dns2 news nntp proxy www2 "
    "www1 shop store blog forum support help status docs jenkins git svn phpmyadmin db "
    "mysql sql server backup cache beta demo intranet localhost secure ssl test2 sandbox "
    "production qa uat vpn2 gateway gw mx2 mx1 ns3 mail2 email owd autodiscover "
    "autoconfig office365 relay lists list blog2 cms old new"
).split()


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return list(DEFAULT_WORDS)
    p = Path(path)
    if not p.exists():
        return list(DEFAULT_WORDS)
    words = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    return words or list(DEFAULT_WORDS)


async def run(target: str, config: dict) -> list[Finding]:
    try:
        import dns.resolver
    except ImportError:
        return []

    args = get_args()
    words = load_wordlist(getattr(args, "wordlist", None) if args else None)

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 3.0
    resolver.timeout = 3.0
    if args and getattr(args, "resolver", None):
        try:
            resolver.nameservers = [args.resolver]
        except Exception:
            pass

    found: list[Finding] = []
    sem = asyncio.Semaphore(50)

    async def probe(name: str) -> None:
        host = f"{name}.{target}"
        async with sem:
            def _q():
                try:
                    answers = resolver.resolve(host, "A")
                    return [str(a) for a in answers]
                except Exception:
                    return []
            addrs = await asyncio.to_thread(_q)
        if addrs:
            found.append(
                Finding(
                    source="dns_brute",
                    category="brute_subdomain",
                    value=host,
                    detail=", ".join(addrs),
                    target_type="domain",
                )
            )

    await asyncio.gather(*(probe(w) for w in words))
    return found