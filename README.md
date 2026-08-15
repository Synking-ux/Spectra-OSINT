# Spectra

Modular OSINT framework for email, username, domain, and IP intelligence.
Built for Kali/WSL. CLI-first, async, polite, and scriptable.

> **Responsible use:** This tool queries only public/open sources and ToS-compliant
> free APIs. Use it only against targets you own or are authorized to investigate.
> You are responsible for complying with the terms of service and rate limits of
> each source and with applicable law.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env      # add API keys you have
```

## Usage

```
spectra email    you@example.com
spectra username  alice
spectra domain    example.com
spectra ip        8.8.8.8
spectra all       example.com        # auto-detects target type
```

> Before installing globally, run in-repo with `python3 spectra.py` instead of `spectra`.

### Options

| Flag | Purpose |
|------|---------|
| `--proxy URL` / `--tor` | Route traffic (e.g. `socks5h://127.0.0.1:9050`) |
| `--delay N` | Min seconds between requests (politeness) |
| `--concurrency N` | Max concurrent requests |
| `--timeout N` | Per-request timeout |
| `--resolver IP` | Custom DNS resolver for brute force |
| `--wordlist FILE` | Custom subdomain wordlist |
| `--no-cache` / `--cache-file P` / `--cache-ttl N` | Response caching controls |
| `--json F` / `--csv F` / `--md F` | Export findings |
| `--list-modules` | Show all registered modules |

Examples:

```bash
spectra domain example.com --json report.json
spectra username alice --delay 0.4 --concurrency 20
spectra ip 8.8.8.8 --tor --csv ip.csv
spectra domain example.com --wordlist subdomains.txt --resolver 1.1.1.1
```

## Modules

**Username**
- `socials` — presence check across 40+ platforms (GitHub, GitLab, Reddit, HN,
  Steam, Twitch, Telegram, Dev.to, npm, PyPI, LeetCode, and more)

**Domain**
- `whois` — registrar, dates, nameservers, registrant org/country
- `dns` — A, AAAA, NS, MX, TXT, SOA, CNAME records
- `crt` — subdomain discovery from certificate transparency (crt.sh)
- `subdomain_brute` — DNS dictionary brute force (60 default names, extensible)
- `hackertarget` — known-subdomain hostsearch API
- `otx` — AlienVault OTX passive DNS *(key)*
- `fingerprint` — HTTP headers, status, and page title fingerprinting

**Email**
- `hibp` — HaveIBeenPwned breach report *(key)*
- `emailrep` — EmailRep.io reputation score
- `github_email` — GitHub users tied to a public email

**IP**
- `ipapi` — ip-api.com geolocation / ISP / ASN (free)
- `ipinfo` — ipinfo.io city, region, ASN, hostname
- `rdap` — RDAP registration data, prefix, and owning entities

Modules marked *(key)* auto-enable when the matching key exists in `.env`.

## How it works

- **Async HTTP** with retries/backoff, shared rate limiter, and optional Tor/proxy
  (`osint/core/http.py`)
- **SQLite cache** so free rate-limited APIs aren't re-hit on reruns
  (`osint/core/cache.py`)
- **Plugin registry** — drop a file in `osint/modules/<type>/` with `META` + `run`
  and it is picked up automatically (`osint/core/registry.py`)
- **Structured findings** — every result is a `Finding` exported to console, JSON,
  CSV, or Markdown

## Adding a module

Create `osint/modules/<target_type>/mymod.py`:

```python
from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "mymod",
    "target_type": "domain",
    "description": "what it does",
    "requires_key": None,          # or "SOME_API_KEY"
}

async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    data = await c.fetch("mymod", "https://api.example.com/...", params={"q": target})
    ...
```

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```
