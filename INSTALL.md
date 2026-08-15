# INSTALL.md — Spectra (osint-tool)

Installation and setup guide for the modular OSINT framework.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.11+** | Tested on 3.13 (WSL Kali) |
| **pip** | Bundled with the venv in this guide |
| **whois** binary | Optional but recommended for the `whois` module (already present in Kali) |
| **git** (optional) | Only needed if you clone the repo from a remote |
| **Tor** (optional) | Only needed for `--tor` |

Check your environment:

```bash
python3 --version
```

If `pip` is missing (common on Kali), don't install it system-wide — the
virtual environment below provides its own pip automatically.

---

## 2. Get the code

Clone the repository (or copy the project folder to your machine):

```bash
git clone <repo-url> osint-tool
cd osint-tool
```

Inside the project you should see:

```
osint-tool/
├── osint/            # framework source
│   ├── cli.py
│   ├── config.py
│   ├── core/         # http, cache, registry, reporting, models
│   └── modules/      # email/ username/ domain/ ip/ modules
├── tests/            # pytest suite
├── requirements.txt
├── pyproject.toml    # enables `pip install .` → global `spectra` command
├── spectra.py        # entry point (or run `python3 spectra.py`)
└── .env.example      # template for API keys
```

---

## 3. Create a virtual environment

From inside the project folder:

```bash
cd osint-tool

python3 -m venv .venv
```

> `python3 -m venv` may fail on some systems if the `venv` module or
> `ensurepip` is incomplete. On Kali, if that happens, install the missing
> pieces without sudo-free pip by using the bundled wheels — the error message
> will tell you which `python3-*` package to add via `sudo apt install`.

Activate it (optional — you can also call the interpreter directly):

```bash
# WSL / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

---

## 4. Install dependencies

```bash
# WSL / Linux (or any shell once venv is active)
.venv/bin/pip install -r requirements.txt

# Windows PowerShell
.venv\Scripts\pip install -r requirements.txt
```

Dependencies installed:

- `httpx[socks]` — async HTTP client + SOCKS proxy support for Tor
- `rich` — terminal tables and output formatting
- `python-dotenv` — loads `.env` API keys
- `python-whois` — WHOIS lookups (needs the `whois` binary)
- `dnspython` — DNS record queries + subdomain brute force
- `ipwhois` — RDAP/WHOIS for IP intelligence

Verify the install:

```bash
.venv/bin/python -c "import httpx, rich, whois, dns, ipwhois; print('deps OK')"
```

---

## 5. Configure API keys (optional)

Free, no-key modules work out of the box. Key-based modules auto-activate only
when their key exists.

```bash
cp .env.example .env
```

Edit `.env` and fill in the keys you have:

```bash
HIBP_API_KEY=          # HaveIBeenPwned v3 (free): https://haveibeenpwned.com/API/Key
EMAILREP_API_KEY=      # EmailRep.io (free tier): https://emailrep.io
GITHUB_TOKEN=          # GitHub PAT (raises search rate limits)
VIRUSTOTAL_API_KEY=    # (reserved)
OTX_API_KEY=           # AlienVault OTX (free): https://otx.alienvault.com/api
IPINFO_TOKEN=          # ipinfo.io (free, 50k req/mo)
```

Key-dependent modules and their keys:

| Module | Key | Notes |
|---|---|---|
| `hibp` | `HIBP_API_KEY` | required |
| `otx` | `OTX_API_KEY` | required |
| `emailrep` | `EMAILREP_API_KEY` | optional (works without, lower limits) |
| `github_email` | `GITHUB_TOKEN` | optional |
| `ipinfo` | `IPINFO_TOKEN` | optional |

---

## 6. Install globally (optional)

Run `spectra` from anywhere on the system.

### Option A — proper install (recommended)

`pyproject.toml` registers a real `spectra` command, so the package is always
importable no matter where you run it:

```bash
.venv/bin/pip install .
spectra --version
```

Editable install (command tracks your code as you edit it):

```bash
.venv/bin/pip install -e .
```

### Option B — drop the script in /usr/bin

```bash
cp spectra.py /usr/bin/spectra
chmod +x /usr/bin/spectra
```

> **Warning:** this only works while the `osint` package is importable — e.g.
> when running from the project directory or with the project on
> `PYTHONPATH`. Running `/usr/bin/spectra` from an unrelated folder will fail
> with `ModuleNotFoundError: No module named 'osint'`. Use Option A instead.

---

## 7. First run

List available modules:

```bash
spectra --list-modules
```

Run a quick smoke test (no keys needed):

```bash
spectra ip 8.8.8.8
spectra domain example.com
spectra username torvalds
```

---

## 8. Run the tests

```bash
.venv/bin/python -m pytest tests/ -q
```

Expected result: `24 passed`.

---

## 9. Usage cheat sheet

```bash
spectra email    you@example.com              # Linux/macOS/WSL
spectra email    you@example.com              # Windows (via WSL or venv)

spectra username alice --delay 0.4 --concurrency 20
spectra domain   example.com --json report.json
spectra ip       8.8.8.8 --csv ip.csv
spectra all      example.com --quiet
```

> In-repo (no global install yet): replace `spectra` with `python3 spectra.py`
> (or `.venv/bin/python spectra.py`).

Common flags:

| Flag | Purpose |
|---|---|
| `--proxy URL` / `--tor` | Route traffic (e.g. `socks5h://127.0.0.1:9050`) |
| `--delay N` | Min seconds between requests (be polite) |
| `--concurrency N` | Max concurrent requests (default 10) |
| `--timeout N` | Per-request timeout in seconds (default 15) |
| `--resolver IP` | Custom DNS resolver for brute force |
| `--wordlist FILE` | Custom subdomain wordlist (one name per line) |
| `--no-cache` | Disable SQLite response cache |
| `--cache-file P` / `--cache-ttl N` | Cache path / TTL (default 86400s) |
| `--json F` / `--csv F` / `--md F` | Export findings |
| `--list-modules` | Show all registered modules |
| `--quiet` | Suppress banner and summary |

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named ...` | venv not active or deps not installed → repeat step 4 |
| `pip` missing on Kali | Don't apt-install; create the venv (step 3) — it ships its own pip |
| `python3 -m venv` fails on Debian/Ubuntu | Install `python3-venv` and `python3-pip`: `sudo apt install python3-venv python3-pip` |
| `whois` module returns nothing | Install the `whois` binary: `sudo apt install whois` (Linux), or `choco install whois` (Windows) |
| `--tor` connection errors | Start Tor first (`sudo systemctl start tor` or `tor &`), verify with `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip` |
| Module says `skipped (missing ...)` | Add the API key to `.env` (step 5) |
| SSL / certificate errors | Check system clock is correct; or pass a custom `--proxy` if required |
| Cache grows stale | Delete the `.osint-cache.db` file or raise `--cache-ttl` |
| Slow subdomain brute | Pass `--resolver 1.1.1.1` and a `--wordlist` tuned to your target |

---

## 11. Responsible use

This tool queries only public/open sources and ToS-compliant free APIs. Use it
only against targets you own or are explicitly authorized to investigate. You
are responsible for obeying each source's terms of service, rate limits, and
applicable law.
