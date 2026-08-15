from __future__ import annotations

import argparse
import asyncio
import ipaddress
import re
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from . import __version__
from .config import load_config
from .core.cache import Cache
from .core.http import HttpClient
from .core.models import Finding
from .core.registry import ModuleInfo, discover
from .core.reporting import export_csv, export_json, export_markdown, render_console

console = Console()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def guess_type(target: str) -> str:
    if EMAIL_RE.match(target):
        return "email"
    if IP_RE.match(target):
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass
    if "." in target and " " not in target and not target.startswith(("http://", "https://")):
        return "domain"
    return "username"


async def _safe_run(info: ModuleInfo, target: str, config: dict) -> list[Finding] | BaseException:
    try:
        return await info.run(target, config)
    except Exception as exc:  # module errors must not kill the whole run
        return exc


async def run_modules(
    modules: list[ModuleInfo], target: str, config: dict
) -> tuple[list[Finding], list[str], list[str], list[tuple[str, str]]]:
    tasks: list[asyncio.Future] = []
    used: list[str] = []
    skipped: list[str] = []
    for info in modules:
        if info.needs_key and not config.get(info.requires_key or ""):
            skipped.append(f"{info.name} (missing {info.requires_key})")
            continue
        used.append(info.name)
        tasks.append(asyncio.ensure_future(_safe_run(info, target, config)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings: list[Finding] = []
    failed: list[tuple[str, str]] = []
    for name, res in zip(used, results):
        if isinstance(res, BaseException):
            failed.append((name, f"{type(res).__name__}: {res}"))
        else:
            findings.extend(res or [])
    return findings, used, skipped, failed


async def run_target(
    target_type: str, target: str, config: dict, cache: Cache, args: argparse.Namespace
) -> None:
    reg = discover()
    modules = reg.get(target_type, [])
    if not modules:
        console.print(f"[red]No modules registered for target type '{target_type}'.[/red]")
        return

    if not args.quiet:
        console.print(
            Panel(
                f"[bold cyan]{target_type}[/bold cyan]: [white]{target}[/white]\n"
                f"[dim]modules: {', '.join(m.name for m in modules)}[/dim]",
                title=f"SPECTRA v{__version__}",
            )
        )

    findings, used, skipped, failed = await run_modules(modules, target, config)

    render_console(findings)
    if failed:
        console.print("[dim]Module errors:[/dim]")
        for name, err in failed:
            console.print(f"  [red]{name}[/red]: {err}")

    if not args.quiet:
        skipped_txt = ", ".join(skipped) or "none"
        console.print(
            f"\n[bold]{len(findings)} finding(s)[/bold] from {len(used)} module(s). "
            f"[yellow]{len(skipped)} skipped[/yellow] "
            f"[dim]({skipped_txt})[/dim]."
        )

    base = args.json or args.csv or args.md
    if base:
        stem = base.rsplit(".", 1)[0]
        if args.json:
            export_json(findings, args.json)
            console.print(f"[green]JSON written to {args.json}[/green]")
        if args.csv:
            export_csv(findings, args.csv)
            console.print(f"[green]CSV written to {args.csv}[/green]")
        if args.md:
            export_markdown(findings, args.md)
            console.print(f"[green]Markdown written to {args.md}[/green]")


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--proxy", help="HTTP/SOCKS proxy URL (e.g. socks5h://127.0.0.1:9050)")
    p.add_argument("--tor", action="store_true", help="route via Tor (socks5h://127.0.0.1:9050)")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    p.add_argument("--delay", type=float, default=0.0, help="min seconds between requests")
    p.add_argument("--concurrency", type=int, default=10, help="max concurrent requests")
    p.add_argument("--no-cache", action="store_true", help="disable response caching")
    p.add_argument("--cache-file", default=".osint-cache.db", help="cache database path")
    p.add_argument("--cache-ttl", type=int, default=86400, help="cache TTL in seconds")
    p.add_argument("--resolver", help="custom DNS resolver IP for subdomain brute force")
    p.add_argument("--wordlist", help="file with one subdomain name per line (domain brute)")
    p.add_argument("--json", help="export findings to JSON file")
    p.add_argument("--csv", help="export findings to CSV file")
    p.add_argument("--md", help="export findings to Markdown file")
    p.add_argument("--quiet", action="store_true", help="suppress banner and module summary")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    p = argparse.ArgumentParser(
        prog="spectra",
        parents=[common],
        description="Spectra: modular OSINT framework - email, username, domain and IP intelligence.",
        epilog="Example: spectra domain example.com --json report.json",
    )
    p.add_argument("--version", action="version", version=f"spectra {__version__}")
    p.add_argument("--list-modules", action="store_true", help="list registered modules and exit")

    sub = p.add_subparsers(dest="subcommand", metavar="target-type")
    for ttype in ("email", "username", "domain", "ip", "all"):
        sp = sub.add_parser(ttype, parents=[common], help=f"run {ttype} modules")
        sp.add_argument("target", help=f"the {ttype} to investigate")
    return p


def _resolve_proxy(args: argparse.Namespace) -> Optional[str]:
    if args.tor:
        return "socks5h://127.0.0.1:9050"
    return args.proxy


async def _amain() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_modules:
        reg = discover()
        for ttype, modules in reg.items():
            for m in modules:
                needs = f"[yellow]key:{m.requires_key}[/yellow]" if m.needs_key else "[green]no key[/green]"
                console.print(f"[cyan]{ttype:10s}[/cyan] {m.name:18s} {needs}  {m.description}")
        return 0

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "all":
        target_type = guess_type(args.target)
    else:
        target_type = args.subcommand

    config = load_config()
    cache = Cache(args.cache_file, ttl=args.cache_ttl, enabled=not args.no_cache)
    client = HttpClient(
        proxy=_resolve_proxy(args),
        timeout=args.timeout,
        cache=cache,
        rate=args.delay,
        concurrent=args.concurrency,
    )
    try:
        from .core.context import _set as _ctx_set

        _ctx_set(client, config, args)
        await run_target(target_type, args.target, config, cache, args)
    finally:
        await client.close()
        cache.close()
    return 0


def main() -> None:
    try:
        code = asyncio.run(_amain())
    except KeyboardInterrupt:
        code = 130
        console.print("\n[yellow]Interrupted.[/yellow]")
    sys.exit(code)