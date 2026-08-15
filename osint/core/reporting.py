from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.table import Table

from .models import Finding


def render_console(findings: Iterable[Finding]) -> None:
    console = Console()
    items = list(findings)
    if not items:
        console.print("[yellow]No findings.[/yellow]")
        return
    by_type: dict[str, list[Finding]] = defaultdict(list)
    for f in items:
        by_type[f.target_type or "general"].append(f)
    for ttype, group in by_type.items():
        table = Table(title=f"[bold]{ttype.upper()}[/bold] findings", show_lines=True)
        table.add_column("Source", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Value")
        table.add_column("Detail")
        for f in group:
            table.add_row(f.source, f.category, f.value, f.detail or "")
        console.print(table)


def export_json(findings: Iterable[Finding], path: str | Path) -> None:
    Path(path).write_text(
        json.dumps([f.to_dict() for f in findings], indent=2, default=str),
        encoding="utf-8",
    )


def export_csv(findings: Iterable[Finding], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["target_type", "source", "category", "value", "detail"])
        for f in findings:
            w.writerow([f.target_type, f.source, f.category, f.value, f.detail])


def export_markdown(findings: Iterable[Finding], path: str | Path) -> None:
    by_type: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_type[f.target_type or "general"].append(f)
    lines = ["# OSINT Report", ""]
    for ttype, group in by_type.items():
        lines.append(f"## {ttype}")
        lines.append("")
        lines.append("| Source | Category | Value | Detail |")
        lines.append("|---|---|---|---|")
        for f in group:
            d = (f.detail or "").replace("|", "\\|")
            v = f.value.replace("|", "\\|")
            lines.append(f"| {f.source} | {f.category} | {v} | {d} |")
        lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")