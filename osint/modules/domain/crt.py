from __future__ import annotations

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "crt",
    "target_type": "domain",
    "description": "Certificate transparency logs (crt.sh) for subdomain discovery",
    "requires_key": None,
}


def parse_names(data) -> set[str]:
    """Extract unique hostnames from crt.sh JSON output."""
    if not isinstance(data, list):
        return set()
    names: set[str] = set()
    for row in data:
        for key in ("name_value", "common_name"):
            val = row.get(key)
            if not val:
                continue
            for part in val.split("\n"):
                part = part.strip().lstrip("*.")
                if part and "." in part:
                    names.add(part)
    return names


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    data = await c.fetch(
        "crt", f"https://crt.sh/?q=%25.{target}&output=json", as_text=False
    )
    if not data:
        return []
    names = parse_names(data)
    # Only keep names under the target domain
    target_l = target.lower()
    findings = []
    for name in sorted(names):
        n = name.lower()
        if n == target_l or n.endswith("." + target_l):
            findings.append(
                Finding(
                    source="crt.sh",
                    category="ct_log_subdomain",
                    value=name,
                    target_type="domain",
                )
            )
    return findings