from __future__ import annotations

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "github_email",
    "target_type": "email",
    "description": "GitHub user search for public email (optional GITHUB_TOKEN)",
    "requires_key": "GITHUB_TOKEN",
}


def parse_github_users(data) -> list[tuple[str, str]]:
    if not isinstance(data, dict):
        return []
    out = []
    for item in data.get("items", []) or []:
        login = item.get("login")
        if login:
            out.append((login, item.get("html_url", "")))
    return out


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    token = config.get("GITHUB_TOKEN", "")
    headers = {"Authorization": f"token {token}"} if token else {}
    data = await c.fetch(
        "github",
        "https://api.github.com/search/users",
        params={"q": target},
        headers=headers,
    )
    if not data:
        return []
    findings = []
    for login, url in parse_github_users(data):
        findings.append(
            Finding(
                source="github",
                category="github_user",
                value=login,
                detail=url,
                target_type="email",
            )
        )
    return findings