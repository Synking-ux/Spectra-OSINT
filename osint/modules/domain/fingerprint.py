from __future__ import annotations

import re

from ...core.context import client as get_client
from ...core.models import Finding

META = {
    "name": "fingerprint",
    "target_type": "domain",
    "description": "HTTP header + page-title technology fingerprinting",
    "requires_key": None,
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
HEADERS_OF_INTEREST = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "via",
    "x-generator",
    "x-amz-cf-id",
    "x-backend-server",
    "x-served-by",
    "x-vercel-id",
    "x-github-request-id",
)


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    findings: list[Finding] = []
    seen = set()

    for base in (f"https://{target}", f"http://{target}"):
        resp = await c.fetch_response(base)
        if resp is None:
            continue
        status = resp.status_code
        final_url = str(resp.url)
        findings.append(
            Finding(
                source="fingerprint",
                category="http_status",
                value=final_url,
                detail=f"status {status}",
                target_type="domain",
            )
        )
        for h in HEADERS_OF_INTEREST:
            val = resp.headers.get(h)
            if val:
                key = f"{h}: {val}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        Finding(
                            source="fingerprint",
                            category=f"header_{h}",
                            value=val,
                            detail=final_url,
                            target_type="domain",
                        )
                    )
        m = TITLE_RE.search(resp.text or "")
        if m:
            title = m.group(1).strip()
            if title and title not in seen:
                seen.add(title)
                findings.append(
                    Finding(
                        source="fingerprint",
                        category="page_title",
                        value=title,
                        detail=final_url,
                        target_type="domain",
                    )
                )
        break  # only follow the first reachable scheme

    return findings