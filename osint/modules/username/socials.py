from __future__ import annotations

import asyncio
import re
from urllib.parse import quote

from ...core.context import client as get_client
from ...core.models import Finding

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# site -> (profile URL template, list of soft-404 body markers, title not-found markers)
PLATFORMS: dict[str, tuple[str, list[str], list[str]]] = {
    "GitHub": (
        "https://github.com/{u}",
        ["this is not the web page you are looking for"],
        ["page not found"],
    ),
    "GitLab": (
        "https://gitlab.com/{u}",
        ["the page you're looking for could not be found"],
        ["page not found"],
    ),
    "Reddit": (
        "https://www.reddit.com/user/{u}/about.json",
        ["not found"],
        [],
    ),
    "HackerNews": ("https://news.ycombinator.com/user?id={u}", ["no such user"], []),
    "Keybase": ("https://keybase.io/{u}", ["sorry, no one here by that name"], []),
    "Steam": (
        "https://steamcommunity.com/id/{u}",
        ["the specified profile could not be found"],
        ["error"],
    ),
    "Twitch": (
        "https://www.twitch.tv/{u}",
        ["unless you've got a time machine, that's a dead end"],
        ["404"],
    ),
    "Pastebin": ("https://pastebin.com/u/{u}", ["not found"], []),
    "TryHackMe": ("https://tryhackme.com/p/{u}", ["page not found"], ["not found"]),
    "Spotify": (
        "https://open.spotify.com/user/{u}",
        ["page not found", "isn't available"],
        [],
    ),
    "SoundCloud": (
        "https://soundcloud.com/{u}",
        ["sorry we couldn't find the page", "something went wrong"],
        ["page not found"],
    ),
    "Telegram": (
        "https://t.me/{u}",
        [],
        [],
    ),
    "Medium": (
        "https://medium.com/@{u}",
        ["page not found"],
        ["page not found"],
    ),
    "Dev.to": (
        "https://dev.to/{u}",
        ["page not found", "nope. nothing here"],
        ["not found"],
    ),
    "Replit": (
        "https://replit.com/@{u}",
        ["this page isn't available", "not found"],
        ["not found"],
    ),
    "HuggingFace": (
        "https://huggingface.co/{u}",
        ["user not found", "404"],
        ["not found"],
    ),
    "npm": (
        "https://www.npmjs.com/~{u}",
        ["we looked everywhere but couldn't find"],
        ["not found"],
    ),
    "PyPI": (
        "https://pypi.org/user/{u}/",
        ["page not found"],
        ["page not found"],
    ),
    "DockerHub": (
        "https://hub.docker.com/u/{u}",
        ["404 not found"],
        ["not found"],
    ),
    "Bitbucket": (
        "https://bitbucket.org/{u}/",
        ["is not a valid bitbucket user", "not found"],
        [],
    ),
    "Chess.com": (
        "https://www.chess.com/member/{u}",
        ["does not exist"],
        ["page not found"],
    ),
    "Lichess": (
        "https://lichess.org/@/{u}",
        ["this player does not exist"],
        ["not found"],
    ),
    "Codewars": (
        "https://www.codewars.com/users/{u}",
        ["user not found"],
        ["user not found"],
    ),
    "LeetCode": (
        "https://leetcode.com/{u}/",
        ["page not found"],
        ["page not found"],
    ),
    "HackerRank": (
        "https://www.hackerrank.com/{u}",
        ["profile not found"],
        ["page not found"],
    ),
    "Exercism": (
        "https://exercism.org/profiles/{u}",
        ["profile not found", "could not find that page"],
        ["not found"],
    ),
    "Kitsu": ("https://kitsu.io/users/{u}", ["page not found"], ["not found"]),
    "MyAnimeList": (
        "https://myanimelist.net/profile/{u}",
        ["404 not found"],
        ["404"],
    ),
    "Gravatar": (
        "https://gravatar.com/{u}",
        ["this profile is not available"],
        [],
    ),
    "Pinterest": (
        "https://www.pinterest.com/{u}/",
        ["profile unavailable"],
        [],
    ),
    "Fiverr": (
        "https://www.fiverr.com/{u}",
        ["not found", "doesn't exist"],
        [],
    ),
    "Etsy": ("https://www.etsy.com/shop/{u}", ["page not found"], ["not found"]),
    "Behance": (
        "https://www.behance.net/{u}",
        ["page not found"],
        ["page not found"],
    ),
    "Dribbble": ("https://dribbble.com/{u}", ["page not found"], ["page not found"]),
    "Vimeo": ("https://vimeo.com/{u}", ["page not found"], ["not found"]),
    "YouTube": (
        "https://www.youtube.com/@{u}",
        ["does not exist", "wasn't found"],
        ["not found"],
    ),
    "Archive.org": (
        "https://archive.org/details/@{u}",
        ["not found"],
        [],
    ),
    "Patreon": (
        "https://www.patreon.com/{u}",
        ["page not found", "we couldn't find the page"],
        ["not found"],
    ),
    "Roblox": (
        "https://www.roblox.com/user.aspx?username={u}",
        ["page cannot be found", "user not found"],
        ["page not found"],
    ),
    "WordPress": (
        "https://{u}.wordpress.com",
        ["do not have a wordpress.com site"],
        ["not found"],
    ),
}

META = {
    "name": "socials",
    "target_type": "username",
    "description": "Checks username presence across 40+ platforms with confidence tiers",
    "requires_key": None,
}

# Titles that are generic placeholders (site shows them for ANY username).
# If a page title matches, treat as absent (the site cannot confirm existence).
TITLE_PLACEHOLDERS: dict[str, list[str]] = {
    "Telegram": ["telegram: contact @"],
}


def _extract_title(body: str) -> str:
    m = TITLE_RE.search(body or "")
    if m:
        return m.group(1).strip()
    return ""


async def run(target: str, config: dict) -> list[Finding]:
    c = get_client()
    findings: list[Finding] = []

    async def check(site: str, tmpl: str, body_markers: list[str], title_markers: list[str]) -> None:
        url = tmpl.format(u=quote(target))
        status, body = await c.fetch_raw(url)
        if status in (404, 410):
            return
        if status == 0 or status in (403, 429) or status >= 500:
            return
        if status != 200:
            return
        lowered = (body or "").lower()
        title = _extract_title(body).lower()

        # Generic placeholder titles (site shows them for any username) -> skip
        for pat in TITLE_PLACEHOLDERS.get(site, []):
            if pat in title:
                return

        # Soft-404 in body or title -> absent
        for m in body_markers:
            if m in lowered:
                return
        for m in title_markers:
            if m in title:
                return

        # Title contains the username -> strong signal of a real profile
        if title and target.lower() in title and len(title) < 120:
            findings.append(
                Finding(
                    source="socials",
                    category="profile",
                    value=f"{site}: {url}",
                    detail=f"verified (status 200, title match: {title[:60]})",
                    target_type="username",
                )
            )
        else:
            # Status 200 with no absent marker but no title match -> possible
            findings.append(
                Finding(
                    source="socials",
                    category="profile",
                    value=f"{site}: {url}",
                    detail="possible (status 200, no absent marker, JS-rendered?)",
                    target_type="username",
                )
            )

    await asyncio.gather(
        *(check(s, t, b, tt) for s, (t, b, tt) in PLATFORMS.items())
    )
    return findings