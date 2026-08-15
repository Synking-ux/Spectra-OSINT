from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

import httpx

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


class RateLimiter:
    """Min-interval spacing + max-concurrency semaphore shared across requests."""

    def __init__(self, min_interval: float = 0.0, max_concurrent: int = 10):
        self.min_interval = min_interval
        self.sem = asyncio.Semaphore(max_concurrent)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        await self.sem.acquire()
        if self.min_interval > 0:
            async with self._lock:
                now = time.monotonic()
                wait = self.min_interval - (now - self._last)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last = time.monotonic()
        return self

    async def __aexit__(self, *exc) -> None:
        self.sem.release()


class HttpClient:
    """Async HTTP client with retries/backoff, per-host rate limiting and caching."""

    def __init__(
        self,
        *,
        proxy: Optional[str] = None,
        timeout: float = 15.0,
        user_agent: Optional[str] = None,
        cache=None,
        retries: int = 2,
        rate: float = 0.0,
        concurrent: int = 10,
        verify: bool = True,
    ):
        self.cache = cache
        self.retries = retries
        self.limiter = RateLimiter(rate, concurrent)
        transport = None
        if proxy:
            transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=verify)
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            transport=transport,
            headers={"User-Agent": user_agent or DEFAULT_UA},
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def fetch(
        self,
        namespace: str,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        cached: bool = True,
        as_text: bool = False,
        limiter: Optional[RateLimiter] = None,
    ) -> Any:
        """GET and return parsed JSON (or text). Returns None on failure."""
        if cached and self.cache:
            hit = self.cache.get(namespace, url, params)
            if hit is not None:
                return hit
        limiter = limiter or self.limiter
        result = None
        for attempt in range(self.retries + 1):
            try:
                async with limiter:
                    resp = await self.client.get(url, params=params, headers=headers)
                if resp.status_code == 429:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                if resp.status_code in (200, 201):
                    if as_text:
                        result = resp.text
                    else:
                        try:
                            result = resp.json()
                        except ValueError:
                            result = resp.text
                    break
                if resp.status_code in (401, 403, 404, 410):
                    break
            except (httpx.HTTPError, asyncio.TimeoutError):
                if attempt == self.retries:
                    break
                await asyncio.sleep(1 * (attempt + 1))
        if result is not None and cached and self.cache:
            self.cache.set(namespace, url, params, result)
        return result

    async def fetch_raw(
        self, url: str, *, headers: dict | None = None, limiter: Optional[RateLimiter] = None
    ) -> tuple[int, str]:
        """GET returning (status_code, body) without caching. For presence checks."""
        limiter = limiter or self.limiter
        for attempt in range(self.retries + 1):
            try:
                async with limiter:
                    resp = await self.client.get(url, headers=headers)
                if resp.status_code == 429:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                return resp.status_code, resp.text
            except (httpx.HTTPError, asyncio.TimeoutError):
                if attempt == self.retries:
                    return 0, ""
                await asyncio.sleep(1 * (attempt + 1))
        return 0, ""

    async def fetch_response(
        self, url: str, *, headers: dict | None = None, limiter: Optional[RateLimiter] = None
    ) -> httpx.Response | None:
        limiter = limiter or self.limiter
        for attempt in range(self.retries + 1):
            try:
                async with limiter:
                    resp = await self.client.get(url, headers=headers)
                if resp.status_code == 429:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                return resp
            except (httpx.HTTPError, asyncio.TimeoutError):
                if attempt == self.retries:
                    return None
                await asyncio.sleep(1 * (attempt + 1))
        return None