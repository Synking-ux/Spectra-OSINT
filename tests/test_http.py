import asyncio

from osint.core.cache import Cache
from osint.core.http import HttpClient, RateLimiter


async def _rate_limiter_spacing():
    limiter = RateLimiter(min_interval=0.05, max_concurrent=2)
    start = asyncio.get_event_loop().time()
    async with limiter:
        pass
    async with limiter:
        pass
    elapsed = asyncio.get_event_loop().time() - start
    return elapsed


def test_rate_limiter_min_interval():
    elapsed = asyncio.run(_rate_limiter_spacing())
    assert elapsed >= 0.04  # two acquisitions spaced by the 0.05s min interval


async def _run(tmp_path):
    cache = Cache(tmp_path / "c.db", enabled=True)
    client = HttpClient(cache=cache, retries=0, timeout=1.0)
    try:
        res = await client.fetch("ns", "http://127.0.0.1:1/nope")
        assert res is None
    finally:
        await client.close()


def test_client_with_cache_handles_failure(tmp_path):
    asyncio.run(_run(tmp_path))