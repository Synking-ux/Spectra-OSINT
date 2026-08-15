import time

from osint.core.cache import Cache


def test_cache_roundtrip(tmp_path):
    c = Cache(tmp_path / "c.db", ttl=100, enabled=True)
    c.set("ns", "http://x", {"q": "1"}, {"a": [1, 2]})
    assert c.get("ns", "http://x", {"q": "1"}) == {"a": [1, 2]}
    c.close()


def test_cache_key_distinguishes_params(tmp_path):
    c = Cache(tmp_path / "c.db", ttl=100, enabled=True)
    c.set("ns", "http://x", {"q": "1"}, "one")
    assert c.get("ns", "http://x", {"q": "2"}) is None
    c.close()


def test_cache_ttl_expiry(tmp_path):
    c = Cache(tmp_path / "c.db", ttl=-1, enabled=True)
    c.set("ns", "http://x", None, "data")
    assert c.get("ns", "http://x") is None
    c.close()


def test_cache_disabled(tmp_path):
    c = Cache(tmp_path / "c.db", enabled=False)
    c.set("ns", "http://x", None, "data")
    assert c.get("ns", "http://x") is None