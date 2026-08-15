from osint.core.registry import all_modules, discover


def test_discover_all_types():
    reg = discover()
    assert set(reg.keys()) == {"email", "username", "domain", "ip"}
    assert len(reg["username"]) >= 1
    assert len(reg["domain"]) >= 5
    assert len(reg["email"]) >= 3
    assert len(reg["ip"]) >= 3


def test_expected_modules_present():
    names = {m.name for m in all_modules()}
    assert {"socials", "dns", "crt", "whois", "fingerprint", "hibp", "emailrep", "ipapi", "rdap"} <= names


def test_module_metadata():
    for m in all_modules():
        assert m.name
        assert m.target_type in ("email", "username", "domain", "ip")
        assert callable(m.run)