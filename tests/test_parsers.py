from osint.modules.domain.crt import parse_names
from osint.modules.domain.hackertarget import parse_hostsearch
from osint.modules.domain.subdomain_brute import load_wordlist
from osint.modules.email.hibp import parse_breaches
from osint.modules.email.emailrep import parse_emailrep
from osint.modules.domain.otx import parse_otx
from osint.cli import guess_type


def test_crt_parse():
    data = [
        {"name_value": "www.example.com\napi.example.com", "common_name": "*.example.com"},
        {"name_value": "other.org", "common_name": "other.org"},
    ]
    names = parse_names(data)
    assert "www.example.com" in names
    assert "api.example.com" in names
    assert "example.com" in names
    assert "other.org" in names


def test_crt_parse_strips_wildcard():
    data = [{"name_value": "*.foo.example.com", "common_name": ""}]
    assert "foo.example.com" in parse_names(data)


def test_hostsearch_parse():
    text = "www.example.com,1.2.3.4\nmail.example.com,5.6.7.8\ngarbage\n"
    rows = parse_hostsearch(text)
    assert ("www.example.com", "1.2.3.4") in rows
    assert ("mail.example.com", "5.6.7.8") in rows


def test_hostsearch_parse_empty():
    assert parse_hostsearch("") == []
    assert parse_hostsearch(None) == []


def test_hibp_parse():
    data = [
        {"Name": "Acme", "BreachDate": "2020-01-01", "Domain": "acme.com",
         "DataClasses": ["Email", "Password"]}
    ]
    rows = parse_breaches(data)
    assert rows[0]["name"] == "Acme"
    assert rows[0]["classes"] == "Email, Password"


def test_emailrep_parse():
    data = {
        "status": "ok",
        "reputation": "high",
        "suspicious": False,
        "references": 42,
        "details": {"breached": True, "malicious_activity": "none"},
    }
    rows = parse_emailrep(data)
    cats = {c for c, _ in rows}
    assert "reputation" in cats
    assert "suspicious" in cats
    assert "breached" in cats


def test_otx_parse():
    data = {"passive_dns": [{"hostname": "sub.example.com", "address": "1.2.3.4"}]}
    assert parse_otx(data) == [("sub.example.com", "1.2.3.4")]


def test_load_wordlist_default():
    words = load_wordlist(None)
    assert "www" in words and "api" in words


def test_load_wordlist_file(tmp_path):
    f = tmp_path / "wl.txt"
    f.write_text("alpha\n# comment\n\nbeta\n")
    words = load_wordlist(str(f))
    assert "alpha" in words and "beta" in words and "comment" not in words


def test_guess_type_email():
    assert guess_type("alice@example.com") == "email"


def test_guess_type_ip():
    assert guess_type("8.8.8.8") == "ip"


def test_guess_type_domain():
    assert guess_type("example.com") == "domain"


def test_guess_type_username():
    assert guess_type("alice_the_cat") == "username"