from osint.core.models import Finding


def test_finding_to_dict():
    f = Finding(source="s", category="c", value="v", detail="d", target_type="domain")
    d = f.to_dict()
    assert d["source"] == "s"
    assert d["category"] == "c"
    assert d["value"] == "v"
    assert d["detail"] == "d"
    assert d["target_type"] == "domain"


def test_finding_defaults():
    f = Finding(source="s", category="c", value="v")
    assert f.detail == ""
    assert f.target_type == ""
    assert f.raw == {}