"""Tests de la consommation d'API tierces non sûre (API10)."""
from modules.unsafe_consumption import analyze_consumption, registrable_domain


def _har(items):
    entries = []
    for it in items:
        e = {"request": {"method": it.get("m", "GET"), "url": it["u"]}}
        if "status" in it:
            e["response"] = {"status": it["status"],
                             "headers": [{"name": "Location", "value": it.get("loc", "")}]}
        entries.append(e)
    return {"log": {"entries": entries}}


TARGET = "https://api.acme.com"


def test_registrable_domain():
    assert registrable_domain("api.acme.com") == "acme.com"
    assert registrable_domain("pay.stripe.com:443") == "stripe.com"


def test_first_party_ignored():
    har = _har([{"u": "https://api.acme.com/v1/users/1"}, {"u": "https://www.acme.com/x"}])
    assert analyze_consumption(har, TARGET) == []


def test_cleartext_third_party_high():
    har = _har([{"u": "http://data.thirdparty.io/feed"}])
    fs = analyze_consumption(har, TARGET)
    assert any(f.kind == "cleartext" and f.severity == "High" for f in fs)


def test_sensitive_dependency_medium():
    har = _har([{"u": "https://pay.stripe.com/charge"}])
    fs = analyze_consumption(har, TARGET)
    dep = [f for f in fs if f.kind == "dependency"][0]
    assert dep.severity == "Medium" and "stripe.com" in dep.title


def test_plain_dependency_low():
    har = _har([{"u": "https://cdn.images.io/logo.png"}])
    dep = [f for f in analyze_consumption(har, TARGET) if f.kind == "dependency"][0]
    assert dep.severity == "Low"


def test_redirect_to_third_party():
    har = _har([{"u": "https://api.acme.com/go", "status": 302, "loc": "https://evil.tracker.io/x"}])
    fs = analyze_consumption(har, TARGET)
    assert any(f.kind == "redirect" for f in fs)


def test_dependency_dedup():
    har = _har([{"u": "https://x.thirdparty.io/a"}, {"u": "https://y.thirdparty.io/b"}])
    deps = [f for f in analyze_consumption(har, TARGET) if f.kind == "dependency"]
    assert len(deps) == 1  # une seule par domaine enregistrable
