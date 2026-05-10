"""Payload library — encoding service + API endpoints."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("PAYLOAD_DIR", str(REPO / "packages/payloads"))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./reconforge-payload-test.db")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", "./artifacts")
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("RUNNER_MODE", "in_process")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD", "admin-passw0rd")
    monkeypatch.setenv("RECONFORGE_TEST_AUTH_BYPASS", "1")
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.services import payloads as payloads_svc
    payloads_svc.reset_cache()
    yield
    get_settings.cache_clear()
    payloads_svc.reset_cache()


# ---------- service unit tests --------------------------------------------


def test_index_finds_all_categories():
    from app.services import payloads as p
    cats = p.categories()
    # The on-disk roster, kept in sync with packages/payloads/.
    assert {"xss", "sqli", "ssrf", "lfi", "ssti", "xxe",
            "nosqli", "redirect", "crlf", "command-injection"} <= set(cats)
    assert all(v >= 1 for v in cats.values())


def test_get_payload_drops_comments_and_blanks():
    from app.services import payloads as p
    meta, body, lines = p.get_payload("xss", "basic")
    assert meta.payload_count == len(lines)
    assert lines, "xss/basic should not be empty"
    assert all(not s.lstrip().startswith("#") and s.strip() for s in lines)
    # The whole-file body still includes the comment header
    assert "#" in body


def test_get_payload_rejects_traversal():
    from app.services import payloads as p
    with pytest.raises(KeyError):
        p.get_payload("xss/..", "basic")
    with pytest.raises(KeyError):
        p.get_payload("../etc", "passwd")
    with pytest.raises(KeyError):
        p.get_payload("xss", "..")
    with pytest.raises(KeyError):
        p.get_payload("xss", "doesnotexist")


def test_encoding_round_trip_for_known_payload():
    from app.services import payloads as p
    src = "<script>alert(1)</script>"
    assert p.encode_line(src, "raw")     == src
    assert p.encode_line(src, "url")     == "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    assert p.encode_line(src, "url2")    == "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"
    assert p.encode_line(src, "base64")  == "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    assert p.encode_line(src, "hex")     == "3c7363726970743e616c6572742831293c2f7363726970743e"
    assert p.encode_line(src, "html")    == "&lt;script&gt;alert(1)&lt;/script&gt;"
    out = p.encode_line(src, "unicode")
    # First char `<` is U+003C — must show up as < (or \U... for >0xFFFF)
    assert out.startswith("\\u003c")
    assert out.count("\\u") == len(src)


def test_unicode_encoding_handles_supplementary_plane():
    from app.services import payloads as p
    # 🌐 is U+1F310, outside the BMP — should use the \U form
    assert p.encode_line("🌐", "unicode") == "\\U0001f310"


def test_encode_lines_rejects_unknown_encoding():
    from app.services import payloads as p
    with pytest.raises(ValueError):
        p.encode_lines(["x"], "rot13")


# ---------- API tests -------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'pl.db'}")
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()

    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"X-Test-User": "admin"}
    with TestClient(app) as c:
        yield c, headers
    from app.core.config import get_settings
    get_settings.cache_clear()


def test_api_index_lists_categories(client):
    c, headers = client
    r = c.get("/api/payloads", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["categories"]) >= {"xss", "sqli", "ssrf"}
    assert body["files"]
    assert body["encodings"] == ["raw", "url", "url2", "base64", "hex", "html", "unicode"]
    sample = next(f for f in body["files"] if f["category"] == "xss" and f["name"] == "basic")
    assert sample["payload_count"] >= 5


def test_api_get_payload_default_raw(client):
    c, headers = client
    r = c.get("/api/payloads/xss/basic", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["encoding"] == "raw"
    assert "<script>alert(1)</script>" in body["payloads"]


def test_api_get_payload_with_encodings(client):
    c, headers = client
    for enc, expected in [
        ("url",  "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
        ("base64", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
        ("html", "&lt;script&gt;alert(1)&lt;/script&gt;"),
    ]:
        r = c.get(f"/api/payloads/xss/basic?encoding={enc}", headers=headers)
        assert r.status_code == 200, f"{enc}: {r.text}"
        assert expected in r.json()["payloads"], f"{enc!r} missing expected encoding"


def test_api_get_payload_invalid_encoding(client):
    c, headers = client
    r = c.get("/api/payloads/xss/basic?encoding=rot13", headers=headers)
    assert r.status_code == 400


def test_api_unknown_payload_404(client):
    c, headers = client
    assert c.get("/api/payloads/xss/nope", headers=headers).status_code == 404


def test_api_blocks_traversal(client):
    c, headers = client
    # FastAPI should normalise "../" out before it reaches the route, but
    # belt-and-braces — service rejects too.
    r = c.get("/api/payloads/xss/..%2Fsqli", headers=headers)
    assert r.status_code in {400, 404}


def test_api_anonymous_blocked(client):
    c, _ = client
    assert c.get("/api/payloads").status_code == 401
    assert c.get("/api/payloads/xss/basic").status_code == 401


def test_api_raw_download(client):
    c, headers = client
    r = c.get("/api/payloads/xss/basic/raw?encoding=url", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "attachment" in r.headers["content-disposition"]
    assert int(r.headers["x-payload-count"]) >= 5
    assert r.headers["x-payload-encoding"] == "url"
    # Body is one URL-encoded payload per line
    lines = [ln for ln in r.text.splitlines() if ln]
    assert "%3Cscript%3Ealert%281%29%3C%2Fscript%3E" in lines
