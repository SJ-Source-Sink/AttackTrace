"""Regression tests for the pre-release security hardening pass."""

import types

import pytest

from app.core import target_guard
from app.core.scan_args import reject_option_like, validate_nmap_flags


# ── nmap flag allowlist / option-injection ───────────────────────────────────

@pytest.mark.parametrize("flags", [
    "-iL /etc/passwd", "-oN /tmp/x", "-oX=/tmp/y", "-oG f", "--script /tmp/evil.nse",
    "--script=../../x", "--datadir /tmp", "--resume f", "--excludefile f", "-sV;id",
])
def test_nmap_flags_rejects_file_and_path_options(flags):
    with pytest.raises(ValueError):
        validate_nmap_flags(flags)


@pytest.mark.parametrize("flags", [
    "-sV -sC", "-sS -p 1-1000 -T4", "--script vuln", "--script=http-title,default",
    "-Pn -F --top-ports 100", "-PS22,80 -sT",
])
def test_nmap_flags_accepts_normal_scans(flags):
    assert validate_nmap_flags(flags)


def test_reject_option_like():
    with pytest.raises(ValueError):
        reject_option_like("-oN/tmp/x")
    assert reject_option_like(" example.com ") == "example.com"


def test_request_models_apply_the_guards():
    from app.api.v1.container_scanner import ContainerScanRequest
    from app.api.v1.nmap import NmapScanRequest

    with pytest.raises(ValueError):
        NmapScanRequest(target="8.8.8.8", scan_type="custom", custom_flags="-iL /etc/passwd")
    with pytest.raises(ValueError):
        NmapScanRequest(target="-oN/tmp/x")
    with pytest.raises(ValueError):
        ContainerScanRequest(scan_type="image", image="--privileged")
    assert NmapScanRequest(target="8.8.8.8", scan_type="custom", custom_flags="-sV").target == "8.8.8.8"


# ── scan-target policy ───────────────────────────────────────────────────────

def _settings(allow_private: bool):
    return lambda: types.SimpleNamespace(ALLOW_PRIVATE_SCAN_TARGETS=allow_private)


@pytest.mark.parametrize("target", [
    "127.0.0.1", "localhost", "http://localhost:8000/x", "169.254.169.254",
    "http://169.254.169.254/latest/meta-data", "10.0.0.5", "192.168.1.1:8080", "172.16.0.1",
    "[::1]", "http://[::1]:5432", "100.64.0.1", "10.0.0.0/24", "::ffff:127.0.0.1", "0.0.0.0",
    "8.8.8.8 10.1.1.1", "https://user@127.0.0.1/",
])
def test_target_guard_blocks_internal_by_default(monkeypatch, target):
    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    assert target_guard.scan_target_problem(target)


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1:443", "93.184.216.0/24", "https://8.8.8.8/x"])
def test_target_guard_allows_public(monkeypatch, target):
    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    assert target_guard.scan_target_problem(target) is None


def test_target_guard_fails_closed_on_unresolvable_unless_opted_in(monkeypatch):
    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    name = "no-such-host-zzqq-12345.invalid"
    assert target_guard.scan_target_problem(name)  # default: refuse
    assert target_guard.scan_target_problem(name, allow_unresolvable=True) is None  # takeover etc.


@pytest.mark.parametrize("target", [
    "user@127.0.0.1", "git@127.0.0.1:x/y", "ssh://git@10.0.0.1/r.git", "http://x\\@127.0.0.1",
    "127.0.0.1#@example.com", "2130706433", "0x7f.0.0.1", "127.1", "user:pw@localhost:8080/p",
    "http://a@b@127.0.0.1", "//127.0.0.1", "[::1",
    "8.8.8.8%@127.0.0.1", "8.8.8.8%25@127.0.0.1", "http://8.8.8.8%@127.0.0.1/",  # '%' must not truncate
])
def test_target_guard_parses_like_the_client(monkeypatch, target):
    # parser-differential bypasses: userinfo/scp-style/obfuscated forms must not look "unresolvable"
    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    assert target_guard.scan_target_problem(target)


def test_secrets_guard_is_deny_by_default(monkeypatch):
    from app.api.v1.secrets import SecretScanRequest

    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    for scan_type in ("url", "git_repo", "github_repo", "anything-else"):
        with pytest.raises(ValueError):
            SecretScanRequest(target="http://127.0.0.1", scan_type=scan_type)
    # github org/user scans take a name, not a host
    assert SecretScanRequest(target="some-org", scan_type="github_org").target == "some-org"


def test_takeover_opts_in_to_unresolvable_but_ffuf_does_not(monkeypatch):
    from app.api.v1.ffuf import FfufScanRequest
    from app.api.v1.takeover import TakeoverRequest

    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    assert TakeoverRequest(targets=["dangling.no-such-host-zzqq-12345.invalid"])
    # FUZZ.<domain> can't be vetted before substitution (the domain's DNS could answer 127.0.0.1)
    with pytest.raises(ValueError):
        FfufScanRequest(url="http://FUZZ.no-such-host-zzqq-12345.invalid/")
    with pytest.raises(ValueError):
        FfufScanRequest(url="http://no-such-host-zzqq-12345.invalid/FUZZ")


def test_ffuf_wordlists_confined_to_known_directories():
    import pathlib

    from app.api.v1 import ffuf

    roots = ffuf._wordlist_roots()
    allowed = lambda p: any(pathlib.Path(p).resolve().is_relative_to(r) for r in roots)  # noqa: E731
    assert allowed(ffuf._BUNDLED_DIR / "subdomains.txt")
    assert not allowed("/etc/passwd")
    assert not allowed(pathlib.Path.home() / ".attacktrace" / "scans" / "x.json")
    assert not allowed(ffuf._BUNDLED_DIR / ".." / ".env")  # traversal out of the wordlists dir


def test_target_guard_opt_in_allows_private_but_never_metadata(monkeypatch):
    monkeypatch.setattr(target_guard, "get_settings", _settings(True))
    assert target_guard.scan_target_problem("10.0.0.5") is None
    assert target_guard.scan_target_problem("127.0.0.1") is None
    assert target_guard.scan_target_problem("169.254.169.254")  # link-local: always blocked


def test_guard_validator_raises_value_error(monkeypatch):
    monkeypatch.setattr(target_guard, "get_settings", _settings(False))
    with pytest.raises(ValueError):
        target_guard.guard_scan_target("http://127.0.0.1:5432")
    with pytest.raises(ValueError):
        target_guard.guard_scan_target(["8.8.8.8", "10.0.0.1"])
    assert target_guard.guard_scan_target(None) is None


# ── CORS_ORIGINS parsing (bare string used to crash startup) ─────────────────

@pytest.mark.parametrize("raw,expected", [
    ("http://localhost:3000", ["http://localhost:3000"]),
    ("http://a.example,http://b.example", ["http://a.example", "http://b.example"]),
    ('["http://x.example"]', ["http://x.example"]),
])
def test_cors_origins_env_forms(monkeypatch, raw, expected):
    from app.core.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", raw)
    assert Settings().CORS_ORIGINS == expected


# ── screenshot mount only serves screenshot images ───────────────────────────

def test_static_mount_serves_only_screenshot_images(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.main import _ScreenshotFiles

    org = tmp_path / "org1"
    (org / "scan1" / "screenshots").mkdir(parents=True)
    (org / "scan1" / "screenshots" / "a.png").write_bytes(b"\x89PNG\r\n")
    (org / "scan1" / "history.json").write_text('{"secret": 1}')
    (org / "other.png").write_bytes(b"\x89PNG\r\n")
    (tmp_path / "top-secret.json").write_text("{}")

    app = FastAPI()
    app.mount("/s", _ScreenshotFiles(directory=str(tmp_path)))
    c = TestClient(app)
    assert c.get("/s/org1/scan1/screenshots/a.png").status_code == 200
    assert c.get("/s/org1/scan1/history.json").status_code == 404
    assert c.get("/s/org1/other.png").status_code == 404  # image, but not under screenshots/
    assert c.get("/s/top-secret.json").status_code == 404
    assert c.get("/s/org1/scan1/screenshots/../history.json").status_code == 404


# ── SSE stream token ─────────────────────────────────────────────────────────

def test_stream_token_is_scoped_and_not_an_access_token():
    from app.core.security import create_stream_token, decode_token

    claims = decode_token(create_stream_token("u1", "o1", "s1"))
    assert claims["type"] == "sse" and claims["scan_id"] == "s1" and claims["org_id"] == "o1"
    assert claims["exp"] - claims["iat"] <= 60


# ── client IP behind a proxy (X-Forwarded-For is client-spoofable) ───────────

@pytest.mark.parametrize("trust,hops,xff,expected", [
    (False, 1, "6.6.6.6", "10.0.0.9"),                    # header ignored unless opted in
    (True, 1, "6.6.6.6, 203.0.113.7", "203.0.113.7"),     # spoofed leftmost entry ignored
    (True, 2, "6.6.6.6, 203.0.113.7, 10.1.1.1", "203.0.113.7"),
    (True, 1, "", "10.0.0.9"),                            # no header -> socket peer
    (True, 3, "203.0.113.7", "10.0.0.9"),                 # fewer entries than hops -> don't guess
])
def test_client_ip_uses_trusted_proxy_entry(monkeypatch, trust, hops, xff, expected):
    from app.api.v1 import auth

    monkeypatch.setattr(auth.settings, "TRUST_PROXY_HEADERS", trust)
    monkeypatch.setattr(auth.settings, "TRUSTED_PROXY_HOPS", hops)
    req = types.SimpleNamespace(headers={"x-forwarded-for": xff}, client=types.SimpleNamespace(host="10.0.0.9"))
    assert auth._client_ip(req) == expected


@pytest.mark.parametrize("url", [
    "http://FUZZ.example.com/", "https://fuzz.example.com/x", "http://FUZZ@example.com/",
    "http://example.com:FUZZ/", "FUZZ.example.com", "http://admin.FUZZ.example.com/",
])
def test_ffuf_rejects_fuzz_in_authority_even_if_host_looks_public(monkeypatch, url):
    from app.api.v1.ffuf import FfufScanRequest

    # Pretend every host passes the resolve/address check: the FUZZ rule must hold on its own.
    monkeypatch.setattr(target_guard, "scan_target_problem", lambda raw, allow_unresolvable=False: None)
    with pytest.raises(ValueError):
        FfufScanRequest(url=url)


def test_ffuf_allows_fuzz_in_path_and_query(monkeypatch):
    from app.api.v1.ffuf import FfufScanRequest

    monkeypatch.setattr(target_guard, "scan_target_problem", lambda raw, allow_unresolvable=False: None)
    assert FfufScanRequest(url="https://example.com/FUZZ")
    assert FfufScanRequest(url="https://example.com/a?x=FUZZ")
