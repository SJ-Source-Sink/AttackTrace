"""Regression tests for bugs found via the end-to-end audit."""
import inspect

from app.api.v1 import attack_suite, js_scanner
from app.api.v1.nuclei import _CATEGORY_TAGS, NucleiScanRequest, _build_nuclei_cmd


def test_nuclei_categories_map_to_real_template_tags():
    # UI category names are not nuclei tag names; passing them straight to -tags
    # matched ~0 templates and the scan failed with "no templates provided".
    cmd = _build_nuclei_cmd(NucleiScanRequest(target="example.com", categories=["technologies", "cves"]), None)
    tags = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-tags"]
    assert tags == ["tech", "cve"]
    assert all(c in _CATEGORY_TAGS for c in ("cves", "exposures", "technologies", "default-logins", "takeovers"))


def test_burp_verify_request_is_injected_not_a_query_param():
    # `Request` was never imported, so FastAPI treated `request` as a required
    # query param and the endpoint always returned 422.
    route = next(r for r in attack_suite.router.routes if getattr(r, "path", "").endswith("/burp/verify"))
    assert "request" not in {p.name for p in route.dependant.query_params}


def test_js_scanner_counts_confirmed_xss_without_crashing():
    # confirmed_xss_count was missing from the nested counter's `nonlocal` list,
    # raising UnboundLocalError mid-scan on any confirmed XSS.
    src = inspect.getsource(js_scanner._run_js_scan)
    start = src.index("def _count_finding")
    assert "nonlocal confirmed_xss_count" in src[start:src.index('yield _sse("start"', start)]
