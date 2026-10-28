"""Integration tests ensuring all static dashboard pages and assets are served properly."""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_index_page_served_at_root():
    """Verify GET / returns 200 and serves index.html."""
    res = client.get("/")
    assert res.status_code == 200
    assert "<!DOCTYPE html>" in res.text
    assert "IntentLock" in res.text


def test_index_html_direct_served():
    """Verify GET /index.html returns 200 and contains dashboard elements."""
    res = client.get("/index.html")
    assert res.status_code == 200
    assert "IntentLock" in res.text
    assert "/css/styles.css" in res.text
    assert "/js/api.js" in res.text


def test_demo_page_served():
    """Verify GET /demo.html returns 200 and contains attack simulator elements."""
    res = client.get("/demo.html")
    assert res.status_code == 200
    assert "<!DOCTYPE html>" in res.text
    assert "IntentLock" in res.text


def test_store_page_served():
    """Verify GET /store.html returns 200 and contains mock store elements."""
    res = client.get("/store.html")
    assert res.status_code == 200
    assert "<!DOCTYPE html>" in res.text
    assert "IntentLock" in res.text


def test_static_css_served():
    """Verify GET /css/styles.css returns 200 with CSS content type."""
    res = client.get("/css/styles.css")
    assert res.status_code == 200
    assert "text/css" in res.headers.get("content-type", "")
    assert ":root" in res.text or "body" in res.text


def test_static_js_served():
    """Verify GET /js/api.js returns 200 with JavaScript content type."""
    res = client.get("/js/api.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "")
    assert "textContent" in res.text


def test_static_demo_js_served():
    """Verify GET /js/demo.js returns 200 with JavaScript content type and contains Phase 9 elements."""
    res = client.get("/js/demo.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "")
    assert "runAttack" in res.text
    assert "REASON_EXPLANATIONS" in res.text


def test_static_store_js_served():
    """Verify GET /js/store.js returns 200 with JavaScript content type."""
    res = client.get("/js/store.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "")


def test_dashboard_page_served_and_no_inner_html():
    """Verify GET /dashboard.html exists, is served with 200, and contains no innerHTML."""
    res = client.get("/dashboard.html")
    assert res.status_code == 200
    assert "<!DOCTYPE html>" in res.text
    assert "Approval" in res.text
    assert "innerHTML" not in res.text


def test_dashboard_js_served_and_no_inner_html():
    """Verify GET /js/dashboard.js exists, is served with JS content-type, and contains no innerHTML."""
    res = client.get("/js/dashboard.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "")
    assert "innerHTML" not in res.text
    assert "textContent" in res.text
    assert "fetchPendingIntents" in res.text
    assert "Copy token" in res.text
    assert "expires" in res.text


def test_dashboard_js_has_copy_token_and_expires():
    """Verify that the strings 'Copy token' and 'expires' appear in the dashboard JS and index page."""
    res_js = client.get("/js/dashboard.js")
    assert res_js.status_code == 200
    assert "Copy token" in res_js.text
    assert "expires" in res_js.text

    res_index = client.get("/index.html")
    assert res_index.status_code == 200
    assert "Copy token" in res_index.text
    assert "expires" in res_index.text



def test_audit_page_served_and_no_inner_html():
    """Verify GET /audit.html exists, is served with 200, and contains no innerHTML."""
    res = client.get("/audit.html")
    assert res.status_code == 200
    assert "<!DOCTYPE html>" in res.text
    assert "Audit" in res.text
    assert "innerHTML" not in res.text


def test_audit_js_served_and_no_inner_html():
    """Verify GET /js/audit.js exists, is served with JS content-type, and contains no innerHTML."""
    res = client.get("/js/audit.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "")
    assert "innerHTML" not in res.text
    assert "textContent" in res.text
    assert "fetchAuditLogs" in res.text


def test_index_html_links_to_dashboard_and_audit():
    """Verify GET /index.html links to both dashboard.html and audit.html."""
    res = client.get("/index.html")
    assert res.status_code == 200
    assert "/dashboard.html" in res.text
    assert "/audit.html" in res.text


def test_api_audit_endpoint_returns_list():
    """Verify GET /api/audit returns 200 with list of audit entries."""
    res = client.get("/api/audit")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

