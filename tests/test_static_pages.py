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

