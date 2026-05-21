"""
Test Suite for CyberTriage API
Tests: triage engine, auth flow, alert CRUD, dashboard stats
"""
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from app.core.database import init_db


@pytest.fixture
async def client():
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def auth_token(client):
    import random, string
    uname = "analyst_" + "".join(random.choices(string.ascii_lowercase, k=6))
    await client.post("/api/auth/register", json={
        "username": uname, "email": f"{uname}@test.com", "password": "testpass123"
    })
    resp = await client.post("/api/auth/login", data={
        "username": uname, "password": "testpass123"
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


# ── Triage Engine Unit Tests ─────────────────────────────────────────────────

class TestTriageEngine:
    def test_brute_force_scores_high(self):
        from app.services.triage_engine import triage
        r = triage("brute_force", "47 failed SSH login attempts for root")
        assert r.severity in ("critical", "high")
        assert r.risk_score >= 70
        assert "T1110" in r.mitre_technique

    def test_ransomware_is_critical(self):
        from app.services.triage_engine import triage
        r = triage("ransomware", "Files encrypted ransom bitcoin demand")
        assert r.severity == "critical"
        assert r.risk_score >= 90

    def test_port_scan_is_low_or_medium(self):
        from app.services.triage_engine import triage
        r = triage("port_scan", "SYN scan detected from external host")
        assert r.severity in ("low", "medium")

    def test_unknown_event_has_fallback(self):
        from app.services.triage_engine import triage
        r = triage("unknown_event_xyz", "some log")
        assert r.mitre_technique is not None
        assert r.severity in ("critical", "high", "medium", "low")

    def test_ip_abuse_score_boosts_risk(self):
        from app.services.triage_engine import triage
        base = triage("port_scan", "scan detected", ip_abuse_score=0)
        boosted = triage("port_scan", "scan detected", ip_abuse_score=100)
        assert boosted.risk_score > base.risk_score

    def test_keyword_boost_works(self):
        from app.services.triage_engine import triage
        base = triage("brute_force", "login failed")
        boosted = triage("brute_force", "powershell bypass root admin credentials")
        assert boosted.risk_score >= base.risk_score

    def test_risk_score_capped_at_100(self):
        from app.services.triage_engine import triage
        r = triage("ransomware", "powershell bypass root credentials encrypted ransom bitcoin", ip_abuse_score=100)
        assert r.risk_score <= 100

    def test_response_recommendation_present(self):
        from app.services.triage_engine import triage
        r = triage("lateral_movement", "remote service exploitation")
        assert len(r.recommended_action) > 10


# ── API Integration Tests ────────────────────────────────────────────────────

class TestAuth:
    async def test_register_new_user(self, client):
        resp = await client.post("/api/auth/register", json={
            "username": "newuser_fresh123", "email": "fresh123@test.com", "password": "pass123"
        })
        assert resp.status_code == 201
        assert resp.json()["username"] == "newuser_fresh123"

    async def test_duplicate_register_fails(self, client):
        await client.post("/api/auth/register", json={
            "username": "dup_user_unique77", "email": "dup77@test.com", "password": "pass"
        })
        # same username, different email → should fail
        resp = await client.post("/api/auth/register", json={
            "username": "dup_user_unique77", "email": "different77@test.com", "password": "pass"
        })
        assert resp.status_code == 400

    async def test_login_returns_token(self, client):
        await client.post("/api/auth/register", json={
            "username": "login_test", "email": "login@test.com", "password": "mypassword"
        })
        resp = await client.post("/api/auth/login", data={
            "username": "login_test", "password": "mypassword"
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_wrong_password_fails(self, client):
        resp = await client.post("/api/auth/login", data={
            "username": "newuser_fresh123", "password": "wrongpass"
        })
        assert resp.status_code == 401

    async def test_protected_route_requires_token(self, client):
        resp = await client.get("/api/alerts/")
        assert resp.status_code == 401


class TestAlerts:
    async def test_triage_alert_success(self, client, auth_headers):
        resp = await client.post("/api/alerts/triage", json={
            "source_ip": "185.220.101.45",
            "event_type": "brute_force",
            "log_message": "47 failed SSH login attempts for root",
            "tool": "splunk"
        }, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["severity"] in ("critical", "high", "medium", "low")
        assert 0 <= data["risk_score"] <= 100
        assert "T1110" in data["mitre_technique"]

    async def test_triage_known_malicious_ip(self, client, auth_headers):
        resp = await client.post("/api/alerts/triage", json={
            "source_ip": "185.220.101.45",
            "event_type": "port_scan",
            "log_message": "Scan from known Tor exit node",
            "tool": "crowdstrike"
        }, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.json()["ip_abuse_score"] == 95.0

    async def test_list_alerts(self, client, auth_headers):
        resp = await client.get("/api/alerts/", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_filter_by_severity_returns_correct_type(self, client, auth_headers):
        # Submit a low-severity alert first
        await client.post("/api/alerts/triage", json={
            "source_ip": "10.0.0.1", "event_type": "port_scan",
            "log_message": "routine scan", "tool": "splunk"
        }, headers=auth_headers)
        resp = await client.get("/api/alerts/?severity=low", headers=auth_headers)
        assert resp.status_code == 200
        for a in resp.json():
            assert a["severity"] == "low"

    async def test_get_alert_by_id(self, client, auth_headers):
        create = await client.post("/api/alerts/triage", json={
            "source_ip": "10.0.0.1", "event_type": "malware",
            "log_message": "Malware signature detected", "tool": "elk"
        }, headers=auth_headers)
        alert_id = create.json()["id"]
        resp = await client.get(f"/api/alerts/{alert_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == alert_id

    async def test_update_alert_status(self, client, auth_headers):
        create = await client.post("/api/alerts/triage", json={
            "source_ip": "8.8.8.8", "event_type": "port_scan",
            "log_message": "Routine scan", "tool": "splunk"
        }, headers=auth_headers)
        alert_id = create.json()["id"]
        resp = await client.patch(f"/api/alerts/{alert_id}", json={
            "status": "investigating", "analyst_notes": "Looking into this"
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    async def test_dashboard_stats(self, client, auth_headers):
        resp = await client.get("/api/alerts/dashboard", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_alerts" in data
        assert "severity_breakdown" in data
        assert data["total_alerts"] >= 0


class TestSystem:
    async def test_health_check(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    async def test_docs_accessible(self, client):
        resp = await client.get("/docs")
        assert resp.status_code == 200
