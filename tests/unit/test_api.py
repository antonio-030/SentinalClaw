"""
Unit-Tests fuer die FastAPI REST-API Endpoints.

Prueft alle oeffentlichen Endpoints mit dem FastAPI TestClient.
Die globale _db-Variable im API-Server wird auf eine Temp-DB
umgebogen, damit die Tests nicht die Produktions-DB beruehren.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.shared.database import DatabaseManager

# Temp-DB Pfad fuer isolierte API-Tests
_API_TEST_DB_PATH = Path("/tmp/test_sentinelclaw_api.db")


@pytest.fixture(autouse=True)
async def _patch_api_db():
    """Ersetzt die globale DB-Instanz im API-Server durch eine Temp-DB.

    Der originale Lifespan wird durch eine leere Variante ersetzt,
    damit der TestClient nicht die Produktions-DB oeffnet.
    """
    import src.api.server as srv

    manager = DatabaseManager(_API_TEST_DB_PATH)
    await manager.initialize()

    # Originalen Lifespan sichern und durch No-Op ersetzen
    original_lifespan = srv.app.router.lifespan_context

    @asynccontextmanager
    async def _noop_lifespan(app: FastAPI):
        yield

    srv.app.router.lifespan_context = _noop_lifespan
    srv._db = manager

    yield

    # Originalzustand wiederherstellen
    srv.app.router.lifespan_context = original_lifespan
    srv._db = None
    await manager.close()
    _API_TEST_DB_PATH.unlink(missing_ok=True)


@pytest.fixture
def client():
    """Erzeugt einen synchronen TestClient fuer die FastAPI-App."""
    from src.api.server import app

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ─── Health-Endpoint ──────────────────────────────────────────────

def test_health_returns_200(client: TestClient):
    """GET /health liefert 200 und enthaelt 'status'."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


def test_health_contains_version(client: TestClient):
    """Health-Response enthaelt die aktuelle Version."""
    data = client.get("/health").json()
    assert data["version"] == "0.1.0"


def test_health_contains_timestamp(client: TestClient):
    """Health-Response enthaelt einen ISO-Zeitstempel."""
    data = client.get("/health").json()
    assert "timestamp" in data
    assert "T" in data["timestamp"]  # ISO-Format pruefung


# ─── Profiles-Endpoint ───────────────────────────────────────────

def test_profiles_returns_200(client: TestClient):
    """GET /api/v1/profiles liefert 200."""
    resp = client.get("/api/v1/profiles")
    assert resp.status_code == 200


def test_profiles_returns_list_of_seven(client: TestClient):
    """Genau 7 vordefinierte Scan-Profile werden zurueckgegeben."""
    data = client.get("/api/v1/profiles").json()
    assert isinstance(data, list)
    assert len(data) == 7


def test_profiles_have_required_fields(client: TestClient):
    """Jedes Profil hat name, description, ports."""
    profiles = client.get("/api/v1/profiles").json()
    for profile in profiles:
        assert "name" in profile
        assert "description" in profile
        assert "ports" in profile
        assert "max_escalation_level" in profile


# ─── Status-Endpoint ─────────────────────────────────────────────

def test_status_returns_200(client: TestClient):
    """GET /api/v1/status liefert 200."""
    resp = client.get("/api/v1/status")
    assert resp.status_code == 200


def test_status_has_system_and_scans(client: TestClient):
    """Status-Response enthaelt 'system' und 'scans' Sektionen."""
    data = client.get("/api/v1/status").json()
    assert "system" in data
    assert "scans" in data


def test_status_system_has_version(client: TestClient):
    """System-Sektion enthaelt die Version."""
    data = client.get("/api/v1/status").json()
    assert data["system"]["version"] == "0.1.0"


def test_status_scans_has_counts(client: TestClient):
    """Scans-Sektion enthaelt running- und total-Zaehler."""
    scans = client.get("/api/v1/status").json()["scans"]
    assert "running" in scans
    assert "total" in scans


# ─── Scans-Endpoint ──────────────────────────────────────────────

def test_list_scans_returns_200(client: TestClient):
    """GET /api/v1/scans liefert 200 und eine Liste."""
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_scans_empty_initially(client: TestClient):
    """Ohne vorherige Scans ist die Liste leer."""
    data = client.get("/api/v1/scans").json()
    assert len(data) == 0


# ─── Findings-Endpoint ───────────────────────────────────────────

def test_list_findings_returns_200(client: TestClient):
    """GET /api/v1/findings liefert 200 und eine Liste."""
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_findings_empty_initially(client: TestClient):
    """Ohne Findings ist die Liste leer."""
    data = client.get("/api/v1/findings").json()
    assert len(data) == 0


# ─── Audit-Endpoint ──────────────────────────────────────────────

def test_list_audit_returns_200(client: TestClient):
    """GET /api/v1/audit liefert 200 und eine Liste."""
    resp = client.get("/api/v1/audit")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ─── Kill-Endpoint ───────────────────────────────────────────────

def test_kill_returns_200(client: TestClient):
    """POST /api/v1/kill liefert 200 und enthaelt 'status'."""
    from src.shared.kill_switch import KillSwitch

    # Kill-Switch vor dem Test zuruecksetzen
    ks = KillSwitch()
    ks.reset()

    resp = client.post("/api/v1/kill", json={"reason": "API-Test"})
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert data["status"] == "killed"

    # Aufraeumen: Kill-Switch wieder deaktivieren
    ks.reset()


def test_kill_includes_reason(client: TestClient):
    """Kill-Response enthaelt die uebergebene Begruendung."""
    from src.shared.kill_switch import KillSwitch

    ks = KillSwitch()
    ks.reset()

    data = client.post(
        "/api/v1/kill", json={"reason": "Sicherheitsvorfall"}
    ).json()
    assert data["reason"] == "Sicherheitsvorfall"

    ks.reset()


# ─── Scan-Detail (404) ───────────────────────────────────────────

def test_get_scan_nonexistent_returns_404(client: TestClient):
    """GET /api/v1/scans/<nicht-existierende-id> liefert 404."""
    fake_id = str(uuid4())
    resp = client.get(f"/api/v1/scans/{fake_id}")
    assert resp.status_code == 404


def test_get_scan_nonexistent_error_message(client: TestClient):
    """404-Response enthaelt eine aussagekraeftige Fehlermeldung."""
    fake_id = str(uuid4())
    data = client.get(f"/api/v1/scans/{fake_id}").json()
    assert "detail" in data
    assert fake_id in data["detail"]


# ─── Query-Parameter ─────────────────────────────────────────────

def test_scans_limit_parameter(client: TestClient):
    """limit-Parameter wird akzeptiert ohne Fehler."""
    resp = client.get("/api/v1/scans?limit=5")
    assert resp.status_code == 200


def test_findings_severity_filter(client: TestClient):
    """severity-Parameter wird akzeptiert ohne Fehler."""
    resp = client.get("/api/v1/findings?severity=critical")
    assert resp.status_code == 200


def test_audit_action_filter(client: TestClient):
    """action-Parameter wird akzeptiert ohne Fehler."""
    resp = client.get("/api/v1/audit?action=scan.started")
    assert resp.status_code == 200
