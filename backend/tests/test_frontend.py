"""Automated verification suite for the Ground Control Station frontend integration (Phase 5).

Verifies that the FastAPI backend properly serves the HTML5/CSS3/Vanilla JS/Three.js
frontend, vendor modules, static assets, and coordinates seamlessly with API endpoints.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppConfig
from backend.app.main import create_app
from backend.app.persistence.database import DatabaseManager


@pytest.fixture
def gcs_client(tmp_path: Path):
    """Provides a fresh isolated test client with frontend static mounting."""
    db_file = tmp_path / "test_gcs.db"
    db_mgr = DatabaseManager(str(db_file))

    cfg = AppConfig(
        db_path=str(db_file),
        telemetry_interval_seconds=0.05,
        simulation_tick_rate_hz=20.0,
        rate_limit_capacity=10.0,
        rate_limit_refill_rate=5.0,
        security_mode="UNSECURED",
    )

    app = create_app(app_config=cfg, db_manager=db_mgr)
    with TestClient(app) as client:
        yield client


def test_frontend_root_serves_html(gcs_client: TestClient):
    """Verify GET / delivers the Ground Control Station index.html."""
    resp = gcs_client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    content = resp.text

    # Core GCS UI elements must be present
    assert "DRONESEC GCS" in content
    assert "three-canvas" in content
    assert "Primary Flight Telemetry" in content
    assert "Authoritative Flight Controls" in content
    assert "btn-launch-attack" in content
    assert "modal-attack-history" in content
    assert "/js/app.js" in content


def test_frontend_static_assets_served(gcs_client: TestClient):
    """Verify that CSS, ES modules, and Three.js vendor scripts are accessible."""
    assets = [
        ("/css/gcs.css", "text/css"),
        ("/js/app.js", "application/javascript"),
        ("/js/simulation.js", "application/javascript"),
        ("/js/telemetry.js", "application/javascript"),
        ("/js/flight_controls.js", "application/javascript"),
        ("/js/security_panel.js", "application/javascript"),
        ("/js/attack_console.js", "application/javascript"),
        ("/js/event_log.js", "application/javascript"),
        ("/js/vendor/three.module.js", "application/javascript"),
        ("/js/vendor/OrbitControls.js", "application/javascript"),
    ]

    for path, expected_content_type in assets:
        resp = gcs_client.get(path)
        assert resp.status_code == 200, f"Failed to load asset: {path}"
        ct = resp.headers.get("content-type", "")
        # Accept text/javascript, application/javascript, or text/css
        assert any(t in ct for t in (expected_content_type, "javascript", "css")), (
            f"Unexpected content-type '{ct}' for {path}"
        )


def test_api_routes_precedence_over_static(gcs_client: TestClient):
    """Verify API routes retain precedence over static file resolution."""
    # Health check
    resp = gcs_client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["data"]["system_status"] == "OPERATIONAL"

    # Drone State
    resp = gcs_client.get("/api/drone/state")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["flight_state"] == "DISARMED"
    assert data["position"]["x"] == 0.0
    assert data["position"]["y"] == 0.0
    assert data["position"]["z"] == 0.0

    # Security Status
    resp = gcs_client.get("/api/security/status")
    assert resp.status_code == 200
    assert resp.json()["data"]["current_mode"] == "UNSECURED"
