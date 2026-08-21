"""API endpoint integration tests using FastAPI TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as tc:
        yield tc


def test_health_endpoint(client: TestClient) -> None:
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SentinelSOC"
    assert data["ml_model_loaded"] is True
    assert "pipeline_mode" in data


def test_seed_and_list_alerts(client: TestClient) -> None:
    seed_res = client.post("/api/alerts/seed?force=true")
    assert seed_res.status_code == 200
    assert seed_res.json()["alerts_loaded"] == 8

    list_res = client.get("/api/alerts")
    assert list_res.status_code == 200
    alerts = list_res.json()
    assert len(alerts) == 8
    assert any(a["id"] == "ALT-2024-001" for a in alerts)


def test_investigate_alert_and_get_report(client: TestClient) -> None:
    # 1. Trigger investigation for ALT-2024-001
    inv_res = client.post("/api/alerts/ALT-2024-001/investigate")
    assert inv_res.status_code == 200
    data = inv_res.json()
    assert data["alert_id"] == "ALT-2024-001"
    assert data["verdict"] == "true_positive"
    assert data["recommended_action"] == "contain"
    assert data["severity"] == "critical"
    assert data["steps_count"] == 7

    # 2. Get alert detail
    detail_res = client.get("/api/alerts/ALT-2024-001")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["status"] == "completed"
    assert detail["investigation"] is not None
    assert len(detail["investigation"]["steps"]) == 7
    assert detail["has_report"] is True

    # 3. Get markdown report
    rep_res = client.get("/api/alerts/ALT-2024-001/report")
    assert rep_res.status_code == 200
    rep = rep_res.json()
    assert rep["alert_id"] == "ALT-2024-001"
    assert "Résumé Exécutif" in rep["markdown"]


def test_stats_endpoint(client: TestClient) -> None:
    stats_res = client.get("/api/alerts/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_alerts"] == 8
    assert stats["completed_alerts"] >= 1
