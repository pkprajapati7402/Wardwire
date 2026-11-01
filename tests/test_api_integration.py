"""API integration tests for alerts, incidents, stats, and simulator."""

from fastapi.testclient import TestClient

from sentinel.api.main import app

client = TestClient(app)


def test_healthz_and_readyz():
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    res = client.get("/readyz")
    assert res.status_code == 200
    assert res.json()["status"] == "ready"


def test_metrics_prometheus():
    res = client.get("/metrics")
    assert res.status_code == 200
    assert "wardwire_ingest_events_total" in res.text


def test_list_alerts_and_incidents():
    res = client.get("/v1/alerts")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    res_inc = client.get("/v1/incidents")
    assert res_inc.status_code == 200
    assert isinstance(res_inc.json(), list)


def test_stats_overview():
    res = client.get("/v1/stats/overview")
    assert res.status_code == 200
    data = res.json()
    assert "requests_per_sec" in data
    assert "current_risk_gauge" in data
    assert "operating_mode" in data


def test_simulator_status():
    res = client.get("/v1/sim/status")
    assert res.status_code == 200
    data = res.json()
    assert "allowed_targets" in data
