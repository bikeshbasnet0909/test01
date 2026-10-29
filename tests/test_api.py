from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_paste_endpoint_returns_report():
    response = client.post("/api/v1/analyze/paste", json={
        "raw_email": "From: sender@example.org\nSubject: Hello\n\nTest body"
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis_mode"] == "deterministic_local_only"
    assert "risk_assessment" in payload


def test_rejects_blank_paste():
    response = client.post("/api/v1/analyze/paste", json={"raw_email": "  "})
    assert response.status_code == 422


def test_upload_requires_eml_extension():
    response = client.post(
        "/api/v1/analyze/eml",
        files={"file": ("email.txt", b"From: a@example.org\n\nbody", "text/plain")},
    )
    assert response.status_code == 415
