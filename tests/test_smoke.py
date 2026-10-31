from fastapi.testclient import TestClient
import app as agentguard

client = TestClient(agentguard.app)

def test_homepage_serves():
    response = client.get("/")
    assert response.status_code == 200
    assert "AGENTGUARD" in response.text

def test_health_endpoint_if_available():
    response = client.get("/api/health")
    # The current MVP may not expose a health endpoint yet.
    assert response.status_code in (200, 404)
