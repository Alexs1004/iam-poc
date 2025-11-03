"""Tests for health check endpoints."""
import pytest
from flask import Flask

from app.api.health import bp as health_bp


@pytest.fixture()
def client():
    app = Flask(__name__)
    app.register_blueprint(health_bp)
    with app.test_client() as client:
        yield client


def test_health_check(client):
    """Test basic health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.data == b"ok"
    assert response.content_type.startswith("text/plain")


def test_readiness_check(client):
    """Test readiness check endpoint (line 16)."""
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.data == b"ready"
    assert response.content_type.startswith("text/plain")
