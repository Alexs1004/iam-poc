import json
from pathlib import Path

import pytest
from flask import Flask

from app.api import docs


@pytest.fixture
def docs_app(tmp_path):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["OPENAPI_SPEC_PATH"] = str(tmp_path / "spec.yaml")
    spec_path = Path(app.config["OPENAPI_SPEC_PATH"])
    spec_path.write_text(
        "openapi: 3.0.3\ninfo:\n  title: Test API\npaths: {}\n", encoding="utf-8"
    )
    app.register_blueprint(docs.bp)
    return app


@pytest.fixture
def docs_client(docs_app):
    with docs_app.test_client() as client:
        yield client


def test_openapi_document_returns_spec_json(docs_client):
    response = docs_client.get("/openapi.json")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["openapi"] == "3.0.3"
    assert payload["info"]["title"] == "Test API"


def test_scim_docs_renders_redoc_page(docs_client):
    response = docs_client.get("/scim/docs")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "<redoc" in html
    assert "OpenAPI JSON" in html


def test_spec_path_uses_default_when_no_override(monkeypatch):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["APP_CONFIG"] = object()
    with app.app_context():
        expected = Path(app.root_path).parent / "openapi" / "scim_openapi.yaml"
        assert docs._spec_path() == expected
