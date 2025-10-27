from types import SimpleNamespace

import pytest
from flask import Flask, Blueprint, abort
from jinja2 import DictLoader

from app.api.errors import register_error_handlers


@pytest.fixture()
def flask_client():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.jinja_loader = DictLoader({"403.html": "{{ title }} - {{ required_role }}"})
    app.logger = SimpleNamespace(error=lambda *args, **kwargs: None)

    register_error_handlers(app)

    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login")
    def login():
        return "login"

    app.register_blueprint(auth_bp)

    @app.route("/scim/v2/forbidden")
    def scim_forbidden():
        abort(403)

    @app.route("/scim/v2/crash")
    def scim_crash():
        raise RuntimeError("boom")

    @app.route("/form/error")
    def form_error():
        abort(400, "invalid payload")

    @app.route("/api/unauth")
    def api_unauth():
        abort(401)

    @app.route("/page/error")
    def page_error():
        abort(500)

    @app.route("/page/forbidden")
    def page_forbidden():
        abort(403)

    with app.test_client() as client:
        yield client


def test_scim_error_returns_json(flask_client):
    response = flask_client.get("/scim/v2/forbidden")
    assert response.status_code == 403
    payload = response.get_json()
    assert payload == {"error": "Forbidden", "message": "Insufficient permissions"}


def test_internal_error_json_payload(flask_client):
    response = flask_client.get("/scim/v2/crash")
    assert response.status_code == 500
    payload = response.get_json()
    assert payload["error"] == "Internal Server Error"
    assert "boom" in payload["message"]


def test_bad_request_html_uses_template(flask_client):
    response = flask_client.get("/form/error", headers={"Accept": "text/html"})
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "Bad Request" in body
    assert "Valid request format" in body


def test_unauthorized_json_message(flask_client):
    response = flask_client.get("/api/unauth", headers={"Accept": "application/json"})
    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized", "message": "Authentication required"}


def test_unauthorized_redirects_to_login(flask_client):
    response = flask_client.get("/api/unauth", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_bad_request_json_payload(flask_client):
    response = flask_client.get("/form/error", headers={"Accept": "application/json"})
    assert response.status_code == 400
    assert response.get_json() == {"error": "Bad Request", "message": "400 Bad Request: invalid payload"}


def test_forbidden_html_path(flask_client):
    response = flask_client.get("/page/forbidden", headers={"Accept": "text/html"})
    assert response.status_code == 403
    body = response.get_data(as_text=True)
    assert "Forbidden" in body
    assert "appropriate permissions" in body


def test_internal_error_html_template(flask_client):
    response = flask_client.get("/page/error", headers={"Accept": "text/html"})
    assert response.status_code == 500
    body = response.get_data(as_text=True)
    assert "Error" in body
    assert "server recovery" in body


def test_not_found_html_template(flask_client):
    response = flask_client.get("/missing-page", headers={"Accept": "text/html"})
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "Not Found" in body
    assert "valid URL" in body
