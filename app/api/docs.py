"""Documentation blueprints exposing the SCIM OpenAPI description and ReDoc UI."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from flask import Blueprint, Response, current_app, jsonify, url_for

bp = Blueprint("docs", __name__)


def _spec_path() -> Path:
    """Resolve the OpenAPI specification path."""
    override = current_app.config.get("OPENAPI_SPEC_PATH")
    if override:
        return Path(override)
    return Path(current_app.root_path).parent / "openapi" / "scim_openapi.yaml"


def _load_spec() -> dict[str, Any]:
    """Load the OpenAPI spec from disk (YAML)."""
    path = _spec_path()
    if not path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@bp.route("/openapi.json", methods=["GET"])
def openapi_document() -> Response:
    """Serve the OpenAPI document as JSON."""
    spec = _load_spec()
    return jsonify(spec)


@bp.route("/scim/docs", methods=["GET"])
def scim_docs() -> Response:
    """Serve a ReDoc page (read-only) for the SCIM specification."""
    spec_url = url_for("docs.openapi_document", _external=False)
    redoc_script = url_for("static", filename="vendor/redoc.standalone.min.js")
    html = f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <title>IAM PoC – SCIM API Reference</title>
    <meta name="robots" content="noindex,nofollow"/>
    <meta name="referrer" content="no-referrer"/>
    <style>
      body {{
        margin: 0;
        font-family: "Segoe UI", Roboto, sans-serif;
        background-color: #f8fafc;
        color: #0f172a;
      }}
      .banner {{
        background: #0f172a;
        color: #f8fafc;
        padding: 12px 24px;
        font-size: 14px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }}
      .banner strong {{
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }}
      redoc {{
        flex: 1 1 auto;
        background-color: #f8fafc;
      }}
      a {{
        color: #0f7dd1;
      }}
    </style>
  </head>
  <body>
    <div class="banner">
      <div>
        <strong>IAM PoC</strong> – SCIM 2.0 reference (read-only). OAuth bearer tokens are mandatory; disable public access in production.
      </div>
      <div>
        <a href="{spec_url}" style="color:#38bdf8;text-decoration:none;">OpenAPI JSON</a>
      </div>
    </div>
    <redoc spec-url="{spec_url}" expand-responses="200"></redoc>
    <script src="{redoc_script}"></script>
  </body>
</html>"""
    return Response(html, status=200, mimetype="text/html")
