"""Health check endpoints."""
from flask import Blueprint

bp = Blueprint("health", __name__)


@bp.route("/health")
def health_check():
    """Basic health check endpoint."""
    return ("ok", 200, {"Content-Type": "text/plain"})


@bp.route("/ready")
def readiness_check():
    """Readiness check endpoint (can be extended with dependency checks)."""
    return ("ready", 200, {"Content-Type": "text/plain"})
