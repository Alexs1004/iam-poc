"""Error handlers for the application."""
from flask import render_template, jsonify
from werkzeug.exceptions import HTTPException


def register_error_handlers(app):
    """Register error handlers with the Flask app."""
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request errors."""
        if _wants_json():
            return jsonify({"error": "Bad Request", "message": str(error)}), 400
        return render_template(
            "403.html",  # Reuse 403 template
            title="Bad Request",
            required_role="Valid request format",
        ), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle 401 Unauthorized errors."""
        if _wants_json():
            return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
        # Redirect to login for web requests
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 Forbidden errors."""
        if _wants_json():
            return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403
        return render_template(
            "403.html",
            title="Forbidden",
            required_role="appropriate permissions",
        ), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors."""
        if _wants_json():
            return jsonify({"error": "Not Found", "message": "Resource not found"}), 404
        return render_template(
            "403.html",  # Reuse 403 template
            title="Not Found",
            required_role="valid URL",
        ), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server Error."""
        app.logger.error(f"Internal error: {error}", exc_info=True)
        if _wants_json():
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500
        return render_template(
            "403.html",  # Reuse 403 template with generic message
            title="Error",
            required_role="server recovery",
        ), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle uncaught exceptions."""
        # Pass through HTTP errors
        if isinstance(error, HTTPException):
            return error
        
        # Log the error
        app.logger.error(f"Unhandled exception: {error}", exc_info=True)
        
        # Return 500
        if _wants_json():
            return jsonify({"error": "Internal Server Error", "message": str(error)}), 500
        return render_template(
            "403.html",
            title="Error",
            required_role="server recovery",
        ), 500


def _wants_json():
    """Check if the client wants a JSON response."""
    from flask import request
    
    # SCIM endpoints always return JSON (RFC 7644)
    if request.path.startswith("/scim/v2"):
        return True
    
    return request.accept_mimetypes.accept_json and \
           not request.accept_mimetypes.accept_html
