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
            "errors/403.html",  # Reuse 403 template
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
        # Extract required role from error description if provided
        # Format: "Required role: role1, role2" or just use default
        required_role = "appropriate permissions"
        if hasattr(error, 'description') and error.description:
            desc = str(error.description)
            if desc.startswith("Required role:"):
                required_role = desc.replace("Required role:", "").strip()
            elif desc != "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server.":
                required_role = desc
        
        if _wants_json():
            # Use generic message for default case, specific message when role is provided
            if required_role == "appropriate permissions":
                message = "Insufficient permissions"
            else:
                message = f"Required role: {required_role}"
            return jsonify({"error": "Forbidden", "message": message}), 403
        return render_template(
            "errors/403.html",
            title="Forbidden",
            required_role=required_role,
        ), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors."""
        if _wants_json():
            return jsonify({"error": "Not Found", "message": "Resource not found"}), 404
        return render_template(
            "errors/403.html",  # Reuse 403 template
            title="Not Found",
            required_role="valid URL",
        ), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server Error."""
        import traceback
        error_details = traceback.format_exc()
        
        # ALWAYS log the full error (even in production) - logs are secure
        app.logger.error(f"Internal error: {error}", exc_info=True)
        print(f"[ERROR 500] {error}")
        print(error_details)
        
        if _wants_json():
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500
        
        # SECURITY: Show traceback ONLY in debug/demo mode, never in production
        show_details = app.debug or app.config.get('DEMO_MODE', False)
        
        return render_template(
            "errors/500.html",
            title="Internal Server Error",
            error_message=error_details if show_details else None,
            show_debug=show_details,
        ), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle uncaught exceptions."""
        # Pass through HTTP errors
        if isinstance(error, HTTPException):
            return error
        
        import traceback
        error_details = traceback.format_exc()
        
        # ALWAYS log the error (even in production) - logs are secure
        app.logger.error(f"Unhandled exception: {error}", exc_info=True)
        print(f"[ERROR UNHANDLED] {error}")
        print(error_details)
        
        # Return 500
        if _wants_json():
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500
        
        # SECURITY: Show traceback ONLY in debug/demo mode, never in production
        show_details = app.debug or app.config.get('DEMO_MODE', False)
        
        return render_template(
            "errors/500.html",
            title="Internal Server Error",
            error_message=error_details if show_details else None,
            show_debug=show_details,
        ), 500


def _wants_json():
    """Check if the client wants a JSON response."""
    from flask import request
    
    # SCIM endpoints always return JSON (RFC 7644)
    if request.path.startswith("/scim/v2"):
        return True
    
    return request.accept_mimetypes.accept_json and \
           not request.accept_mimetypes.accept_html
