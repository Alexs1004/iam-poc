import os
from urllib.parse import urlencode
from flask import Flask, redirect, url_for, session, render_template_string, request
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")

ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8080/realms/demo")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "flask-app")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5000/callback")
POST_LOGOUT_REDIRECT_URI = os.environ.get("POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/")

oauth = OAuth(app)
oidc = oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET or None,  # public client
    client_kwargs={"scope": "openid profile email"},
    fetch_token=lambda: session.get("token"),
)
USERINFO_URL = f"{ISSUER}/protocol/openid-connect/userinfo"

TEMPLATE = """
<!doctype html>
<title>IAM Demo</title>
<h1>Mini IAM Demo</h1>
<ul>
  {% if token %}
    <li><a href="{{ url_for('me') }}">/me</a></li>
    <li><a href="{{ url_for('admin') }}">/admin</a></li>
    <li><a href="{{ url_for('logout') }}">Logout (global)</a></li>
    <li><a href="{{ url_for('login', force=1) }}">Login as different user</a></li>
  {% else %}
    <li><a href="{{ url_for('login') }}">Login with Keycloak</a></li>
  {% endif %}
</ul>
{% if msg %}<pre>{{ msg }}</pre>{% endif %}
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE, token=session.get("token"), msg="")

# Login normal (SSO si session Keycloak encore active)
@app.route("/login")
def login():
    force = request.args.get("force")
    extra = {}
    if force:                     # permet de re-demander les identifiants
        extra["prompt"] = "login" # OIDC: force re-auth
    return oidc.authorize_redirect(redirect_uri=REDIRECT_URI, **extra)

@app.route("/callback")
def callback():
    token = oidc.authorize_access_token()
    session["token"] = token
    return redirect(url_for("me"))

# Logout global (Keycloak + app)
@app.route("/logout")
def logout():
    token = session.get("token") or {}
    id_token = token.get("id_token")  # fourni par Authlib après /callback
    session.clear()

    params = {
        # OIDC RP-Initiated Logout
        "post_logout_redirect_uri": os.environ.get("POST_LOGOUT_REDIRECT_URI", "http://localhost:5000/"),
    }
    if id_token:
        params["id_token_hint"] = id_token
    else:
        # fallback si pas d'id_token en session
        params["client_id"] = os.environ.get("OIDC_CLIENT_ID", "flask-app")

    logout_url = f"{ISSUER}/protocol/openid-connect/logout?{urlencode(params)}"
    return redirect(logout_url)

def _roles_from_token(token):
    roles = []
    if not token:
        return roles
    realm_access = token.get("userinfo", {}).get("realm_access") or token.get("access_token", {}).get("realm_access")
    if isinstance(realm_access, dict):
        roles.extend(realm_access.get("roles", []))
    return roles

@app.route("/me")
def me():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))
    userinfo = oidc.get(USERINFO_URL, token=token).json()
    roles = _roles_from_token({"userinfo": userinfo})
    return render_template_string(
        TEMPLATE + "<h2>Userinfo</h2><pre>{{ ui|tojson(indent=2) }}</pre>"
                   "<h2>Roles</h2><pre>{{ roles }}</pre>",
        token=token, msg="", ui=userinfo, roles=roles
    )

@app.route("/admin")
def admin():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))
    userinfo = oidc.get(USERINFO_URL, token=token).json()
    roles = _roles_from_token({"userinfo": userinfo})
    if "admin" not in roles:
        return render_template_string(TEMPLATE, token=token, msg="403 Forbidden: admin role required")
    return render_template_string(TEMPLATE, token=token, msg="Welcome admin!")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
