import os
from flask import Flask, redirect, url_for, session, render_template_string, request
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")

ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8080/realms/demo")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "flask-app")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:5000/callback")

oauth = OAuth(app)
oidc = oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET or None,
    client_kwargs={
        "scope": "openid profile email",
    },
)

TEMPLATE = """
<!doctype html>
<title>IAM Demo</title>
<h1>Mini IAM Demo</h1>
<ul>
  {% if token %}
    <li><a href="{{ url_for('me') }}">/me</a></li>
    <li><a href="{{ url_for('admin') }}">/admin</a></li>
    <li><a href="{{ url_for('logout') }}">Logout</a></li>
  {% else %}
    <li><a href="{{ url_for('login') }}">Login with Keycloak</a></li>
  {% endif %}
</ul>
{% if msg %}<pre>{{ msg }}</pre>{% endif %}
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE, token=session.get("token"), msg="")

@app.route("/login")
def login():
    return oidc.authorize_redirect(redirect_uri=REDIRECT_URI)

@app.route("/callback")
def callback():
    token = oidc.authorize_access_token()
    session["token"] = token
    return redirect(url_for("me"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

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
    userinfo = oidc.get("userinfo").json()
    roles = _roles_from_token({"userinfo": userinfo})
    return render_template_string(TEMPLATE + "<h2>Userinfo</h2><pre>{{ ui|tojson(indent=2) }}</pre><h2>Roles</h2><pre>{{ roles }}</pre>",
                                 token=token, msg="", ui=userinfo, roles=roles)

@app.route("/admin")
def admin():
    token = session.get("token")
    if not token:
        return redirect(url_for("login"))
    userinfo = oidc.get("userinfo").json()
    roles = _roles_from_token({"userinfo": userinfo})
    if "admin" not in roles:
        return render_template_string(TEMPLATE, token=token, msg="403 Forbidden: admin role required")
    return render_template_string(TEMPLATE, token=token, msg="Welcome admin!")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
