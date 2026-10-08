import os
import secrets
from pathlib import Path
from urllib.parse import urlencode

import requests
from flask import (
Flask,
jsonify,
redirect,
request,
send_from_directory,
session,
)

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent

BASE_URL = "https://tuners-customs-web-production.up.railway.app"

DISCORD_API = "https://discord.com/api/v10"

DISCORD_CLIENT_ID = os.environ.get(
"DISCORD_CLIENT_ID", ""
)

DISCORD_CLIENT_SECRET = os.environ.get(
"DISCORD_CLIENT_SECRET", ""
)

FLASK_SECRET_KEY = os.environ.get(
"FLASK_SECRET_KEY", ""
)

if not FLASK_SECRET_KEY:
raise RuntimeError(
"Missing FLASK_SECRET_KEY"
)

app.secret_key = FLASK_SECRET_KEY

app.config.update(
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SECURE=True,
SESSION_COOKIE_SAMESITE="Lax",
PERMANENT_SESSION_LIFETIME=86400,
)

REDIRECT_URI = (
BASE_URL + "/auth/discord/callback"
)


@app.route("/")
def home():
return send_from_directory(
BASE_DIR,
"index.html"
)


@app.route("/auth/discord")
def discord_login():
if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
return (
"Discord OAuth nie je nastaveny.",
503,
)

state = secrets.token_urlsafe(32)

session["oauth_state"] = state

params = {
"client_id": DISCORD_CLIENT_ID,
"redirect_uri": REDIRECT_URI,
"response_type": "code",
"scope": "identify",
"state": state,
}

authorization_url = (
"https://discord.com/oauth2/authorize?"
+ urlencode(params)
)

return redirect(authorization_url)


@app.route("/auth/discord/callback")
def discord_callback():
if request.args.get("error"):
return redirect("/?login=cancelled")

expected_state = session.pop(
"oauth_state", None
)

received_state = request.args.get(
"state", ""
)

if not expected_state:
return "Chybajuci OAuth state.", 400

if not secrets.compare_digest(
expected_state,
received_state,
):
return "Neplatny OAuth state.", 400

code = request.args.get("code")

if not code:
return "Chybajuci Discord kod.", 400

try:
token_response = requests.post(
DISCORD_API + "/oauth2/token",
data={
"client_id": DISCORD_CLIENT_ID,
"client_secret": DISCORD_CLIENT_SECRET,
"grant_type": "authorization_code",
"code": code,
"redirect_uri": REDIRECT_URI,
},
timeout=15,
)

token_response.raise_for_status()

access_token = token_response.json()[
"access_token"
]

user_response = requests.get(
DISCORD_API + "/users/@me",
headers={
"Authorization": (
f"Bearer {access_token}"
)
},
timeout=15,
)

user_response.raise_for_status()

user = user_response.json()

user_id = user["id"]
username = user["username"]

except (
requests.RequestException,
KeyError,
ValueError,
):
return (
"Discord prihlasenie zlyhalo.",
502,
)

session.clear()

session.permanent = True

session["user"] = {
"id": user_id,
"username": username,
"global_name": user.get(
"global_name"
),
"avatar": user.get("avatar"),
}

return redirect("/?login=success")


@app.route("/api/me")
def current_user():
user = session.get("user")

if not user:
return jsonify({
"authenticated": False
}), 401

return jsonify({
"authenticated": True,
"user": user,
})


@app.route("/logout")
def logout():
session.clear()
return redirect("/")


@app.route("/<path:filename>")
def static_files(filename):
if filename.startswith("."):
return "Not found", 404

return send_from_directory(
BASE_DIR,
filename,
)


if __name__ == "__main__":
port = int(
os.environ.get("PORT", "8080")
)

app.run(
host="0.0.0.0",
port=port,
)
