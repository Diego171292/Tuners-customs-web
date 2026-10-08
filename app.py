import os
import secrets
from pathlib import Path
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session, jsonify, send_file

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")
if not app.secret_key:
raise RuntimeError("Missing FLASK_SECRET_KEY")

app.config.update(
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SECURE=True,
SESSION_COOKIE_SAMESITE="Lax",
)

CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")

BASE_URL = "https://tuners-customs-web-production.up.railway.app"
REDIRECT_URI = BASE_URL + "/auth/discord/callback"

DISCORD_API = "https://discord.com/api/v10"


@app.route("/")
def home():
return send_file(Path(__file__).parent / "index.html")


@app.route("/auth/discord")
def discord_login():
if not CLIENT_ID or not CLIENT_SECRET:
return "Discord login is not configured", 503

state = secrets.token_urlsafe(32)
session["oauth_state"] = state

params = {
"client_id": CLIENT_ID,
"redirect_uri": REDIRECT_URI,
"response_type": "code",
"scope": "identify guilds",
"state": state,
"prompt": "consent",
}

return redirect(
"https://discord.com/oauth2/authorize?"
+ urlencode(params)
)


@app.route("/auth/discord/callback")
def discord_callback():
if request.args.get("error"):
return redirect("/?login=cancelled")

expected_state = session.pop("oauth_state", None)
received_state = request.args.get("state", "")

if (
not expected_state
or not secrets.compare_digest(
expected_state, received_state
)
):
return "Invalid login state", 400

code = request.args.get("code")
if not code:
return "Missing authorization code", 400

try:
token_response = requests.post(
DISCORD_API + "/oauth2/token",
data={
"client_id": CLIENT_ID,
"client_secret": CLIENT_SECRET,
"grant_type": "authorization_code",
"code": code,
"redirect_uri": REDIRECT_URI,
},
timeout=15,
)
token_response.raise_for_status()
access_token = token_response.json()["access_token"]

user_response = requests.get(
DISCORD_API + "/users/@me",
headers={
"Authorization": f"Bearer {access_token}"
},
timeout=15,
)
user_response.raise_for_status()
user = user_response.json()

except (requests.RequestException, KeyError, ValueError):
return "Discord authentication failed", 502

session.clear()
session["user"] = {
"id": user["id"],
"username": user["username"],
"global_name": user.get("global_name"),
"avatar": user.get("avatar"),
}

return redirect("/?login=success")


@app.route("/api/me")
def current_user():
user = session.get("user")

if not user:
return jsonify({"authenticated": False}), 401

return jsonify({
"authenticated": True,
"user": user,
})


@app.route("/logout")
def logout():
session.clear()
return redirect("/")


if __name__ == "__main__":
app.run(
host="0.0.0.0",
port=int(os.environ.get("PORT", "8080")),
)
