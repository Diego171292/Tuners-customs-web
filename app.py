import os
import secrets
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, request, send_from_directory, session

BASE_DIR = Path(__file__).resolve().parent
DISCORD_API = "https://discord.com/api/v10"
DEFAULT_REDIRECT_URI = (
    "https://tuners-customs-web-production.up.railway.app/auth/discord/callback"
)

app = Flask(__name__)
secret_key = os.environ.get("FLASK_SECRET_KEY", "").strip()
if not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing in Railway Variables")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
)


def oauth_config():
    return (
        os.environ.get("DISCORD_CLIENT_ID", "").strip(),
        os.environ.get("DISCORD_CLIENT_SECRET", "").strip(),
        os.environ.get("DISCORD_REDIRECT_URI", "").strip() or DEFAULT_REDIRECT_URI,
    )


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/auth-status")
def auth_status():
    client_id, client_secret, redirect_uri = oauth_config()
    return jsonify({
        "client_id_present": bool(client_id),
        "client_secret_present": bool(client_secret),
        "redirect_uri_configured": bool(redirect_uri),
        "ready": bool(client_id and client_secret),
    })


@app.get("/auth/discord")
@app.get("/login")
def discord_login():
    client_id, client_secret, redirect_uri = oauth_config()
    if not client_id:
        return "Discord Client ID chyba v Railway Variables.", 503
    if not client_secret:
        return "Discord Client Secret chyba v Railway Variables.", 503

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }
    return redirect("https://discord.com/oauth2/authorize?" + urlencode(params))


@app.get("/auth/discord/callback")
def discord_callback():
    if request.args.get("error"):
        return redirect("/?login=cancelled")

    expected = session.pop("oauth_state", None)
    actual = request.args.get("state", "")
    if not expected or not secrets.compare_digest(expected, actual):
        return "Neplatny prihlasovaci stav. Skus to znova.", 400

    code = request.args.get("code")
    if not code:
        return "Chyba prihlasovaci kod Discordu.", 400

    client_id, client_secret, redirect_uri = oauth_config()
    if not client_id or not client_secret:
        return "Discord prihlasovacie udaje chybaju v Railway.", 503

    try:
        token_response = requests.post(
            DISCORD_API + "/oauth2/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
            timeout=15,
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]
        user_response = requests.get(
            DISCORD_API + "/users/@me",
            headers={"Authorization": "Bearer " + access_token},
            timeout=15,
        )
        user_response.raise_for_status()
        user = user_response.json()
        user_id = user["id"]
        username = user["username"]
    except (requests.RequestException, KeyError, ValueError, TypeError):
        return "Discord prihlasenie zlyhalo. Skus to znova.", 502

    session.clear()
    session.permanent = True
    session["user"] = {
        "id": user_id,
        "username": username,
        "global_name": user.get("global_name"),
        "avatar": user.get("avatar"),
    }
    return redirect("/?login=success")


@app.get("/api/me")
def current_user():
    user = session.get("user")
    if user is None:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": user})


@app.get("/logout")
@app.get("/auth/logout")
def logout():
    session.clear()
    return redirect("/")


@app.get("/<path:filename>")
def static_files(filename):
    blocked = {"Dockerfile", "requirements.txt", "runtime.txt", "Procfile"}
    if (filename.startswith(".") or "/." in filename or
            filename.endswith(".py") or filename in blocked):
        return "Not found", 404
    return send_from_directory(BASE_DIR, filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
