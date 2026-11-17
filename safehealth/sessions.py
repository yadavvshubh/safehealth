"""SR8: server-side sessions.

The cookie holds only a 256-bit random ID. The server stores its SHA-256, so a stolen database
does not yield usable cookies, and logout or a detection rule can kill a session immediately.
A new ID is issued at every privilege change (anonymous -> password OK -> fully logged in).
"""
import hashlib
import hmac
import json
import secrets
import time

from flask import abort, current_app, g, request

from .db import get_db

PASSIVE_ENDPOINTS = {"static", "security.api_summary"}   # polling must not keep a session alive


def cookie_name():
    return "__Host-sh_session" if current_app.config["COOKIE_SECURE"] else "sh_session"


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def start(state, user_id=None):
    db = get_db()
    if g.get("session") is not None:
        db.execute("DELETE FROM sessions WHERE id_hash=?", (g.session["id_hash"],))
    token = secrets.token_urlsafe(32)
    now = time.time()
    db.execute(
        "INSERT INTO sessions (id_hash, user_id, state, csrf, created_at, last_seen, ip) VALUES (?,?,?,?,?,?,?)",
        (_hash(token), user_id, state, secrets.token_urlsafe(32), now, now, request.remote_addr),
    )
    db.commit()
    g.session = db.execute("SELECT * FROM sessions WHERE id_hash=?", (_hash(token),)).fetchone()
    g.set_cookie = token
    g.clear_cookie = False
    return token


def destroy_current():
    if g.get("session") is not None:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE id_hash=?", (g.session["id_hash"],))
        db.commit()
    g.session = None
    g.user = None
    g.pending_user = None
    g.set_cookie = None
    g.clear_cookie = True


def destroy_user_sessions(user_id, keep_current=False):
    db = get_db()
    if keep_current and g.get("session") is not None:
        db.execute("DELETE FROM sessions WHERE user_id=? AND id_hash<>?", (user_id, g.session["id_hash"]))
    else:
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    db.commit()


def still_exists():
    if g.get("session") is None:
        return False
    row = get_db().execute("SELECT 1 FROM sessions WHERE id_hash=?", (g.session["id_hash"],)).fetchone()
    return row is not None


def load():
    """before_request: resolve the cookie to a session and user, enforcing expiry."""
    g.session = g.user = g.pending_user = g.set_cookie = None
    g.clear_cookie = False
    token = request.cookies.get(cookie_name())
    if not token:
        return
    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE id_hash=?", (_hash(token),)).fetchone()
    if row is None:
        g.clear_cookie = True
        return
    cfg = current_app.config
    now = time.time()
    idle = cfg["SESSION_IDLE_SECONDS"] if row["state"] == "active" else cfg["PRELOGIN_SECONDS"]
    user = None
    if row["user_id"] is not None:
        user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    expired = now - row["last_seen"] > idle or now - row["created_at"] > cfg["SESSION_ABSOLUTE_SECONDS"]
    disabled = row["user_id"] is not None and (user is None or not user["is_active"])
    if expired or disabled:
        db.execute("DELETE FROM sessions WHERE id_hash=?", (row["id_hash"],))
        db.commit()
        g.clear_cookie = True
        return
    if request.endpoint not in PASSIVE_ENDPOINTS:
        db.execute("UPDATE sessions SET last_seen=? WHERE id_hash=?", (now, row["id_hash"]))
        db.commit()
    g.session = row
    if row["state"] == "active":
        g.user = user
    elif row["state"] == "mfa_pending":
        g.pending_user = user


def check_csrf():
    """before_request: every state-changing request must carry the session's CSRF token."""
    if request.method in ("GET", "HEAD", "OPTIONS") or request.endpoint is None:
        return
    sent = request.form.get("csrf_token", "")
    if g.session is None or not hmac.compare_digest(sent, g.session["csrf"]):
        from . import audit
        audit.log("csrf.failure", result="denied", detail={"path": request.path})
        abort(400, description="Your session expired or the form was not valid. Please reload the page and try again.")


def save_cookie(response):
    """after_request: set or clear the session cookie with Secure, HttpOnly and SameSite=Strict."""
    secure = current_app.config["COOKIE_SECURE"]
    if g.get("set_cookie"):
        response.set_cookie(cookie_name(), g.set_cookie, httponly=True, secure=secure, samesite="Strict", path="/")
    elif g.get("clear_cookie"):
        response.delete_cookie(cookie_name(), httponly=True, secure=secure, samesite="Strict", path="/")
    return response


def csrf_token():
    return g.session["csrf"] if g.get("session") is not None else ""


def flash(message, category="info"):
    if g.get("session") is None:
        return
    db = get_db()
    row = db.execute("SELECT data FROM sessions WHERE id_hash=?", (g.session["id_hash"],)).fetchone()
    if row is None:
        return
    data = json.loads(row["data"])
    data.setdefault("flash", []).append([category, message])
    db.execute("UPDATE sessions SET data=? WHERE id_hash=?", (json.dumps(data), g.session["id_hash"]))
    db.commit()


def pop_flashes():
    if g.get("session") is None:
        return []
    db = get_db()
    row = db.execute("SELECT data FROM sessions WHERE id_hash=?", (g.session["id_hash"],)).fetchone()
    if row is None:
        return []
    data = json.loads(row["data"])
    messages = data.pop("flash", [])
    if messages:
        db.execute("UPDATE sessions SET data=? WHERE id_hash=?", (json.dumps(data), g.session["id_hash"]))
        db.commit()
    return messages
