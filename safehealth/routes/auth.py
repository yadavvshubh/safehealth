"""Login (password -> TOTP), MFA enrolment, logout, password change."""
import time

from flask import Blueprint, current_app, g, redirect, render_template, request, url_for

from .. import audit, mfa as mfa_lib, passwords, sessions
from ..crypto import cipher
from ..db import get_db
from ..limiter import limiter
from ..rbac import authenticated, mfa_stage, public

bp = Blueprint("auth", __name__)
GENERIC_FAILURE = "Invalid username or password, or the account is temporarily locked."


def _login_rate():
    return current_app.config["LOGIN_RATE"]


@bp.route("/login", methods=["GET", "POST"])
@public
@limiter.limit(_login_rate, methods=["POST"])
def login():
    if g.user is not None:
        return redirect(url_for("main.home"))
    if request.method == "GET":
        if g.session is None:
            sessions.start("anon")
        return render_template("login.html")

    username = (request.form.get("username") or "").strip().lower()[:64]
    password = (request.form.get("password") or "")[:256]
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if user is not None and user["locked_until"] > time.time():
        passwords.dummy_verify(password)
        audit.log("login.blocked", result="denied", username=username, detail={"reason": "locked"})
        return render_template("login.html", error=GENERIC_FAILURE), 401

    valid = passwords.verify(user["password_hash"], password) if user else passwords.dummy_verify(password)
    if not (user is not None and valid and user["is_active"]):
        audit.log("login.failure", result="failure", username=username, detail={"stage": "password"})
        return render_template("login.html", error=GENERIC_FAILURE), 401   # same message for every cause

    if passwords.needs_rehash(user["password_hash"]):
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (passwords.hash_password(password), user["id"]))
        db.commit()
    sessions.start("mfa_pending", user["id"])       # new session ID: prevents session fixation
    g.pending_user = user
    audit.log("login.password_ok")
    return redirect(url_for("auth.mfa" if user["totp_enabled"] else "auth.mfa_enroll"))


def _complete_login(user):
    db = get_db()
    db.execute("UPDATE users SET fail_reset_at=? WHERE id=?", (time.time(), user["id"]))
    db.commit()
    sessions.start("active", user["id"])            # new session ID again at full login
    g.pending_user, g.user = None, user
    audit.log("login.success")
    return redirect(url_for("main.home"))


def _mfa_failed():
    audit.log("login.failure", result="failure", detail={"stage": "mfa"})
    if not sessions.still_exists():                 # the brute-force rule locked the account
        sessions.destroy_current()
        return redirect(url_for("auth.login"))
    return None


@bp.route("/mfa", methods=["GET", "POST"])
@mfa_stage
@limiter.limit(_login_rate, methods=["POST"])
def mfa():
    user = g.pending_user
    if not user["totp_enabled"]:
        return redirect(url_for("auth.mfa_enroll"))
    if request.method == "POST":
        if mfa_lib.verify(user, request.form.get("code", "")):
            return _complete_login(user)
        return _mfa_failed() or (render_template("mfa.html", error="Invalid or already-used code."), 401)
    return render_template("mfa.html")


@bp.route("/mfa/enroll", methods=["GET", "POST"])
@mfa_stage
@limiter.limit(_login_rate, methods=["POST"])
def mfa_enroll():
    user = g.pending_user
    if user["totp_enabled"]:
        return redirect(url_for("auth.mfa"))
    db = get_db()
    secret = cipher().decrypt(user["totp_secret_enc"]) if user["totp_secret_enc"] else None
    if not secret:
        secret = mfa_lib.new_secret()
        db.execute("UPDATE users SET totp_secret_enc=? WHERE id=?", (cipher().encrypt(secret), user["id"]))
        db.commit()
    error = None
    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if mfa_lib.check(secret, code):
            db.execute("UPDATE users SET totp_enabled=1, last_totp_code=?, last_totp_at=? WHERE id=?",
                       (code, time.time(), user["id"]))
            db.commit()
            audit.log("mfa.enrolled")
            return _complete_login(user)
        failed = _mfa_failed()
        if failed:
            return failed
        error = "That code is not correct. Check the time on your phone and try again."
    uri = mfa_lib.provisioning_uri(secret, user["username"])
    spaced = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("mfa_enroll.html", secret=spaced, qr=mfa_lib.qr_svg(uri), error=error), (401 if error else 200)


@bp.route("/logout", methods=["POST"])
@authenticated
def logout():
    audit.log("logout")
    sessions.destroy_current()                      # server-side delete: the old cookie is now useless
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@authenticated
def change_password():
    errors = []
    if request.method == "POST":
        current = (request.form.get("current") or "")[:256]
        new = request.form.get("new") or ""
        if not passwords.verify(g.user["password_hash"], current):
            errors.append("Current password is not correct.")
            audit.log("password.change", result="failure")
        elif new != (request.form.get("confirm") or ""):
            errors.append("The two new passwords do not match.")
        else:
            errors = passwords.policy_errors(new, g.user["username"])
        if not errors:
            db = get_db()
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (passwords.hash_password(new), g.user["id"]))
            db.commit()
            sessions.destroy_user_sessions(g.user["id"], keep_current=True)
            audit.log("password.change")
            sessions.flash("Password changed. Other sessions were signed out.", "ok")
            return redirect(url_for("main.home"))
    return render_template("password.html", errors=errors), (400 if errors else 200)
