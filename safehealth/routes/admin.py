"""FR5: administrator manages staff accounts and performs incident-response actions."""
import time

from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import audit, passwords, sessions, validators as v
from ..db import get_db
from ..rbac import PERMISSIONS, require

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/users")
@require("users.manage")
def users():
    rows = get_db().execute(
        "SELECT u.*, (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id AND s.state='active') AS live"
        " FROM users u ORDER BY u.role, u.username").fetchall()
    audit.log("users.list")
    return render_template("admin/users.html", users=rows, now=time.time())


@bp.route("/users/new", methods=["GET", "POST"])
@require("users.manage")
def new_user():
    roles = sorted(PERMISSIONS)
    if request.method == "POST":
        try:
            username = v.text(request.form, "username", "Username", 32, pattern=v.USERNAME)
            full_name = v.text(request.form, "full_name", "Full name", 80, pattern=v.NAME)
            role = v.choice(request.form, "role", "Role", roles)
            password = request.form.get("password") or ""
            problems = passwords.policy_errors(password, username)
            if problems:
                raise v.Invalid(" ".join(problems))
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise v.Invalid("That username is already taken.")
        except v.Invalid as exc:
            return render_template("admin/user_form.html", roles=roles, form=request.form, error=str(exc)), 400
        cur = db.execute("INSERT INTO users (username,full_name,role,password_hash,created_at) VALUES (?,?,?,?,?)",
                         (username, full_name, role, passwords.hash_password(password), time.time()))
        db.commit()
        audit.log("user.create", detail={"target_id": cur.lastrowid, "target": username, "role": role})
        sessions.flash(f"Account '{username}' created. They will set up their authenticator at first login.", "ok")
        return redirect(url_for("admin.users"))
    return render_template("admin/user_form.html", roles=roles, form={})


@bp.route("/users/<int:user_id>/<action>", methods=["POST"])
@require("users.manage")
def user_action(user_id, action):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None or action not in ("deactivate", "activate", "unlock", "reset-mfa", "end-sessions"):
        return redirect(url_for("admin.users"))
    if action == "deactivate":
        if target["id"] == g.user["id"]:
            sessions.flash("You cannot deactivate your own account.", "error")
            return redirect(url_for("admin.users"))
        db.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
        db.commit()
        sessions.destroy_user_sessions(user_id)         # leavers lose access at once (UR7)
    elif action == "activate":
        db.execute("UPDATE users SET is_active=1 WHERE id=?", (user_id,))
    elif action == "unlock":
        db.execute("UPDATE users SET locked_until=0, fail_reset_at=? WHERE id=?", (time.time(), user_id))
    elif action == "reset-mfa":
        db.execute("UPDATE users SET totp_enabled=0, totp_secret_enc=NULL WHERE id=?", (user_id,))
        db.commit()
        sessions.destroy_user_sessions(user_id, keep_current=True)
    elif action == "end-sessions":
        sessions.destroy_user_sessions(user_id, keep_current=True)
    db.commit()
    audit.log("user." + action, detail={"target_id": user_id, "target": target["username"]})
    sessions.flash(f"Done: {action} for '{target['username']}'.", "ok")
    return redirect(url_for("admin.users"))
