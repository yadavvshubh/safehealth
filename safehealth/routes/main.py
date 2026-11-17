from flask import Blueprint, g, render_template

from ..db import get_db
from ..rbac import authenticated

bp = Blueprint("main", __name__)


@bp.route("/")
@authenticated
def home():
    db, user, stats = get_db(), g.user, {}
    if user["role"] in ("doctor", "nurse"):
        stats["Assigned patients"] = db.execute(
            "SELECT COUNT(*) FROM assignments WHERE user_id=?", (user["id"],)).fetchone()[0]
    if user["role"] == "doctor":
        stats["Upcoming appointments"] = db.execute(
            "SELECT COUNT(*) FROM appointments WHERE doctor_id=? AND status='scheduled'", (user["id"],)).fetchone()[0]
    if user["role"] == "receptionist":
        stats["Registered patients"] = db.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
        stats["Scheduled appointments"] = db.execute(
            "SELECT COUNT(*) FROM appointments WHERE status='scheduled'").fetchone()[0]
    if user["role"] == "admin":
        stats["Staff accounts"] = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        stats["Open alerts"] = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
    return render_template("home.html", stats=stats)
