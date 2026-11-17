"""FR6: SOC-style dashboard - alerts, event counts, audit-log search, chain verification."""
import json
import time
from datetime import datetime

from flask import Blueprint, g, jsonify, redirect, render_template, request, url_for

from .. import audit, sessions
from ..db import get_db
from ..rbac import require

bp = Blueprint("security", __name__, url_prefix="/security")
PAGE = 50


def _summary():
    db, day = get_db(), time.time() - 86400
    count = lambda action: db.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action=? AND ts>=?", (action, day)).fetchone()[0]
    open_by_sev = {r["severity"]: r["n"] for r in db.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE status='open' GROUP BY severity")}
    alerts = [dict(r) for r in db.execute("SELECT * FROM alerts ORDER BY status DESC, last_seen DESC LIMIT 25")]
    for a in alerts:
        a["time"] = datetime.fromtimestamp(a["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "counts": {
            "Open High alerts": open_by_sev.get("High", 0),
            "Open Medium alerts": open_by_sev.get("Medium", 0),
            "Logins (24 h)": count("login.success"),
            "Failed logins (24 h)": count("login.failure"),
            "Denied requests (24 h)": count("access.denied"),
            "Record views (24 h)": count("patient.view"),
            "Locked accounts": db.execute("SELECT COUNT(*) FROM users WHERE locked_until>?", (time.time(),)).fetchone()[0],
            "Audit entries": db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        },
        "alerts": alerts,
    }


@bp.route("/")
@require("security.view")
def dashboard():
    audit.log("security.dashboard")
    events = get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 15").fetchall()
    return render_template("security/dashboard.html", summary=_summary(), events=events,
                           chain=request.args.get("chain"))


@bp.route("/api/summary")
@require("security.view")
def api_summary():
    return jsonify(_summary())


@bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@require("security.view")
def acknowledge(alert_id):
    db = get_db()
    db.execute("UPDATE alerts SET status='acknowledged', ack_by=?, ack_at=? WHERE id=? AND status='open'",
               (g.user["username"], time.time(), alert_id))
    db.commit()
    audit.log("alert.acknowledge", detail={"alert_id": alert_id})
    return redirect(url_for("security.dashboard"))


@bp.route("/verify-chain", methods=["POST"])
@require("security.view")
def verify_chain():
    result = audit.verify_chain()
    audit.log("audit.verify", result="success" if result["ok"] else "failure",
              detail={"entries": result["count"], "bad_id": result["bad_id"]})
    if result["ok"]:
        sessions.flash(f"Audit chain intact: {result['count']} entries verified.", "ok")
    else:
        sessions.flash(f"AUDIT LOG TAMPERING DETECTED at entry #{result['bad_id']}. "
                       "Preserve the database file as evidence and follow the incident playbook.", "error")
    return redirect(url_for("security.dashboard"))


@bp.route("/audit")
@require("security.view")
def audit_search():
    args, where, params = request.args, [], []
    filters = {k: (args.get(k) or "").strip()[:64] for k in ("username", "action", "patient_id", "result", "ip", "day")}
    if filters["username"]:
        where.append("username = ?"); params.append(filters["username"])
    if filters["action"]:
        where.append("action LIKE ? ESCAPE '\\'")
        params.append(filters["action"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if filters["patient_id"].isdigit():
        where.append("patient_id = ?"); params.append(int(filters["patient_id"]))
    if filters["result"] in ("success", "failure", "denied"):
        where.append("result = ?"); params.append(filters["result"])
    if filters["ip"]:
        where.append("ip = ?"); params.append(filters["ip"])
    try:
        start = datetime.strptime(filters["day"], "%Y-%m-%d").timestamp()
        where.append("ts >= ? AND ts < ?"); params += [start, start + 86400]
    except ValueError:
        filters["day"] = ""
    page = max(1, int(args.get("page", "1")) if args.get("page", "1").isdigit() else 1)
    # The WHERE text is built only from the fixed fragments above; every value is a bound parameter.
    sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ? OFFSET ?"
    rows = get_db().execute(sql, params + [PAGE + 1, (page - 1) * PAGE]).fetchall()
    audit.log("audit.search", detail={k: val for k, val in filters.items() if val})
    entries = [dict(r, detail_obj=json.loads(r["detail"])) for r in rows[:PAGE]]
    return render_template("security/audit.html", entries=entries, filters=filters, page=page,
                           has_next=len(rows) > PAGE)
