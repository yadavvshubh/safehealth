"""SR10: rule-based detection engine. Runs synchronously on every audit event, so alert latency
is effectively the request time (target in the proposal: 60 seconds or less).

Rules (section 8.3): brute force, mass record access, privilege violation, suspicious login,
repeated authorisation failures. File-integrity alerts for the ransomware drill come from fim.py.
"""
import json
import time
from datetime import datetime

from flask import current_app

from . import sessions
from .db import get_db

RANK = {"Low": 0, "Medium": 1, "High": 2}


def raise_alert(rule, severity, summary, key, user_id=None, username=None, ip=None,
                evidence=None, response="", cooldown=120):
    """Create an alert, or fold a repeat into the open alert for the same rule and subject."""
    from . import audit
    db = get_db()
    now = time.time()
    evidence_json = json.dumps(evidence or {}, sort_keys=True)
    row = db.execute(
        "SELECT * FROM alerts WHERE rule=? AND dedup_key=? AND status='open' AND last_seen>=?"
        " ORDER BY id DESC LIMIT 1", (rule, key, now - cooldown)).fetchone()
    if row:
        if RANK[severity] < RANK[row["severity"]]:
            severity = row["severity"]
        db.execute("UPDATE alerts SET hits=hits+1, last_seen=?, severity=?, summary=?, evidence=?, response=?"
                   " WHERE id=?", (now, severity, summary, evidence_json, response, row["id"]))
        db.commit()
        return row["id"]
    cur = db.execute(
        "INSERT INTO alerts (created_at,last_seen,rule,severity,dedup_key,subject_user_id,username,ip,summary,"
        "evidence,response) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (now, now, rule, severity, key, user_id, username, ip, summary, evidence_json, response))
    db.commit()
    audit.log("alert.raised", system=True, detail={"alert_id": cur.lastrowid, "rule": rule, "severity": severity})
    return cur.lastrowid


def evaluate(event):
    action = event["action"]
    if action == "login.failure":
        _brute_force(event)
    elif action == "login.success":
        _suspicious_login(event)
    elif action == "patient.view":
        _mass_record_access(event)
    elif action == "access.denied":
        _privilege_violation(event)
        _repeated_authz_failures(event)


def _brute_force(event):
    cfg, db, now = current_app.config, get_db(), time.time()
    username, ip = event["username"], event["ip"]
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    since = max(now - cfg["LOCKOUT_WINDOW"], user["fail_reset_at"] if user else 0)
    count = db.execute("SELECT COUNT(*) FROM audit_log WHERE action='login.failure' AND username=? AND ts>=?",
                       (username, since)).fetchone()[0]
    if count >= cfg["LOCKOUT_THRESHOLD"]:
        response = "No such account; nothing to lock."
        if user:
            db.execute("UPDATE users SET locked_until=? WHERE id=?", (now + cfg["LOCKOUT_SECONDS"], user["id"]))
            db.commit()
            sessions.destroy_user_sessions(user["id"])
            response = f"Account locked for {cfg['LOCKOUT_SECONDS'] // 60} minutes; all its sessions terminated."
        raise_alert("brute_force", "High",
                    f"{count} failed logins for '{username}' within {cfg['LOCKOUT_WINDOW']} s",
                    key=f"user:{username}", user_id=user["id"] if user else None, username=username, ip=ip,
                    evidence={"failures": count, "source_ip": ip}, response=response,
                    cooldown=cfg["LOCKOUT_SECONDS"])
    from_ip = db.execute("SELECT COUNT(*), COUNT(DISTINCT username) FROM audit_log"
                         " WHERE action='login.failure' AND ip=? AND ts>=?",
                         (ip, now - cfg["LOCKOUT_WINDOW"])).fetchone()
    if from_ip[0] >= 2 * cfg["LOCKOUT_THRESHOLD"]:
        raise_alert("brute_force", "High",
                    f"{from_ip[0]} failed logins from {ip} across {from_ip[1]} account(s)",
                    key=f"ip:{ip}", ip=ip, evidence={"failures": from_ip[0], "accounts": from_ip[1]},
                    response="Login rate limit applied to this address; consider blocking it at the firewall.")


def _suspicious_login(event):
    cfg, db = current_app.config, get_db()
    reasons = []
    known = {r["ip"] for r in db.execute(
        "SELECT DISTINCT ip FROM audit_log WHERE action='login.success' AND user_id=? AND id<?",
        (event["user_id"], event["id"]))}
    if known and event["ip"] not in known:
        reasons.append("new IP address")
    start, end = cfg["CLINIC_HOURS"]
    hour = datetime.fromtimestamp(event["ts"]).hour
    if not (start <= hour < end):
        reasons.append("outside clinic hours")
    if reasons:
        raise_alert("suspicious_login", "Medium",
                    f"Login by '{event['username']}' from {event['ip']}: " + " and ".join(reasons),
                    key=f"user:{event['user_id']}:{event['ip']}", user_id=event["user_id"],
                    username=event["username"], ip=event["ip"], evidence={"reasons": reasons, "hour": hour},
                    response="Second factor (TOTP) was required and passed; confirm with the staff member.",
                    cooldown=3600)


def _mass_record_access(event):
    cfg, db, now = current_app.config, get_db(), time.time()
    count = db.execute("SELECT COUNT(DISTINCT patient_id) FROM audit_log WHERE action='patient.view'"
                       " AND user_id=? AND ts>=?", (event["user_id"], now - cfg["MASS_ACCESS_WINDOW"])).fetchone()[0]
    if count >= cfg["MASS_ACCESS_THRESHOLD"]:
        response = "Flagged for session review by the administrator."
        if cfg["MASS_ACCESS_TERMINATE"]:
            sessions.destroy_user_sessions(event["user_id"])
            response = "User's sessions terminated; flagged for review."
        raise_alert("mass_record_access", "High",
                    f"'{event['username']}' opened {count} different patient records within "
                    f"{cfg['MASS_ACCESS_WINDOW']} s",
                    key=f"user:{event['user_id']}", user_id=event["user_id"], username=event["username"],
                    ip=event["ip"], evidence={"distinct_patients": count}, response=response)


def _privilege_violation(event):
    detail = json.loads(event["detail"])
    if detail.get("reason") not in ("role", "no_policy"):
        return
    cfg, db, now = current_app.config, get_db(), time.time()
    count = db.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action='access.denied' AND user_id=? AND ts>=?"
        " AND json_extract(detail,'$.reason') IN ('role','no_policy')",
        (event["user_id"], now - cfg["PRIV_REPEAT_WINDOW"])).fetchone()[0]
    severity = "High" if count >= cfg["PRIV_REPEAT_THRESHOLD"] else "Medium"
    raise_alert("privilege_violation", severity,
                f"'{event['username']}' ({event['role']}) requested {detail.get('path')} which the role forbids"
                f" ({count} time(s) in {cfg['PRIV_REPEAT_WINDOW'] // 60} min)",
                key=f"user:{event['user_id']}", user_id=event["user_id"], username=event["username"],
                ip=event["ip"], evidence={"violations": count, "last_path": detail.get("path"),
                                          "required": detail.get("required")},
                response="Request denied (403) and logged.", cooldown=cfg["PRIV_REPEAT_WINDOW"])


def _repeated_authz_failures(event):
    cfg, db, now = current_app.config, get_db(), time.time()
    count = db.execute("SELECT COUNT(*) FROM audit_log WHERE action='access.denied' AND user_id=? AND ts>=?",
                       (event["user_id"], now - cfg["AUTHZ_FAIL_WINDOW"])).fetchone()[0]
    if count >= cfg["AUTHZ_FAIL_THRESHOLD"]:
        raise_alert("repeated_authz_failures", "Medium",
                    f"'{event['username']}' had {count} denied requests within {cfg['AUTHZ_FAIL_WINDOW']} s"
                    " (possible ID tampering / forced browsing)",
                    key=f"user:{event['user_id']}", user_id=event["user_id"], username=event["username"],
                    ip=event["ip"], evidence={"denied": count}, response="All requests denied (403) and logged.")
