"""SR9, SR10 + success criteria: 100% of sensitive actions logged, 5 of 5 rules fire, alert latency."""
import sqlite3
import time

import pytest

from conftest import PASSWORD, force_login, form_csrf, rows, totp_now
from safehealth import audit
from safehealth.db import get_db
from test_auth import full_login, start_login


def alerts(app, rule):
    return rows(app, "SELECT * FROM alerts WHERE rule=?", (rule,))


def test_every_sensitive_action_is_logged(app, login):
    meera, ravi, admin = login("meera"), login("ravi"), login("sharma")
    meera.get("/patients/")
    meera.get("/patients/1")
    meera.post("/patients/1/clinical", data={"csrf_token": meera.csrf, "diagnosis": "x"})
    meera.post("/patients/1/vitals", data={"csrf_token": meera.csrf, "pulse": "70"})
    meera.post("/patients/1/prescriptions", data={"csrf_token": meera.csrf, "drug": "a", "dosage": "b"})
    ravi.post("/patients/1/team", data={"csrf_token": ravi.csrf, "user_id": "3", "action": "assign"})
    ravi.get("/appointments/")
    ravi.post("/appointments/1/status", data={"csrf_token": ravi.csrf, "status": "completed"})
    admin.get("/admin/users")
    admin.get("/security/audit")
    admin.post("/security/verify-chain", data={"csrf_token": admin.csrf})
    ravi.get("/security/")
    meera.post("/logout", data={"csrf_token": meera.csrf})
    logged = [r["action"] for r in rows(app, "SELECT action FROM audit_log ORDER BY id")]
    expected = ["patients.list", "patient.view", "clinical.update", "vitals.record", "prescription.add",
                "care_team.assign", "appointments.list", "appointment.update", "users.list", "audit.search",
                "audit.verify", "access.denied", "logout"]
    assert [a for a in logged if a != "alert.raised"] == expected
    entry = rows(app, "SELECT * FROM audit_log WHERE action='patient.view'")[0]
    assert (entry["username"], entry["role"], entry["patient_id"], entry["ip"], entry["result"]) == \
           ("meera", "doctor", 1, "127.0.0.1", "success") and entry["ts"] > 0


def test_hash_chain_verifies_and_detects_tampering(app, login):
    meera = login("meera")
    for pid in (1, 2, 3, 4):
        meera.get(f"/patients/{pid}")
    with app.app_context():
        assert audit.verify_chain() == {"ok": True, "count": 4, "bad_id": None, "head": audit.verify_chain()["head"]}
        db = get_db()
        with pytest.raises(sqlite3.IntegrityError):                # append-only triggers
            db.execute("UPDATE audit_log SET username='nobody' WHERE id=2")
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM audit_log WHERE id=2")
        db.rollback()
        # An attacker with file access drops the trigger and rewrites history...
        db.execute("DROP TRIGGER audit_no_update")
        db.execute("UPDATE audit_log SET patient_id=99 WHERE id=2")
        db.commit()
        result = audit.verify_chain()
        assert result["ok"] is False and result["bad_id"] == 2     # ...and the chain exposes it
    admin = login("sharma")
    page = admin.post("/security/verify-chain", data={"csrf_token": admin.csrf}, follow_redirects=True)
    assert "TAMPERING DETECTED at entry #2" in page.get_data(as_text=True)


def test_deleting_an_entry_breaks_the_chain(app, login):
    meera = login("meera")
    for pid in (1, 2, 3):
        meera.get(f"/patients/{pid}")
    with app.app_context():
        db = get_db()
        db.execute("DROP TRIGGER audit_no_delete")
        db.execute("DELETE FROM audit_log WHERE id=2")
        db.commit()
        assert audit.verify_chain()["bad_id"] == 3


def test_rule1_brute_force_locks_account_and_kills_sessions(app, login):
    victim = login("anita")
    assert victim.get("/").status_code == 200
    attacker = app.test_client()
    started = time.time()
    for _ in range(5):
        start_login(attacker, "anita", "guess")
    alert = alerts(app, "brute_force")
    assert len(alert) == 1 and alert[0]["severity"] == "High" and "locked" in alert[0]["response"]
    assert alert[0]["created_at"] - started < 60                   # NFR: alert within 60 seconds
    assert victim.get("/").status_code == 302                      # existing sessions terminated
    assert rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='alert.raised'")[0]["n"] == 1


def test_rule1_also_counts_wrong_mfa_codes_and_unknown_users(app):
    client = app.test_client()
    start_login(client, "meera", PASSWORD)
    token = form_csrf(client.get("/mfa"))
    for _ in range(5):
        r = client.post("/mfa", data={"csrf_token": token, "code": "000000"})
    assert r.status_code == 302 and len(alerts(app, "brute_force")) == 1
    assert rows(app, "SELECT locked_until FROM users WHERE username='meera'")[0]["locked_until"] > time.time()
    for _ in range(5):
        start_login(app.test_client(), "ghost", "guess")
    assert len(alerts(app, "brute_force")) >= 2                    # per-account and per-source-IP alerts


def test_admin_unlock_resets_the_failure_counter(app, login):
    client = app.test_client()
    for _ in range(5):
        start_login(client, "anita", "guess")
    admin = login("sharma")
    uid = rows(app, "SELECT id FROM users WHERE username='anita'")[0]["id"]
    admin.post(f"/admin/users/{uid}/unlock", data={"csrf_token": admin.csrf})
    start_login(client, "anita", "one more typo")
    assert rows(app, "SELECT locked_until FROM users WHERE username='anita'")[0]["locked_until"] == 0
    assert full_login(app, app.test_client(), "anita").status_code == 302


def test_rule2_mass_record_access(app, login):
    meera = login("meera")
    for pid in range(1, 15):
        meera.get(f"/patients/{pid}")
    assert alerts(app, "mass_record_access") == []
    meera.get("/patients/1")                                       # repeat views of one record do not count
    assert alerts(app, "mass_record_access") == []
    meera.get("/patients/15")
    alert = alerts(app, "mass_record_access")
    assert len(alert) == 1 and alert[0]["severity"] == "High" and alert[0]["username"] == "meera"


def test_rule3_privilege_violation_escalates_when_repeated(app, login):
    ravi = login("ravi")
    ravi.get("/security/audit")
    alert = alerts(app, "privilege_violation")
    assert len(alert) == 1 and alert[0]["severity"] == "Medium" and "/security/audit" in alert[0]["summary"]
    ravi.get("/admin/users")
    ravi.post("/patients/1/clinical", data={"csrf_token": ravi.csrf, "diagnosis": "x"})
    alert = alerts(app, "privilege_violation")
    assert len(alert) == 1 and alert[0]["severity"] == "High" and alert[0]["hits"] == 3


def test_rule4_suspicious_login_new_ip_and_out_of_hours(app):
    assert full_login(app, app.test_client(), "meera").status_code == 302
    assert alerts(app, "suspicious_login") == []                   # first-ever login sets the baseline
    with app.app_context():
        get_db().execute("UPDATE users SET last_totp_code=NULL")
        get_db().commit()
    other = app.test_client()
    other.environ_base["REMOTE_ADDR"] = "10.9.8.7"
    assert full_login(app, other, "meera").status_code == 302
    alert = alerts(app, "suspicious_login")
    assert len(alert) == 1 and alert[0]["severity"] == "Medium" and "new IP" in alert[0]["summary"]
    app.config["CLINIC_HOURS"] = (0, 0)                            # every hour is now "outside hours"
    assert full_login(app, app.test_client(), "arjun").status_code == 302
    assert any("outside clinic hours" in a["summary"] for a in alerts(app, "suspicious_login"))


def test_rule5_repeated_authorisation_failures(app, login):
    meera = login("meera")
    for pid in range(100, 104):
        meera.get(f"/patients/{pid}")                              # walking patient IDs (IDOR probing)
    assert alerts(app, "repeated_authz_failures") == []
    meera.get("/patients/104")
    alert = alerts(app, "repeated_authz_failures")
    assert len(alert) == 1 and alert[0]["severity"] == "Medium"
    assert alerts(app, "privilege_violation") == []                # object-level denials are a different rule


def test_dashboard_shows_alerts_and_admin_can_acknowledge(app, login):
    for _ in range(5):
        start_login(app.test_client(), "anita", "guess")
    admin = login("sharma")
    page = admin.get("/security/").get_data(as_text=True)
    assert "brute_force" in page and "Acknowledge" in page
    data = admin.get("/security/api/summary").get_json()
    assert data["counts"]["Open High alerts"] == 1 and data["counts"]["Locked accounts"] == 1
    admin.post(f"/security/alerts/{data['alerts'][0]['id']}/ack", data={"csrf_token": admin.csrf})
    assert admin.get("/security/api/summary").get_json()["counts"]["Open High alerts"] == 0
    found = admin.get("/security/audit", query_string={"action": "login.", "result": "failure"}).get_data(as_text=True)
    assert found.count("login.failure") == 5
