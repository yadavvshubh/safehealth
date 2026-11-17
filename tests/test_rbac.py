"""SR4 + success criterion: 100% of restricted requests denied in the role-by-route matrix."""
import sqlite3

import pytest

from conftest import rows

ALL = {"admin", "doctor", "nurse", "receptionist"}
# Written by hand from section 9.3 of the proposal - deliberately NOT derived from rbac.py.
MATRIX = {
    ("GET", "/"): ALL,
    ("GET", "/account/password"): ALL,
    ("GET", "/admin/users"): {"admin"},
    ("GET", "/admin/users/new"): {"admin"},
    ("POST", "/admin/users/new"): {"admin"},
    ("POST", "/admin/users/3/end-sessions"): {"admin"},
    ("GET", "/security/"): {"admin"},
    ("GET", "/security/api/summary"): {"admin"},
    ("GET", "/security/audit"): {"admin"},
    ("POST", "/security/verify-chain"): {"admin"},
    ("POST", "/security/alerts/1/ack"): {"admin"},
    ("GET", "/patients/"): {"doctor", "nurse", "receptionist"},
    ("GET", "/patients/1"): {"doctor", "nurse", "receptionist"},
    ("GET", "/patients/new"): {"receptionist"},
    ("POST", "/patients/new"): {"receptionist"},
    ("GET", "/patients/1/edit"): {"receptionist"},
    ("POST", "/patients/1/clinical"): {"doctor"},
    ("POST", "/patients/1/prescriptions"): {"doctor"},
    ("POST", "/patients/1/vitals"): {"doctor", "nurse"},
    ("POST", "/patients/1/team"): {"receptionist"},
    ("GET", "/appointments/"): {"doctor", "receptionist"},
    ("GET", "/appointments/new"): {"receptionist"},
    ("POST", "/appointments/new"): {"receptionist"},
    ("POST", "/appointments/1/status"): {"receptionist"},
}
USER = {"admin": "sharma", "doctor": "meera", "nurse": "anita", "receptionist": "ravi"}
CASES = [(m, p, role) for (m, p), allowed in MATRIX.items() for role in sorted(ALL)]


@pytest.mark.parametrize("method,path,role", CASES)
def test_role_route_matrix(app, login, method, path, role):
    client = login(USER[role])
    before = rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='access.denied'")[0]["n"]
    r = client.open(path, method=method, data={"csrf_token": client.csrf} if method == "POST" else None)
    if role in MATRIX[(method, path)]:
        assert r.status_code != 403, f"{role} should be allowed {method} {path}"
    else:
        assert r.status_code == 403, f"{role} must be denied {method} {path}"
        after = rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='access.denied'")[0]["n"]
        assert after == before + 1                               # every denial is logged


def test_matrix_covers_every_route(app):
    covered = set()
    adapter = app.url_map.bind("localhost")
    for method, path in MATRIX:
        covered.add(adapter.match(path, method=method)[0])
    every = {r.endpoint for r in app.url_map.iter_rules()} - {"static", "auth.login", "auth.mfa", "auth.mfa_enroll", "auth.logout"}
    assert every - covered == set()


def test_unauthenticated_requests_go_to_login(app):
    client = app.test_client()
    for method, path in MATRIX:
        if method == "GET":
            r = client.get(path)
            assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_default_deny_for_a_view_without_policy(app, login):
    app.add_url_rule("/forgotten", "forgotten", lambda: "secret")
    assert login("sharma").get("/forgotten").status_code == 403


def test_idor_doctor_cannot_open_unassigned_patient(app, login):
    meera = login("meera")
    assert meera.get("/patients/1").status_code == 200
    assert meera.get("/patients/19").status_code == 403          # arjun's patient: changing the ID in the URL
    assert meera.get("/patients/9999").status_code == 403        # same answer for IDs that do not exist
    assert meera.post("/patients/19/prescriptions", data={"csrf_token": meera.csrf, "drug": "x", "dosage": "y"}).status_code == 403
    assert rows(app, "SELECT COUNT(*) n FROM prescriptions WHERE patient_id=19")[0]["n"] == 0
    denied = rows(app, "SELECT * FROM audit_log WHERE action='access.denied' AND patient_id=19")
    assert len(denied) == 2 and denied[0]["username"] == "meera"


def test_field_level_scope_per_role(app, login):
    doctor = login("meera").get("/patients/1").get_data(as_text=True)
    nurse = login("anita").get("/patients/1").get_data(as_text=True)
    reception = login("ravi").get("/patients/1").get_data(as_text=True)
    assert all(m in doctor for m in ("ALLERGY-MARKER", "DIAGNOSIS-MARKER", "HISTORY-MARKER"))
    assert "DIAGNOSIS-MARKER" in nurse and "HISTORY-MARKER" not in nurse and "Prescriptions" not in nurse
    assert not any(m in reception for m in ("ALLERGY-MARKER", "DIAGNOSIS-MARKER", "HISTORY-MARKER"))
    assert "Test Patient 1" in reception


def test_lists_only_show_assigned_patients(app, login):
    page = login("arjun").get("/patients/").get_data(as_text=True)
    assert "Test Patient 19" in page and "Test Patient 1<" not in page
    assert "Test Patient 1<" in login("ravi").get("/patients/").get_data(as_text=True)
    assert "Test Patient 1<" not in login("arjun").get("/appointments/").get_data(as_text=True)


def test_sensitive_fields_encrypted_at_rest(app, login):
    meera = login("meera")
    meera.post("/patients/1/clinical", data={"csrf_token": meera.csrf, "diagnosis": "PLAINTEXT-SECRET-DX",
                                             "allergies": "PLAINTEXT-ALLERGY", "history": "PLAINTEXT-HISTORY"})
    meera.post("/patients/1/prescriptions", data={"csrf_token": meera.csrf, "drug": "PLAINTEXT-DRUG", "dosage": "1"})
    meera.post("/patients/1/vitals", data={"csrf_token": meera.csrf, "pulse": "70", "notes": "PLAINTEXT-NOTE"})
    raw = open(app.config["DB_PATH"], "rb").read()
    for marker in (b"PLAINTEXT-SECRET-DX", b"PLAINTEXT-ALLERGY", b"PLAINTEXT-HISTORY", b"PLAINTEXT-DRUG",
                   b"PLAINTEXT-NOTE", b"DIAGNOSIS-MARKER"):
        assert marker not in raw
    assert b"field.key" not in raw and "PLAINTEXT-SECRET-DX" in meera.get("/patients/1").get_data(as_text=True)
    secrets_in_db = rows(app, "SELECT totp_secret_enc FROM users")[0]["totp_secret_enc"]
    assert secrets_in_db.startswith("gAAAA")                      # TOTP secrets are encrypted too


def test_xss_payload_is_encoded(app, login):
    meera = login("meera")
    payload = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    meera.post("/patients/1/clinical", data={"csrf_token": meera.csrf, "diagnosis": payload})
    meera.post("/patients/1/vitals", data={"csrf_token": meera.csrf, "notes": payload})
    page = meera.get("/patients/1").get_data(as_text=True)
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    ravi = login("ravi")
    r = ravi.post("/patients/new", data={"csrf_token": ravi.csrf, "full_name": payload, "dob": "1990-01-01",
                                         "gender": "Other", "phone": "+91 90000 00000"})
    assert r.status_code == 400 and "<script>alert(1)" not in r.get_data(as_text=True)


def test_sql_injection_in_search_and_audit_filters(app, login):
    ravi, admin = login("ravi"), login("sharma")
    for payload in ("' OR 1=1 --", "%' UNION SELECT password_hash,2,3,4 FROM users --", "'; DROP TABLE patients; --"):
        r = ravi.get("/patients/", query_string={"q": payload})
        assert r.status_code == 200 and "No patients" in r.get_data(as_text=True)
        assert admin.get("/security/audit", query_string={"username": payload, "action": payload, "ip": payload}).status_code == 200
    assert rows(app, "SELECT COUNT(*) n FROM patients")[0]["n"] == 20


def test_security_headers(app, login):
    h = login("meera").get("/patients/1", base_url="https://localhost").headers
    assert "default-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Cache-Control"] == "no-store" and "max-age" in h["Strict-Transport-Security"]


def test_clinic_workflow(app, login):
    ravi = login("ravi")
    r = ravi.post("/patients/new", data={"csrf_token": ravi.csrf, "full_name": "Test Patient New", "dob": "2000-02-02",
                                         "gender": "Female", "phone": "+91 90000 12345", "address": "1 Lab Road"})
    pid = int(r.headers["Location"].rsplit("/", 1)[1])
    arjun_id = rows(app, "SELECT id FROM users WHERE username='arjun'")[0]["id"]
    arjun = login("arjun")
    assert arjun.get(f"/patients/{pid}").status_code == 403
    ravi.post("/appointments/new", data={"csrf_token": ravi.csrf, "patient_id": pid, "doctor_id": arjun_id,
                                         "scheduled_at": "2026-12-05T09:30", "note": "First visit"})
    assert arjun.get(f"/patients/{pid}").status_code == 200       # booking assigned the doctor
    arjun.post(f"/patients/{pid}/prescriptions", data={"csrf_token": arjun.csrf, "drug": "Placebo", "dosage": "1 daily"})
    assert "Placebo" in arjun.get(f"/patients/{pid}").get_data(as_text=True)
    assert "Test Patient New" in arjun.get("/appointments/").get_data(as_text=True)
    admin = login("sharma")
    r = admin.post("/admin/users/new", data={"csrf_token": admin.csrf, "username": "newnurse", "full_name": "New Nurse",
                                             "role": "nurse", "password": "Another-Good-Pass-77"})
    assert r.status_code == 302 and rows(app, "SELECT role FROM users WHERE username='newnurse'")[0]["role"] == "nurse"
    weak = admin.post("/admin/users/new", data={"csrf_token": admin.csrf, "username": "weak", "full_name": "Weak One",
                                                "role": "nurse", "password": "short"})
    assert weak.status_code == 400
