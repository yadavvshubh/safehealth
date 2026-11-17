"""SR1, SR2, SR3, SR6, SR8: passwords, lockout, MFA, injection in login, sessions, CSRF."""
import time

from conftest import PASSWORD, form_csrf, rows, totp_now
from safehealth import passwords
from safehealth.db import get_db


def start_login(client, username, password):
    token = form_csrf(client.get("/login"))
    return client.post("/login", data={"csrf_token": token, "username": username, "password": password})


def full_login(app, client, username="meera"):
    r = start_login(client, username, PASSWORD)
    assert r.status_code == 302 and r.headers["Location"].endswith("/mfa")
    token = form_csrf(client.get("/mfa"))
    return client.post("/mfa", data={"csrf_token": token, "code": totp_now(app, username)})


def test_passwords_are_hashed_not_stored(app):
    stored = rows(app, "SELECT password_hash FROM users")[0]["password_hash"]
    assert PASSWORD not in stored and stored.startswith("$")
    assert passwords.verify(stored, PASSWORD) and not passwords.verify(stored, "wrong")


def test_password_policy():
    assert passwords.policy_errors("short1A")
    assert passwords.policy_errors("alllowercaseletters1")
    assert passwords.policy_errors("Meera-Is-The-Best-99", "meera")
    assert not passwords.policy_errors("Correct-Horse-42-Battery", "meera")


def test_password_alone_is_not_enough(app):
    client = app.test_client()
    start_login(client, "meera", PASSWORD)
    assert client.get("/patients/").status_code == 302          # still not logged in without TOTP
    assert client.get("/patients/1").headers["Location"].endswith("/login")


def test_full_login_with_totp_and_session_rotation(app):
    client = app.test_client()
    client.get("/login")
    anon = client.get_cookie("sh_session").value
    start_login(client, "meera", PASSWORD)
    pending = client.get_cookie("sh_session").value
    token = form_csrf(client.get("/mfa"))
    r = client.post("/mfa", data={"csrf_token": token, "code": totp_now(app, "meera")})
    active = client.get_cookie("sh_session").value
    assert r.status_code == 302 and len({anon, pending, active}) == 3      # new ID at each step
    assert client.get("/patients/1").status_code == 200
    assert rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='login.success' AND username='meera'")[0]["n"] == 1


def test_wrong_totp_rejected_and_code_cannot_be_replayed(app):
    client = app.test_client()
    start_login(client, "meera", PASSWORD)
    token = form_csrf(client.get("/mfa"))
    assert client.post("/mfa", data={"csrf_token": token, "code": "000000"}).status_code == 401
    code = totp_now(app, "meera")
    assert client.post("/mfa", data={"csrf_token": token, "code": code}).status_code == 302
    other = app.test_client()                                   # attacker replays the same code
    start_login(other, "meera", PASSWORD)
    token2 = form_csrf(other.get("/mfa"))
    assert other.post("/mfa", data={"csrf_token": token2, "code": code}).status_code == 401


def test_first_login_forces_mfa_enrolment(app):
    with app.app_context():
        get_db().execute("UPDATE users SET totp_enabled=0, totp_secret_enc=NULL WHERE username='ravi'")
        get_db().commit()
    client = app.test_client()
    r = start_login(client, "ravi", PASSWORD)
    assert r.headers["Location"].endswith("/mfa/enroll")
    page = client.get("/mfa/enroll")
    token = form_csrf(page)
    assert client.post("/mfa/enroll", data={"csrf_token": token, "code": "123456"}).status_code == 401
    r = client.post("/mfa/enroll", data={"csrf_token": token, "code": totp_now(app, "ravi")})
    assert r.status_code == 302 and client.get("/patients/").status_code == 200
    assert rows(app, "SELECT totp_enabled FROM users WHERE username='ravi'")[0]["totp_enabled"] == 1


def test_sql_injection_in_login_fails_and_is_logged(app):
    client = app.test_client()
    for payload in ("' OR '1'='1' --", "meera'--", "admin' UNION SELECT 1,2,3--"):
        assert start_login(client, payload, "' OR '1'='1").status_code == 401
    assert rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='login.failure'")[0]["n"] == 3
    assert rows(app, "SELECT COUNT(*) n FROM users")[0]["n"] == 5       # tables intact


def test_same_error_for_unknown_user_and_wrong_password(app):
    client = app.test_client()
    a = start_login(client, "meera", "wrong-password").get_data(as_text=True)
    b = start_login(client, "nobody", "wrong-password").get_data(as_text=True)
    strip = lambda html: html.split("<main>")[1].split('name="csrf_token"')[0]
    assert strip(a) == strip(b)


def test_lockout_after_five_failures(app):
    client = app.test_client()
    for _ in range(5):
        assert start_login(client, "anita", "wrong").status_code == 401
    assert rows(app, "SELECT locked_until FROM users WHERE username='anita'")[0]["locked_until"] > time.time()
    assert start_login(client, "anita", PASSWORD).status_code == 401    # correct password, still locked
    assert rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='login.blocked'")[0]["n"] == 1


def test_logout_invalidates_session_on_server(app):
    client = app.test_client()
    full_login(app, client)
    stolen = client.get_cookie("sh_session").value
    token = form_csrf(client.get("/"))
    client.post("/logout", data={"csrf_token": token})
    thief = app.test_client()
    thief.set_cookie("sh_session", stolen)
    assert thief.get("/patients/1").status_code == 302          # old cookie is useless


def test_idle_and_absolute_session_expiry(app, login):
    client = login("meera")
    assert client.get("/").status_code == 200
    with app.app_context():
        get_db().execute("UPDATE sessions SET last_seen=last_seen-16*60")
        get_db().commit()
    assert client.get("/").status_code == 302
    client = login("meera")
    with app.app_context():
        get_db().execute("UPDATE sessions SET created_at=created_at-9*3600")
        get_db().commit()
    assert client.get("/").status_code == 302


def test_cookie_flags(tmp_path):
    from safehealth import create_app
    secure_app = create_app(instance_dir=tmp_path / "i2", TESTING=True, RATELIMIT_ENABLED=False)
    header = secure_app.test_client().get("/login", base_url="https://localhost").headers["Set-Cookie"]
    assert header.startswith("__Host-sh_session=")
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
        assert flag in header


def test_csrf_token_required(app, login):
    client = login("ravi")
    assert client.post("/logout").status_code == 400
    assert client.post("/logout", data={"csrf_token": "guess"}).status_code == 400
    assert client.get("/").status_code == 200                   # still logged in: forged logout failed
    assert rows(app, "SELECT COUNT(*) n FROM audit_log WHERE action='csrf.failure'")[0]["n"] == 2


def test_deactivated_user_loses_access_immediately(app, login):
    nurse, admin = login("anita"), login("sharma")
    uid = rows(app, "SELECT id FROM users WHERE username='anita'")[0]["id"]
    assert nurse.get("/patients/").status_code == 200
    admin.post(f"/admin/users/{uid}/deactivate", data={"csrf_token": admin.csrf})
    assert nurse.get("/patients/").status_code == 302
