import hashlib
import re
import secrets
import time

import pyotp
import pytest

from safehealth import create_app, passwords
from safehealth.crypto import cipher
from safehealth.db import get_db

PASSWORD = "Correct-Horse-42-Battery"
ROLES = {"sharma": "admin", "meera": "doctor", "arjun": "doctor", "anita": "nurse", "ravi": "receptionist"}


@pytest.fixture()
def app(tmp_path):
    app = create_app(instance_dir=tmp_path / "instance", TESTING=True, COOKIE_SECURE=False,
                     RATELIMIT_ENABLED=False, CLINIC_HOURS=(0, 24))
    with app.app_context():
        db, c = get_db(), cipher()
        pw_hash = passwords.hash_password(PASSWORD)
        for username, role in ROLES.items():
            db.execute("INSERT INTO users (username,full_name,role,password_hash,totp_secret_enc,totp_enabled,created_at)"
                       " VALUES (?,?,?,?,?,1,?)", (username, username.title(), role, pw_hash,
                                                   c.encrypt(pyotp.random_base32()), time.time()))
        ids = {r["username"]: r["id"] for r in db.execute("SELECT id, username FROM users")}
        for n in range(1, 21):          # patients 1-20; 1-18 belong to meera+anita, 19-20 to arjun
            db.execute("INSERT INTO patients (full_name,dob,gender,phone,allergies_enc,diagnosis_enc,history_enc,"
                       "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                       (f"Test Patient {n}", "1990-01-01", "Other", "+91 90000 00000", c.encrypt("ALLERGY-MARKER"),
                        c.encrypt("DIAGNOSIS-MARKER"), c.encrypt("HISTORY-MARKER"), time.time(), time.time()))
            for staff in (("meera", "anita") if n <= 18 else ("arjun",)):
                db.execute("INSERT INTO assignments VALUES (?,?)", (n, ids[staff]))
        db.execute("INSERT INTO appointments (patient_id,doctor_id,scheduled_at,created_at) VALUES (1,?,?,?)",
                   (ids["meera"], "2026-12-01T10:00", time.time()))
        db.commit()
    return app


def force_login(app, client, username, ip="127.0.0.1"):
    """Create an active session directly (the full password+TOTP flow is tested in test_auth)."""
    token = secrets.token_urlsafe(32)
    with app.app_context():
        db = get_db()
        uid = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        db.execute("INSERT INTO sessions (id_hash,user_id,state,csrf,created_at,last_seen,ip) VALUES (?,?,?,?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(), uid, "active", "csrf-" + username, time.time(), time.time(), ip))
        db.commit()
    client.set_cookie("sh_session", token)
    return "csrf-" + username


@pytest.fixture()
def login(app):
    def _login(username):
        client = app.test_client()
        client.csrf = force_login(app, client, username)
        return client
    return _login


def form_csrf(response):
    return re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)).group(1)


def totp_now(app, username):
    with app.app_context():
        row = get_db().execute("SELECT totp_secret_enc FROM users WHERE username=?", (username,)).fetchone()
        return pyotp.TOTP(cipher().decrypt(row["totp_secret_enc"])).now()


def rows(app, sql, params=()):
    with app.app_context():
        return [dict(r) for r in get_db().execute(sql, params)]
