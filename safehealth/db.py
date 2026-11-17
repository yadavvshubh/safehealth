"""SQLite access. SR6: every query in this project uses ? placeholders - never string building."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','doctor','nurse','receptionist')),
    password_hash TEXT NOT NULL,
    totp_secret_enc TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    last_totp_code TEXT,
    last_totp_at REAL NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    locked_until REAL NOT NULL DEFAULT 0,
    fail_reset_at REAL NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,            -- SHA-256 of the cookie value; the raw ID is never stored
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('anon','mfa_pending','active')),
    csrf TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT,
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    dob TEXT NOT NULL,
    gender TEXT NOT NULL,
    phone TEXT NOT NULL,
    address_enc TEXT,
    allergies_enc TEXT,
    diagnosis_enc TEXT,
    history_enc TEXT,
    created_by INTEGER REFERENCES users(id),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS assignments (
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (patient_id, user_id)
);
CREATE TABLE IF NOT EXISTS vitals (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    recorded_by INTEGER NOT NULL REFERENCES users(id),
    recorded_at REAL NOT NULL,
    temperature REAL, pulse INTEGER, bp_sys INTEGER, bp_dia INTEGER, spo2 INTEGER,
    notes_enc TEXT
);
CREATE TABLE IF NOT EXISTS prescriptions (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES users(id),
    created_at REAL NOT NULL,
    body_enc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES users(id),
    scheduled_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled','completed','cancelled')),
    created_by INTEGER REFERENCES users(id),
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    user_id INTEGER,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    patient_id INTEGER,
    ip TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL UNIQUE,      -- UNIQUE forces a single, linear chain
    hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS audit_action_ts ON audit_log(action, ts);
CREATE INDEX IF NOT EXISTS audit_user_ts ON audit_log(user_id, ts);
-- SR9: the log is append-only at the SQL layer; the hash chain catches anyone who bypasses this.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    subject_user_id INTEGER,
    username TEXT,
    ip TEXT,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '{}',
    response TEXT NOT NULL DEFAULT '',
    hits INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged')),
    ack_by TEXT,
    ack_at REAL
);
"""


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
