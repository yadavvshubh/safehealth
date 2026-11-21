"""Synthetic demo data (NFR Privacy: no real patient data anywhere). All names are invented."""
import json
import os
import secrets
import string
import time
from pathlib import Path

from flask import current_app

from . import passwords
from .crypto import cipher
from .db import get_db

STAFF = [
    ("sharma", "Mr. Sharma", "admin"),
    ("meera", "Dr. Meera Iyer", "doctor"),
    ("arjun", "Dr. Arjun Rao", "doctor"),
    ("anita", "Anita Joseph", "nurse"),
    ("kavya", "Kavya Menon", "nurse"),
    ("ravi", "Ravi Kumar", "receptionist"),
]
PATIENTS = [
    ("Test Patient Alpha", "1984-03-12", "Female", "+91 90000 00001", "Penicillin", "Type 2 diabetes (synthetic)"),
    ("Test Patient Bravo", "1975-11-02", "Male", "+91 90000 00002", "", "Hypertension (synthetic)"),
    ("Test Patient Charlie", "1992-07-21", "Male", "+91 90000 00003", "Peanuts", "Seasonal asthma (synthetic)"),
    ("Test Patient Delta", "2001-01-30", "Female", "+91 90000 00004", "", "Migraine (synthetic)"),
    ("Test Patient Echo", "1968-09-09", "Other", "+91 90000 00005", "Sulfa drugs", "Osteoarthritis (synthetic)"),
    ("Test Patient Foxtrot", "1989-05-17", "Female", "+91 90000 00006", "", "Iron-deficiency anaemia (synthetic)"),
    ("Test Patient Golf", "1955-12-25", "Male", "+91 90000 00007", "Aspirin", "Chronic kidney disease stage 2 (synthetic)"),
    ("Test Patient Hotel", "1997-04-04", "Female", "+91 90000 00008", "", "Hypothyroidism (synthetic)"),
    ("Test Patient India", "1980-08-15", "Male", "+91 90000 00009", "Latex", "Lower back pain (synthetic)"),
    ("Test Patient Juliet", "2010-02-11", "Female", "+91 90000 00010", "", "Allergic rhinitis (synthetic)"),
]
# Extra records so the mass-record-access rule (15 records in 2 minutes) can be demonstrated.
PATIENTS += [(f"Test Patient Number {chr(65 + i)}", "1990-01-01", "Other", f"+91 90000 001{i:02d}", "", "Routine check (synthetic)")
             for i in range(12)]


def _password():
    # Hosted demo: one fixed, shareable password for every account so it survives the free host's
    # restarts (which wipe the disk and re-seed). Must still pass the policy. Unset in the lab -> random.
    fixed = os.environ.get("SAFEHEALTH_DEMO_PASSWORD")
    if fixed:
        if passwords.policy_errors(fixed):
            raise SystemExit("SAFEHEALTH_DEMO_PASSWORD fails the password policy (need 12+ chars, upper, lower, digit).")
        return fixed
    alphabet = string.ascii_letters + string.digits
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(16))
        if not passwords.policy_errors(candidate):
            return candidate


def run():
    db, c, now = get_db(), cipher(), time.time()
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        raise SystemExit("Database already has users. Delete instance/safehealth.db first to reseed.")
    credentials, ids = [], {}
    for username, full_name, role in STAFF:
        password = _password()
        cur = db.execute("INSERT INTO users (username,full_name,role,password_hash,created_at) VALUES (?,?,?,?,?)",
                         (username, full_name, role, passwords.hash_password(password), now))
        ids[username] = cur.lastrowid
        credentials.append((username, role, password))
    for i, (name, dob, gender, phone, allergies, diagnosis) in enumerate(PATIENTS):
        cur = db.execute(
            "INSERT INTO patients (full_name,dob,gender,phone,address_enc,allergies_enc,diagnosis_enc,history_enc,"
            "created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (name, dob, gender, phone, c.encrypt(f"{i + 1} Example Street, Sample Nagar"), c.encrypt(allergies),
             c.encrypt(diagnosis), c.encrypt("Synthetic history generated for the SafeHealth lab."),
             ids["ravi"], now, now))
        pid = cur.lastrowid
        doctor = "arjun" if i in (3, 4, 5) else "meera"      # Dr. Meera has enough patients for the mass-access demo
        nurse = "anita" if i % 2 == 0 else "kavya"
        db.execute("INSERT INTO assignments VALUES (?,?)", (pid, ids[doctor]))
        db.execute("INSERT INTO assignments VALUES (?,?)", (pid, ids[nurse]))
        if i < 6:
            db.execute("INSERT INTO appointments (patient_id,doctor_id,scheduled_at,note,created_by,created_at)"
                       " VALUES (?,?,?,?,?,?)", (pid, ids[doctor], f"2026-12-{i + 1:02d}T10:30", "Follow-up", ids["ravi"], now))
            db.execute("INSERT INTO vitals (patient_id,recorded_by,recorded_at,temperature,pulse,bp_sys,bp_dia,spo2,notes_enc)"
                       " VALUES (?,?,?,?,?,?,?,?,?)", (pid, ids[nurse], now, 36.8, 72 + i, 120, 80, 98, c.encrypt("Stable.")))
            db.execute("INSERT INTO prescriptions (patient_id,doctor_id,created_at,body_enc) VALUES (?,?,?,?)",
                       (pid, ids[doctor], now, c.encrypt(json.dumps(
                           {"drug": "Placebo 10 mg", "dosage": "1 tablet daily", "instructions": "Synthetic entry."}))))
    db.commit()
    out = Path(current_app.config["INSTANCE"]) / "demo_credentials.txt"
    lines = ["SafeHealth demo accounts (generated at seed time; lab use only; this file is git-ignored)", ""]
    lines += [f"{u:<8} {r:<13} {p}" for u, r, p in credentials]
    out.write_text("\n".join(lines) + "\n")
    return credentials, out
