# SafeHealth

A secure healthcare information management and cyber-threat monitoring prototype for small clinics.
**Prevent → Detect → Respond → Recover.** MCA cybersecurity capstone.

> Lab prototype. Synthetic data only. Not hardened or audited for production. "HIPAA-informed" and
> "aligned with DPDP concepts" — never "compliant".

## What is in the box

| Stage | What is implemented | Where |
|---|---|---|
| Prevent | Argon2id password hashing + policy, account lockout, login rate limiting, TOTP MFA for all staff, server-side RBAC with default deny, object-level (assigned-patient) checks, Fernet field encryption with keys outside the DB, parameterised SQL only, input validation, auto-escaped output, CSRF tokens, server-side sessions with Secure/HttpOnly/SameSite cookies, security headers, HTTPS | `safehealth/passwords.py`, `mfa.py`, `rbac.py`, `crypto.py`, `sessions.py`, `validators.py`, `__init__.py` |
| Detect | Hash-chained, append-only audit log; five detection rules; file-integrity monitoring; live dashboard and audit search | `audit.py`, `detection.py`, `fim.py`, `routes/security.py` |
| Respond | Automatic lockout and session termination, alerts with evidence, admin actions (unlock, end sessions, deactivate, reset MFA), incident playbook | `detection.py`, `routes/admin.py`, `docs/RUNBOOKS.md` |
| Recover | Encrypted backups with manifest and extra/offline copies, verified restore, timed ransomware drill | `backup.py`, `manage.py` |

Clinic features: patients, medical records (history, allergies, diagnosis, vitals), appointments,
prescriptions, staff accounts — four roles (admin, doctor, nurse, receptionist) per the access matrix.

## Setup (Windows, macOS or Linux — Python 3.10+)

```
python -m venv .venv
.venv\Scripts\activate            (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
python manage.py seed             creates demo staff + synthetic patients, prints the passwords
python run.py                     https://127.0.0.1:5443
```

The browser will warn about the self-signed lab certificate — accept it. At first login each user is
asked to add SafeHealth to an authenticator app (Google/Microsoft Authenticator, Aegis…).

Demo accounts: `sharma` (admin), `meera`, `arjun` (doctors), `anita`, `kavya` (nurses), `ravi` (receptionist).
Passwords are random, generated at seed time and saved to `instance/demo_credentials.txt` (git-ignored).

To attack it from the Kali VM on the isolated lab network:
`set SAFEHEALTH_HOST=0.0.0.0` and `set SAFEHEALTH_CERT_HOSTS=<lab IP>` before the first `python run.py`.

## Tests

```
python -m pytest
```

138 tests, mapped to the proposal's success criteria:

| Success criterion | Test |
|---|---|
| Restricted requests denied: 100% | `tests/test_rbac.py::test_role_route_matrix` (24 routes × 4 roles, written from §9.3, not from the code) |
| Sensitive actions in audit log: 100% | `tests/test_audit_detection.py::test_every_sensitive_action_is_logged` |
| Rule scenarios raising the correct alert: 5 of 5 | `test_rule1_…` to `test_rule5_…` |
| Alert latency ≤ 60 s | `test_rule1_brute_force_locks_account_and_kills_sessions` |
| Restore time ≤ 30 min, data loss ≤ 24 h | `tests/test_backup.py::test_full_ransomware_drill_meets_targets` |

## Commands

```
python manage.py backup --copy-to E:\safehealth-offline     encrypted backup + offline copy
python manage.py restore --yes                              restore the latest backup
python manage.py verify-audit                               check the audit hash chain
python manage.py lab-setup                                  dummy drill files + integrity baseline
python manage.py fim-check --watch 10                       file-integrity monitor
python manage.py simulate-ransomware                        scrambles the dummy lab files only
python manage.py drill --yes                                full timed drill -> instance/drill_report.json
python manage.py lab-totp meera                             current TOTP code (lab scripting only)
```

Schedule the daily backup with Windows Task Scheduler or cron.

## Detection rules (tune in `safehealth/config.py`)

| Rule | Trigger | Severity | Automatic response |
|---|---|---|---|
| brute_force | 5 failed logins (password or TOTP) for one account in 2 min; or 10 from one IP | High | 15-minute lockout, sessions terminated, alert |
| mass_record_access | 15 different patient records opened by one user in 2 min | High | Alert, flagged for session review (`MASS_ACCESS_TERMINATE=True` also ends sessions) |
| privilege_violation | A request the user's role forbids | Medium; High at 3 in 10 min | 403, logged, alert |
| suspicious_login | Login from an IP not seen before for that user, or outside 07:00–21:00 | Medium | Alert (TOTP is always required) |
| repeated_authz_failures | 5 denied requests in 2 min | Medium | Alert |
| ransomware_file_integrity | 5+ monitored files changed/removed at once | High | Alert → restore runbook |

## Demo flow (10–15 minutes, §15.2)

1. `meera` logs in with TOTP and opens an assigned patient.
2. `ravi` (receptionist) requests `/patients/1/clinical` or `/security/audit` → 403; admin dashboard shows the alert.
3. From Kali: brute-force `anita`'s login (Burp Intruder / ZAP), then SQLmap against `/login` and `/patients/?q=`.
4. Dashboard shows the High alert; Staff accounts shows `anita` locked.
5. `python manage.py drill --yes` → file-integrity alert, restore, timings.
6. Show one finding from your vulnerability register as found → fixed → retested.

## Design decisions worth defending in the viva

- **Default deny** — a route with no declared policy returns 403 (`rbac.enforce`), tested.
- **"Assigned" patients** — a doctor joins a patient's care team when the receptionist books an appointment
  with them; the receptionist can also assign doctors/nurses on the patient page. Admins never see patient data.
- **Nurse "limited" view** — allergies, current diagnosis and vitals; no history, no prescriptions.
  Fields outside a role's scope are never decrypted, not merely hidden.
- **Sessions are server-side** — the cookie is a random ID whose SHA-256 is stored; logout and lockout delete it.
- **Audit chain** — `UNIQUE(prev_hash)` forces one linear chain; SQL triggers make it append-only;
  editing the file directly breaks the hashes, which `verify-audit` reports with the entry number.

## Known limitations (be upfront about these)

- SQLite has no database accounts, so "the app's DB account cannot alter the backup store" is not enforced
  here — use OS file permissions now, PostgreSQL roles later.
- The audit chain proves tampering inside the log; someone who steals the whole file *and* recomputes every
  hash is only caught by comparing against a backup. Keep the offline copy.
- Flask's development server and a self-signed certificate are for the lab only.
- Rule-based detection: fixed thresholds, no machine learning; expect tuning.
- Rate-limit counters are in memory and reset on restart.
- The drill's restore time is measured on a tiny synthetic database.
- Not built yet: the deliberately weak baseline build (§8.5), the security-score method (§7.3 of the WBS),
  PostgreSQL support.

All testing must target only your own lab instance, with your guide's approval.
