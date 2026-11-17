# Control mapping: requirement → code → test

Draft for WBS 7.4. The NIST CSF 2.0 function is given for each control; add the HIPAA Security Rule
and DPDP references from your literature review before submission.

| ID | Requirement | Implementation | Verified by | NIST CSF 2.0 |
|---|---|---|---|---|
| SR1 | Argon2/bcrypt hashes, password policy | `passwords.py` (argon2-cffi, Argon2id) | `test_passwords_are_hashed_not_stored`, `test_password_policy` | Protect |
| SR2 | Lockout and login rate limiting | `detection._brute_force`, `limiter.py`, `routes/auth.py` | `test_lockout_after_five_failures`, `test_rule1_*` (rate limiter itself: manual test) | Protect |
| SR3 | TOTP MFA for staff | `mfa.py`, `routes/auth.py` | `test_password_alone_is_not_enough`, `test_full_login_*`, `test_wrong_totp_*`, `test_first_login_forces_mfa_enrolment` | Protect |
| SR4 | Server-side RBAC, default deny | `rbac.py` | `test_role_route_matrix` (96 cases), `test_default_deny_*`, `test_idor_*`, `test_field_level_scope_per_role` | Protect |
| SR5 | Field encryption, keys outside DB | `crypto.py`; `*_enc` columns | `test_sensitive_fields_encrypted_at_rest`, `test_backup_key_is_separate_*` | Protect |
| SR6 | Parameterised queries only | every `db.execute(..., params)` | `test_sql_injection_in_login_*`, `test_sql_injection_in_search_*` | Protect |
| SR7 | Input validation, output encoding | `validators.py`; Jinja2 auto-escape; CSP | `test_xss_payload_is_encoded` | Protect |
| SR8 | Secure sessions | `sessions.py` | `test_logout_invalidates_*`, `test_idle_and_absolute_*`, `test_cookie_flags`, `test_csrf_token_required` | Protect |
| SR9 | Tamper-evident audit log | `audit.py`; triggers in `db.py` | `test_every_sensitive_action_is_logged`, `test_hash_chain_*`, `test_deleting_an_entry_*` | Detect |
| SR10 | Detection rules and alerts | `detection.py` | `test_rule1_*` … `test_rule5_*`, `test_dashboard_*` | Detect / Respond |
| SR11 | Encrypted backups, offline copy, tested restore | `backup.py`, `fim.py` | `tests/test_backup.py` (6 tests) | Recover |
| SR12 | HTTPS, security headers | `tls.py`, `run.py`, `_security_headers` | `test_security_headers`, `test_cookie_flags` | Protect |

## STRIDE → control

| Threat | Control | Test |
|---|---|---|
| Spoofing (stolen doctor password) | SR1–SR3 | `test_password_alone_is_not_enough` |
| Tampering (altered diagnosis, edited logs) | SR4, SR6, SR9 | `test_hash_chain_verifies_and_detects_tampering` |
| Repudiation | SR9 | `test_every_sensitive_action_is_logged` |
| Information disclosure | SR4, SR5, SR12 | `test_field_level_scope_per_role`, `test_sensitive_fields_encrypted_at_rest` |
| Denial of service (login flooding, ransomware) | SR2, SR11 | `test_full_ransomware_drill_meets_targets` |
| Elevation of privilege | SR4 | `test_role_route_matrix` |
