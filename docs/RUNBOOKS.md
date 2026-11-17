# Incident playbook and restore runbook

Drafts for WBS 7.2. Fill in names, phone numbers and your measured drill timings.

## Incident playbook

| Step | What to do | Who |
|---|---|---|
| 1. Triage | Open **Security** dashboard. Note alert rule, severity, user, IP, time. Is it still happening? | Security officer |
| 2. Contain | **Staff accounts** → *End sessions* / *Deactivate* the affected account. For ransomware signs: disconnect the host from the network. Do not switch it off. | Admin |
| 3. Investigate | **Audit log** → filter by user, IP or patient ID. Run `python manage.py verify-audit`. Copy `instance/safehealth.db` to separate media as evidence before changing anything. | Security officer |
| 4. Eradicate | Reset the user's password and MFA. Patch the weakness. Rotate keys if the key folder may have been read. | Admin + developer |
| 5. Recover | Follow the restore runbook below. | Admin |
| 6. Notify | If personal data was exposed: Data Protection Board and affected patients (DPDP Rules — detailed report within 72 hours) and CERT-In (2022 directions — 6 hours). *Deadlines as cited in the project proposal §2.4; verify against the original texts.* | Clinic owner |
| 7. Learn | Add the finding to the vulnerability register; tune the detection thresholds; add a regression test. | Both |

### What each alert means

| Alert | First action |
|---|---|
| brute_force | Account is already locked for 15 min. Check the source IP in the audit log; unlock only after speaking to the staff member. |
| mass_record_access | Ask the user why. If unexplained: end sessions, deactivate, review every `patient.view` by that user. |
| privilege_violation | One hit is usually a mis-click. High (3+) means someone is exploring: end sessions and investigate. |
| suspicious_login | Confirm with the staff member that it was them. If not: end sessions, reset password and MFA. |
| repeated_authz_failures | Typical of ID tampering (IDOR probing). Review the paths in the audit detail. |
| ransomware_file_integrity | Go straight to step 2 (isolate) and the restore runbook. |

## Restore runbook

1. Stop the server (Ctrl+C).
2. Confirm the keys are available: `instance/keys/field.key` and `backup.key` (or your `SAFEHEALTH_KEY_DIR`).
   **Without `backup.key` the backups cannot be opened, and without `field.key` the clinical fields cannot be read —
   keep a copy of both keys offline, separate from the backups.**
3. Restore: `python manage.py restore --yes` (latest) or `--file <path to .db.enc>` for the offline copy.
   The command checks the checksum, decrypts, runs SQLite's integrity check and verifies the audit chain
   *before* replacing anything. The old database is moved to `instance/quarantine/` as evidence.
4. Start the server. All sessions were cleared; staff sign in again.
5. Reset passwords and MFA for affected accounts. Re-enter work done since the backup from paper notes.
6. Record: time detected, time restored, data lost.

### Drill results (fill in)

Targets: RTO (restore time) <= 30 min; RPO (data-loss window) <= 24 h. The drill
scrambles 30 dummy files, raises the file-integrity alert, destroys the live lab
database and restores it from the last encrypted backup. Figures below are from the
lab instance (synthetic data) and will be larger on a full clinic database.

| Run | Date | Seconds to alert | Restore time | Data-loss window | Targets met? |
|---|---|---|---|---|---|
| 1 | 2026-11-16 | 0.008 s | 0.004 s | 0.013 s | Yes (both) |
| 2 | 2026-11-16 | 0.008 s | 0.003 s | 0.013 s | Yes (both) |
| 3 | 2026-11-16 | 0.008 s | 0.003 s | 0.014 s | Yes (both) |

- **Seconds to alert**: time from the simulated ransomware scrambling the files to the
  High `ransomware_file_integrity` alert being raised. All 30 of 30 files were flagged.
- **Restore time (RTO)**: time to verify the backup checksum, decrypt, pass the SQLite
  integrity check, verify the audit chain and swap the database back in. Far under the
  30-minute target because the lab database is small.
- **Data-loss window (RPO)**: in the drill this is the few milliseconds between the
  backup and the simulated attack. **In a real deployment it equals the backup
  interval** - with the recommended daily backup that is up to 24 hours, which meets the
  RPO target. Run `python manage.py backup` more often to shrink it.
- **Audit chain after restore**: verified intact on every run.

Re-run these on the lab VM with `python manage.py drill --yes` and replace the figures
with your own; the report should use the VM numbers, not these container numbers.
