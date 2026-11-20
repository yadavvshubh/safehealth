# SafeHealth v1.0 — frozen for submission (2026-11-16)

This is the version to submit and demo. Freeze it here: make no further code changes
except fixes forced by Kali testing, and record any such fix below.

## What is complete and verified
- Clinic app: patients, records, vitals, prescriptions, appointments, staff accounts (4 roles).
- Security layer SR1–SR12 (see docs/CONTROL_MAPPING.md).
- Detection engine (5 rules + file-integrity), hash-chained audit log, SOC dashboard.
- Encrypted backup, verified restore, ransomware drill.

## Test evidence
- 138/138 automated tests pass (GitHub Actions, real libraries).
- 68/68 live attack checks pass against the HTTPS server (script: vapt/live_attack.py).
- Baseline vs hardened: 19/19 vulnerable → 0/19 (see vapt/).
- Security score: 0.3/10 → 9.3/10 (**self-assessed** by the team; the baseline was built to be weak, so treat the Kali results as the independent evidence).
- Ransomware drill on the lab host: detect ~0.46 s, restore ~0.07 s, 30/30 files flagged, chain intact (see docs/RUNBOOKS.md).

## Still owned by the team (not code)
- Kali VAPT screenshots (Nmap, SQLmap, Burp, ZAP) — see docs/KALI_TEST_PLAN.md.
- Report chapters marked [To add] — literature review and personal analysis.

## Fixes after freeze (log them here)
| Date | What Kali found | Fix | Retest |
|---|---|---|---|
| | | | |

## v1.1 — UI restyle only (2026-11-17)
Cosmetic change after the v1.0 freeze. No Python, template, route or security-logic change.

| Date | Change | Files | Retest |
|---|---|---|---|
| 2026-11-17 | Restyled the UI to an Apple-style design language (single blue accent, pill buttons, hairlines, no shadows). | safehealth/static/style.css | 138/138 tests pass; all 16 screens checked visually |
| 2026-11-17 | Fixed restyle defects: invalid `font` shorthand on buttons/inputs, secondary buttons that looked like links, low-contrast status and muted text (now WCAG AA, >= 4.5:1), unreadable Log out button. | safehealth/static/style.css | Same as above |
| 2026-11-17 | Added the live attack script so the 68 checks can be reproduced. | vapt/live_attack.py | Not re-run after the restyle (CSS only) |

To submit the original teal UI instead, restore style.css from the v1.0 commit on GitHub.

## Kali lab run (2026-11-17)
First run from the Kali VM (VirtualBox, host-only network 192.168.56.0/24, no internet). Kali at
192.168.56.101; both builds listening only on the host-only address 192.168.56.1. No application
code changed. Evidence is in `vapt/kali/` (screenshots taken inside Kali, demo page `demo.html`).

| Test | Baseline | Hardened |
|---|---|---|
| `compare_builds.py`, 19 paired attacks over the lab network | 19/19 vulnerable | 0/19 vulnerable |
| `live_attack.py`, 68 checks | - | 68/68 pass |
| `pytest` | - | 138/138 pass |
| Browser demo in Kali Firefox: SQLi login, stored XSS, UNION search, IDOR, MFA, dashboard | attacks succeed | blocked; alerts raised |

Fixes to the **test scripts** (not the app), found by this run:

| Date | What the run found | Fix | Retest |
|---|---|---|---|
| 2026-11-17 | The hardened login limit (10/min per IP) answered the scripts' own logins with 429, so 6 of 19 comparison checks and 18 live checks ran logged out. | `compare_builds.py`, `live_attack.py`: on 429 wait 61 s and retry once. | 0/19, 68/68 |
| 2026-11-17 | The "correct password refused while locked" check got the rate limiter's 429, not the lockout's 401. | `live_attack.py` waits out the limit first, so the lockout itself is tested. | Pass (401) |
| 2026-11-17 | nmap stalled on reverse DNS lookups: the lab has no DNS server. | `-n -Pn` on every nmap call (`kali_run.sh`, `kali_vapt.py`, test plan); `kali_run.sh` back to a full `-p-` sweep. | Not yet re-run on Kali |
| 2026-11-17 | sqlmap stops at the first HTTP 401, and a failed login answers 401, so a login injection test would end at once and prove nothing. | `--ignore-code=401` on both login runs (`kali_run.sh`, `kali_vapt.py`, test plan). | Not yet re-run on Kali |
| 2026-11-17 | `kali_run.sh` tested the baseline search as a doctor, whose query is safe; only the receptionist's search is injectable. The hardened login run had no CSRF URL or delay, so 400/429 answers would have read as "not injectable". | Defaults to `ravi`, checks the login really succeeded (302), `--tables` not `--dbs` (SQLite); hardened run uses `--csrf-url` and `--delay=7`. | Not yet re-run on Kali |

Notes: checks F05/F06 in the comparison were answered by the rate limit before the lockout (the
live checks cover the lockout). OWASP ZAP is not installed on the Kali VM and the lab is offline,
so nikto covers the header scan. The full `nmap -p-` sweep was slow because nmap waited on
reverse DNS; `vapt/kali_run.sh` now passes `-n` and scans every port. The ransomware drill was re-run
on the lab host on 2026-11-21 (docs/RUNBOOKS.md).

## Kali lab run (2026-11-20)

Second run from the Kali VM, re-running `vapt/kali_run.sh` with the 2026-11-17 fixes. The CLI tool logs
(nmap, sqlmap, nikto, the brute-force loop) and a `summary.md` are now in
`vapt/kali/evidence-2026-11-20/`, so the "CLI tool logs still to be added" item is closed. Headline
evidence: the baseline login is bypassed with `' OR '1'='1' --` (HTTP 302, no password) while the
hardened build answers the same input with 401; full table in the summary. App code unchanged.

This run exposed three more faults in the **test scripts** (not the app), now fixed:

| What the run found | Fix | Retest |
|---|---|---|
| All sqlmap runs shared one `--output-dir`, so the hardened login **replayed the baseline's cached injection** and was wrongly reported injectable — a false positive on the hardened build. | `--flush-session` on every sqlmap call in `kali_run.sh`. | Hardened now tests fresh (and is not injectable). |
| The baseline-login sqlmap `--dump -T users` fell back to a time-based blind dump that crawls for hours (the login's 302/401/200 answers confuse the oracle). | Dropped `--dump`; the step now just confirms the injection. The bypass it enables is proved directly by `vapt/login_injection_proof.sh`. | Confirms in ~1 min. |
| `hydra http-post-form` misreads the baseline's 401-on-failed-login as HTTP auth and wrote ~8 MB of errors, 0 results. | Replaced the hydra step with a plain curl loop (`brute_baseline.txt`): 101 attempts, none blocked, planted password found. | Pass. |

Also: sqlmap at default level **missed** the baseline receptionist search (it only saw HTTP 500s and
gave up), so `vapt/search_injection_proof.sh` proves it directly (lone quote → 500, tautology → full
table). sqlmap cannot cleanly test the hardened login behind a per-request CSRF token (400s / flaky
dev-server TLS); `vapt/login_injection_proof.sh` is the authoritative hardened check instead. The full
`nmap -p-` sweep also lists the Windows host's own ports (MySQL 3306/33060, Delivery-Optimization 7680),
which are the lab host, not SafeHealth.
