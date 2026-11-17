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
- Ransomware drill: detect ~0.008 s, restore ~0.003 s, chain intact (see docs/RUNBOOKS.md).

## Still owned by the team (not code)
- Kali VAPT screenshots (Nmap, SQLmap, Burp, ZAP) — see docs/KALI_TEST_PLAN.md.
- Report chapters marked [To add] — literature review and personal analysis.
- Drill re-run on the lab VM; replace container timings with VM numbers in docs/RUNBOOKS.md.

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

Notes: checks F05/F06 in the comparison were answered by the rate limit before the lockout (the
live checks cover the lockout). OWASP ZAP is not installed on the Kali VM and the lab is offline,
so nikto covers the header scan. A full `nmap -p-` over the host-only adapter takes hours, so
`vapt/kali_run.sh` scans the top 1000 ports plus 5443/5444. The Kali CLI tool logs (nmap, sqlmap,
nikto, hydra) and the ransomware drill on the lab VM are still to be added.
