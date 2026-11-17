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
