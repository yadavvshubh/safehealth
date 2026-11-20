# Kali VAPT run — 2026-11-20

Lab only. Kali `192.168.56.101` → both builds on the VirtualBox host-only address `192.168.56.1`:
hardened `https://…:5443`, deliberately-vulnerable baseline `http://…:5444`. No internet, no DNS.
Driven by `vapt/kali_run.sh` plus two direct proof scripts; app code unchanged.

## Headline result

| Attack | Baseline | Hardened | Evidence |
|---|---|---|---|
| SQLi login bypass (`' OR '1'='1' --` as username) | **HTTP 302 — logged in with no password** | HTTP 401 — treated as a wrong username | `login_injection_proof.txt` |
| SQLi in login (lone `'`) | **HTTP 500 — query breaks** | HTTP 401 | `login_injection_proof.txt`, `sqlmap_baseline_login.txt` |
| SQLi in patient search (receptionist) | **`'`→500, `' OR '1'='1`→full-table page (3853 B vs 1466 B)** | parameterised | `search_injection_proof.txt` |
| Brute force, no lockout | **101 logins tried, none blocked, password found** | locks out + rate-limits (see `live_attack.py`) | `brute_baseline.txt` |
| Security headers | none | CSP, HSTS, XFO=DENY, nosniff, Referrer/Permissions-Policy, `__Host-` cookie Secure+HttpOnly+SameSite | `headers_*.txt`, `nikto_*` |
| TLS | plain HTTP | HTTPS only | `nmap_*`, `headers_*` |

## Files

- `run.log` — step timeline.
- `nmap_ports.txt` — full TCP sweep of the host-only address. Besides the two apps (5443, 5444) it
  lists the Windows **host's** own services: MySQL 3306/33060 and Delivery-Optimization 7680. Those
  are the lab host, not SafeHealth — ignore them for the app assessment.
- `nmap_app_ports.txt`, `nmap_http_baseline.txt`, `nmap_https_hardened.txt` — service/version, HTTP
  methods/headers, and the hardened TLS cipher enumeration.
- `headers_baseline.txt` vs `headers_hardened.txt` — the clearest single comparison.
- `sqlmap_baseline_login.txt` — sqlmap confirms the baseline login is injectable (boolean + time-based
  blind, SQLite).
- `sqlmap_baseline_search.txt` — sqlmap at default level **missed** the search injection (it only saw
  HTTP 500s and gave up). `search_injection_proof.txt` proves it directly instead.
- `sqlmap_hardened_login.txt` — **inconclusive by design.** This run sqlmap could not complete the TLS
  handshake against the single-thread dev server ("can't establish SSL connection"); on other runs its
  probes came back HTTP 400 from the per-request anti-CSRF check and it reported "parameters do not
  appear to be injectable". Either way sqlmap cannot cleanly test a login behind a fresh-token-per-request
  CSRF guard. The hardened login's safety is shown directly by `login_injection_proof.txt` (identical 401
  for an injection payload and for a normal wrong password, versus the baseline's 302 bypass).
- `search_injection_proof.txt`, `login_injection_proof.txt` — the direct curl proofs above.
- `brute_baseline.txt` — 100 rockyou passwords + the real one planted last; the baseline answers every
  attempt (no lockout, no 429) and the planted password returns 302.
- `nikto_baseline.txt.txt`, `nikto_hardened.txt.txt` — baseline flags the missing headers and the
  non-HttpOnly cookie; hardened shows only the self-signed lab-cert name mismatch and the Python version.

## Tooling fixes made during this run

- **sqlmap false positive (serious):** all sqlmap runs share one `--output-dir`, so the hardened login
  replayed the baseline's cached injection point and was wrongly reported injectable. Fixed with
  `--flush-session` on every sqlmap call in `kali_run.sh`.
- **sqlmap baseline login hung:** `--dump -T users` fell back to a time-based blind extraction that
  crawls for hours (the login's 302/401/200 answers confuse the oracle). Dropped the dump — confirming
  the injection is the evidence; the bypass it enables is shown by `login_injection_proof.sh`.
- **hydra unusable:** the baseline answers a failed login with HTTP 401, which hydra's `http-post-form`
  misreads as HTTP auth, producing ~8 MB of errors and zero results. Replaced with a plain curl loop
  (`brute_baseline.txt`).
- **baseline search:** sqlmap missed it at default level; added `search_injection_proof.sh`.
