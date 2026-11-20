# Kali Linux test plan (VAPT)

For WBS 5.2, 5.3 and section 8.5 of the proposal. Two students, isolated lab.

> **Rules of engagement.** Test only your own two lab instances. No third-party systems. Keep the
> VMs on a host-only network with no internet route. Get your guide's written permission first and
> keep it with the report. The baseline build is deliberately vulnerable — never put it on a real network.

## 0. Lab setup

| Machine | Role | Address (example) |
|---|---|---|
| Ubuntu/Windows host | runs both SafeHealth builds | 192.168.56.10 |
| Kali Linux VM | attacker | 192.168.56.20 |

Host-only network in VirtualBox (`vboxnet0`), no NAT adapter on the Kali VM during testing.

On the host, start each build so the Kali VM can reach it:

```bash
# Hardened build (HTTPS, port 5443)
cd SafeHealth
python manage.py seed                 # note the printed passwords
set SAFEHEALTH_HOST=0.0.0.0            # Windows: set / Linux: export
set SAFEHEALTH_CERT_HOSTS=192.168.56.10
python run.py

# Weak baseline build (HTTP, port 5444) - separate terminal
cd SafeHealth-baseline
python manage.py seed
set SAFEHEALTH_HOST=192.168.56.10
set SAFEHEALTH_I_UNDERSTAND_THIS_IS_VULNERABLE=1
python run.py
```

Targets from Kali:
- Hardened: `https://192.168.56.10:5443`
- Baseline: `http://192.168.56.10:5444`

Take a VM snapshot of both before you start, so you can roll back after destructive tests.

Shortcut for the host side: double-click `start_lab_for_kali.bat`. It starts both builds on the
VirtualBox host-only address (so the baseline is not exposed to your Wi-Fi), checks they answer,
and opens both `demo_credentials.txt` files.

### 0.1 One-command run (the kit)

`vapt/kali/kali_vapt.py` runs the CLI parts of sections 2-5 against both builds, plus the
detection check, and writes a baseline-vs-hardened `summary.md` and a `.tar.gz` of all evidence:

```bash
python3 safehealth/vapt/kali/kali_vapt.py --baseline http://192.168.56.10:5444 --hardened https://192.168.56.10:5443
```

See `vapt/kali/README.md`. Still take the Burp and dashboard screenshots by hand (section 4):
the kit's logs are the evidence for the CLI tools, Burp needs the GUI.

## 1. Mapping to the proposal (section 8.5)

| Area | Tool | Run against |
|---|---|---|
| Port/exposure | Nmap | both |
| SQL injection | SQLmap, Burp | both |
| Authentication / brute force | Burp Intruder, ZAP, hydra | both |
| Broken access control / IDOR | Burp Repeater | both |
| Cross-site scripting | Burp, ZAP | both |
| Session security | Burp, browser dev tools | both |
| Headers / config | ZAP, nikto | both |

Run every test against the **baseline first** (expect it to succeed) and then the **hardened build**
(expect it to fail). That pairing is your before/after evidence.

## 2. Nmap — exposure

```bash
# -n -Pn: the isolated lab has no DNS server; without -n nmap stalls on reverse lookups
nmap -n -Pn -sV -p- 192.168.56.10                 # full TCP port + service scan
nmap -n -Pn --script http-headers,http-methods -p 5444 192.168.56.10
nmap -n -Pn --script ssl-enum-ciphers -p 5443 192.168.56.10
```
**Screenshot:** the open-ports table for each build. Expected: only the intended app port reachable;
TLS ciphers listed for 5443; nothing for 5444 (plain HTTP).

## 3. SQLmap — SQL injection

Log in once in the browser, copy the `Cookie` header, then:

```bash
# Both builds answer a failed login with HTTP 401, which makes sqlmap stop unless told
# --ignore-code=401. Without it every login run below ends at once and proves nothing.

# --flush-session on every run: they share one output dir, so without it a later target replays an
# earlier target's cached injection point (a false positive on the hardened build).

# Baseline login (expect: injectable). No --dump: the login's 302/401/200 answers confuse sqlmap's
# oracle, so it falls back to a time-based blind dump that crawls for hours. Confirming the injection
# is enough; the auth bypass it enables is proved directly by vapt/login_injection_proof.sh.
sqlmap -u "http://192.168.56.10:5444/login" --data="username=x&password=x" -p username \
       --ignore-code=401 --flush-session --batch --risk=3 --level=5

# Baseline search (expect: injectable). Log in as the RECEPTIONIST (ravi): the baseline only builds
# the search SQL by string formatting for that role; doctors use a safe query. sqlmap at default level
# can still miss it (it only sees the HTTP 500s), so vapt/search_injection_proof.sh proves it directly.
sqlmap -u "http://192.168.56.10:5444/patients/?q=x" --cookie="sh_session=PASTE" --flush-session --batch --tables

# Hardened login (expect: not injectable). Without --csrf-token every request is refused with 400,
# and without --delay the 10-per-minute login limit answers 429 - either would make
# "not injectable" meaningless. The cookie on this build is __Host-sh_session. In practice the CSRF
# token (400s) and the single-thread dev-server TLS make sqlmap inconclusive here; the authoritative
# hardened check is vapt/login_injection_proof.sh (injection payload answered with 401, like a wrong password).
sqlmap -u "https://192.168.56.10:5443/login" --data="csrf_token=x&username=x&password=x" -p username \
       --csrf-token=csrf_token --csrf-url="https://192.168.56.10:5443/login" --ignore-code=401 --delay=7 --flush-session --batch

# Hardened search as ravi (expect: not injectable). Paste the __Host-sh_session value.
sqlmap -u "https://192.168.56.10:5443/patients/?q=x" -p q --cookie="__Host-sh_session=PASTE" \
       --delay=0.25 --level=2 --batch
```
**Screenshot:** on the baseline, the dumped `users` table and "parameter is injectable"; on the
hardened build, "all tested parameters do not appear to be injectable".

## 4. Burp Suite — brute force, IDOR, XSS, sessions

Set Kali's browser proxy to Burp (127.0.0.1:8080), import Burp's CA for the HTTPS target.

- **Brute force (Intruder).** Capture a `POST /login`, mark the password, load a small wordlist.
  - Baseline: every request returns 302/200 — no limit.
  - Hardened: account locks after 5, and the **Security dashboard shows a High `brute_force` alert**. Screenshot both the Intruder results and the dashboard.
- **IDOR (Repeater).** Log in as a doctor, open one of your patients, then change the ID in
  `GET /patients/<id>` to another number.
  - Baseline: 200 with another patient's record. Hardened: 403.
- **XSS.** In a patient's diagnosis/notes field submit `<script>alert(document.domain)</script>`, then reload the page.
  - Baseline: alert fires. Hardened: shown as text; the CSP header blocks inline scripts.
- **Sessions.** Compare the `Set-Cookie` on each build (Proxy > HTTP history). Log out and replay an
  old cookie in Repeater. Baseline: still works. Hardened: redirected to login.

> Burp Community limits Intruder speed. On the **baseline** a plain loop is the cleanest brute force:
> hydra's `http-post-form` misreads the baseline's 401-on-failed-login as HTTP auth and logs nothing
> useful, so `vapt/kali_run.sh` uses curl instead (a wrong password answers 401, the right one 302):
> ```bash
> while read pw; do
>   curl -s -o /dev/null -w "%{http_code} $pw\n" -d "username=ravi" --data-urlencode "password=$pw" \
>     http://192.168.56.10:5444/login
> done < rockyou-top100.txt   # none are blocked: no lockout, no rate limit on the baseline
> ```
> A fresh CSRF token per request defeats this against the **hardened** build (400s). Use Burp Intruder
> with a macro/session rule that reloads `/login` for the token, or the kit's built-in brute-force test
> (section 0.1) — the hardened account locks after 5 tries. That the CSRF token defeats naive guessing
> tools is itself a finding to note.

## 5. OWASP ZAP — headers and automated scan

```bash
# zap-cli is retired; ZAP's own command-line quick scan (spider + active scan + HTML report):
zaproxy -cmd -quickurl http://192.168.56.10:5444 -quickout ~/zap_baseline.html -quickprogress
zaproxy -cmd -quickurl https://192.168.56.10:5443 -quickout ~/zap_hardened.html -quickprogress
# or use the ZAP desktop: Automated Scan on each target
nikto -h http://192.168.56.10:5444
nikto -h https://192.168.56.10:5443
```
**Screenshot:** ZAP Alerts panel for each build. Expected on the baseline: missing CSP,
missing anti-clickjacking header, cookie without HttpOnly/Secure. Hardened: these are gone.

## 6. Ransomware drill (on the host, hardened build)

```bash
python manage.py lab-setup
python manage.py drill --yes       # saves instance/drill_report.json
```
**Screenshot:** the drill report (detection time, restore time, data-loss window) and the
`ransomware_file_integrity` High alert on the dashboard.

## 7. Recording findings

For every test, capture: the request, the response (or tool output), and — on the hardened build —
the matching dashboard alert and audit-log entry. Put each into the **Vulnerability register** tab of
the test-results spreadsheet: finding, evidence, severity, impact, remediation, retest result.

The scripted comparison in `vapt/compare_builds.py` gives you a quick baseline-vs-hardened table to
check your manual findings against; the Kali tools above are the evidence your report needs.
