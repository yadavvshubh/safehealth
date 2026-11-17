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
nmap -sV -p- 192.168.56.10                       # full TCP port + service scan
nmap --script http-headers,http-methods -p 5444 192.168.56.10
nmap --script ssl-enum-ciphers -p 5443 192.168.56.10
```
**Screenshot:** the open-ports table for each build. Expected: only the intended app port reachable;
TLS ciphers listed for 5443; nothing for 5444 (plain HTTP).

## 3. SQLmap — SQL injection

Log in once in the browser, copy the `Cookie` header, then:

```bash
# Baseline login (expect: injectable, dumps the users table)
sqlmap -u "http://192.168.56.10:5444/login" --data="username=x&password=x" \
       --batch --risk=3 --level=5 --dump -T users

# Baseline search (expect: UNION injection)
sqlmap -u "http://192.168.56.10:5444/patients/?q=x" --cookie="sh_session=PASTE" --batch --dbs

# Hardened, same two targets (expect: not injectable)
sqlmap -u "https://192.168.56.10:5443/login" --data="username=x&password=x" --batch --risk=3 --level=5
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

> Burp Community limits Intruder speed. For heavier brute-force use ZAP's fuzzer or `hydra`:
> ```bash
> hydra -l anita -P rockyou-top100.txt 192.168.56.10 http-post-form \
>   "/login:csrf_token=^CSRF^&username=^USER^&password=^PASS^:Invalid"
> ```
> (The hardened build needs a fresh CSRF token per request, which is itself a finding to note.)

## 5. OWASP ZAP — headers and automated scan

```bash
# Baseline
zap-cli quick-scan --self-contained http://192.168.56.10:5444
# or use the ZAP desktop: Automated Scan on each target
nikto -h http://192.168.56.10:5444
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
