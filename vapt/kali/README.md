# Kali VAPT kit

One command runs the Kali-side tests from `docs/KALI_TEST_PLAN.md` against **both** lab builds and
packs every log into one archive for the report. Lab use only: it refuses public IP addresses.

## Run it

1. **Windows host:** double-click `start_lab_for_kali.bat` in the project root. It starts the hardened
   build (https, 5443) and the vulnerable baseline (http, 5444) on the VirtualBox host-only address,
   checks that they answer, and opens both `demo_credentials.txt` files.
2. **Kali VM:**

   ```bash
   git clone https://github.com/yadavvshubh/safehealth.git     # or: cd safehealth && git pull
   python3 safehealth/vapt/kali/kali_vapt.py \
       --baseline http://192.168.56.1:5444 --hardened https://192.168.56.1:5443
   ```

   Type the passwords it asks for, then `YES`. Add `--quick` for a 15-minute run.
3. Send back `~/safehealth-vapt/<timestamp>.tar.gz` (shared folder, or attach it in the chat).

## What it tests

| Area | Checks | Tools |
|---|---|---|
| Transport | HTTPS only, weak TLS protocols | sslscan / testssl, nmap `ssl-enum-ciphers` |
| Headers | CSP, framing, nosniff, Referrer-Policy, no-store, HSTS | built-in, nmap `http-security-headers` |
| Session | HttpOnly / Secure / SameSite cookie, replay after logout | built-in |
| Authentication | user enumeration, lockout, rate limit, MFA | built-in |
| Injection | login bypass, search UNION, stored and reflected XSS | built-in, sqlmap (login + authenticated search) |
| Access control | admin pages as a doctor, IDOR across patient IDs 1-30 | built-in |
| CSRF | login and password-change forms without a token | built-in |
| Exposure | open ports, service banner, DB/key/source files | nmap, whatweb, built-in |
| Scanners | generic web findings, hidden paths | nikto, gobuster / ffuf, OWASP ZAP |
| Detection | brute-force, privilege and IDOR alerts raised; audit chain intact | admin API after the attack |

Default accounts: `arjun` (doctor), `ravi` (receptionist: the baseline's injectable search only runs
for this role), `kavya` (brute-force victim; locked 15 min on the hardened build), `sharma` (admin).
Accounts without MFA are enrolled by the kit and their lab secrets kept in
`~/safehealth-vapt/lab_mfa_secrets.txt`; `python manage.py lab-totp USER` on the host prints a code
for browser logins either way.

## Notes

- The stored-XSS test writes a script into one patient's diagnosis and then restores the original text.
- Full run is about 1 to 1.5 hours; Ctrl+C skips the tool that is running; every tool is time-boxed.
- `summary.md` has the baseline-vs-hardened table for the report; `http_transcript.log` has every
  request and response line (passwords masked) as evidence.
