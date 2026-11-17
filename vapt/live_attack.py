"""Live security test against a running SafeHealth lab server (our own instance only).

Usage: python attack.py https://127.0.0.1:5443 <instance_dir>
"""
import http.client
import json
import re
import ssl
import sqlite3
import sys
import time
import urllib.parse
from pathlib import Path

import pyotp

BASE = urllib.parse.urlparse(sys.argv[1])
INSTANCE = Path(sys.argv[2])
CTX = ssl._create_unverified_context()          # self-signed lab certificate
RESULTS = []


def check(area, name, ok, detail=""):
    RESULTS.append((area, name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  [{area}] {name}" + (f"  ({detail})" if detail else ""))


class Client:
    def __init__(self, ip_note=""):
        self.cookies = {}

    def request(self, method, path, form=None, raw_body=None, headers=None):
        conn = http.client.HTTPSConnection(BASE.hostname, BASE.port, context=CTX, timeout=30)
        hdrs = dict(headers or {})
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if raw_body is not None:
            body = raw_body
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        start = time.perf_counter()
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        resp.elapsed = time.perf_counter() - start
        resp.text = resp.read().decode("utf-8", "replace")
        for header in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0]
            if "Max-Age=0" in header or "expires=Thu, 01 Jan 1970" in header:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        conn.close()
        return resp

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, form):
        return self.request("POST", path, form=form)

    def csrf(self, path="/"):
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.get(path).text)
        return m.group(1) if m else ""


SECRETS = {}


def login(username, password):
    c = Client()
    token = c.csrf("/login")
    r = c.post("/login", {"csrf_token": token, "username": username, "password": password})
    if r.status == 429:                   # login rate limit (10/min/IP) hit by earlier checks: wait it out once
        time.sleep(61)
        r = c.post("/login", {"csrf_token": c.csrf("/login"), "username": username, "password": password})
    if r.status != 302:
        return c, r
    loc = r.headers["Location"]
    if loc.endswith("/mfa/enroll"):
        page = c.get("/mfa/enroll")
        secret = re.search(r'class="secret">([A-Z2-7 ]+)<', page.text).group(1).replace(" ", "")
        SECRETS[username] = secret
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        r = c.post("/mfa/enroll", {"csrf_token": token, "code": pyotp.TOTP(secret).now()})
    else:
        token = c.csrf("/mfa")
        r = c.post("/mfa", {"csrf_token": token, "code": pyotp.TOTP(SECRETS[username]).now()})
    return c, r


creds = {}
for line in (INSTANCE / "demo_credentials.txt").read_text().splitlines()[2:]:
    user, _role, pw = line.split()
    creds[user] = pw

db = lambda: sqlite3.connect(INSTANCE / "safehealth.db")
count = lambda sql, *p: db().execute(sql, p).fetchone()[0]

# ---------------------------------------------------------------- 1. unauthenticated
anon = Client()
for path in ("/", "/patients/1", "/security/", "/admin/users", "/security/api/summary"):
    r = anon.get(path)
    check("Access", f"anonymous GET {path} -> login", r.status == 302 and r.headers["Location"].endswith("/login"), str(r.status))

# ---------------------------------------------------------------- 2. MFA login
pre = Client()
tok = pre.csrf("/login")
r = pre.post("/login", {"csrf_token": tok, "username": "meera", "password": creds["meera"]})
check("Auth", "correct password alone does not grant access", pre.get("/patients/1").status == 302)
meera, r = login("meera", creds["meera"])
check("Auth", "doctor logs in with password + TOTP (first-login enrolment)", r.status == 302 and meera.get("/patients/1").status == 200)
page = meera.get("/patients/1").text
check("RBAC", "doctor sees diagnosis and prescriptions of assigned patient", "Clinical record" in page and "Prescriptions" in page)

replay = Client()
tok = replay.csrf("/login")
replay.post("/login", {"csrf_token": tok, "username": "meera", "password": creds["meera"]})
tok = replay.csrf("/mfa")
used_code = pyotp.TOTP(SECRETS["meera"]).now()
r = replay.post("/mfa", {"csrf_token": tok, "code": used_code})
check("Auth", "TOTP code cannot be replayed", r.status == 401)
r = replay.post("/mfa", {"csrf_token": tok, "code": "123456"})
check("Auth", "wrong TOTP code rejected", r.status == 401)

# ---------------------------------------------------------------- 3. SQL injection
sqli = ["' OR '1'='1' -- ", "admin'--", "' UNION SELECT username,password_hash FROM users--",
        "'; DROP TABLE patients;--", "' OR SLEEP(5)--", "\" OR \"\"=\"", "meera' AND 1=1--"]
attacker = Client()
users_before, patients_before = count("SELECT COUNT(*) FROM users"), count("SELECT COUNT(*) FROM patients")
slow = 0
for p in sqli:
    tok = attacker.csrf("/login")
    r = attacker.post("/login", {"csrf_token": tok, "username": p, "password": p})
    slow = max(slow, r.elapsed)
    check("SQLi", f"login payload rejected: {p!r}", r.status == 401 and "Traceback" not in r.text and "sqlite" not in r.text.lower())
check("SQLi", "no time-based injection (max login response)", slow < 2, f"{slow:.2f}s")

ravi, r = login("ravi", creds["ravi"])
for p in ["' OR 1=1 --", "%' UNION SELECT password_hash,2,3,4 FROM users --", "x'; DROP TABLE patients; --"]:
    r = ravi.get("/patients/?" + urllib.parse.urlencode({"q": p}))
    check("SQLi", f"search payload harmless: {p!r}", r.status == 200 and "$argon2" not in r.text and "$stub$" not in r.text and "Test Patient Alpha" not in r.text)
check("SQLi", "database intact after injection attempts",
      count("SELECT COUNT(*) FROM users") == users_before and count("SELECT COUNT(*) FROM patients") == patients_before)

# ---------------------------------------------------------------- 4. Broken access control
for method, path in (("GET", "/security/"), ("GET", "/admin/users"), ("POST", "/patients/1/clinical")):
    form = {"csrf_token": ravi.csrf(), "diagnosis": "hacked"} if method == "POST" else None
    r = ravi.request(method, path, form=form)
    check("RBAC", f"receptionist {method} {path} -> 403", r.status == 403)
recep_page = ravi.get("/patients/1").text
check("RBAC", "receptionist cannot see diagnosis/allergies", "Type 2 diabetes" not in recep_page and "Penicillin" not in recep_page and "Test Patient Alpha" in recep_page)

anita, r = login("anita", creds["anita"])
nurse_page = anita.get("/patients/1").text
check("RBAC", "nurse sees diagnosis but not history/prescriptions",
      "Type 2 diabetes" in nurse_page and "Synthetic history" not in nurse_page and "Add prescription" not in nurse_page)
r = anita.post("/patients/1/prescriptions", {"csrf_token": anita.csrf(), "drug": "x", "dosage": "y"})
check("RBAC", "nurse cannot add prescriptions", r.status == 403)

sharma, r = login("sharma", creds["sharma"])
check("RBAC", "admin cannot open patient records", sharma.get("/patients/1").status == 403)

arjun, r = login("arjun", creds["arjun"])
own = arjun.get("/patients/4").status
idor = [arjun.get(f"/patients/{pid}").status for pid in (1, 2, 3, 7, 8)]
check("IDOR", "doctor can open own patient", own == 200)
check("IDOR", "doctor changing patient ID in URL gets 403 (5 tries)", all(s == 403 for s in idor), str(idor))
check("IDOR", "non-existent ID gives same 403 (no enumeration)", arjun.get("/patients/99999").status == 403)
r = arjun.post("/patients/1/prescriptions", {"csrf_token": arjun.csrf(), "drug": "evil", "dosage": "1"})
check("IDOR", "cannot write prescription to someone else's patient", r.status == 403 and count("SELECT COUNT(*) FROM prescriptions WHERE patient_id=1 AND doctor_id=(SELECT id FROM users WHERE username='arjun')") == 0)

# ---------------------------------------------------------------- 5. XSS
payload = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
meera.post("/patients/1/clinical", {"csrf_token": meera.csrf(), "allergies": "Penicillin", "diagnosis": payload, "history": "ok"})
meera.post("/patients/1/vitals", {"csrf_token": meera.csrf(), "pulse": "72", "notes": payload})
page = meera.get("/patients/1").text
check("XSS", "stored payload in diagnosis/vitals is HTML-encoded", "<script>alert" not in page and "&lt;script&gt;alert" in page)
r = ravi.post("/patients/new", {"csrf_token": ravi.csrf(), "full_name": "Test Patient Xss", "dob": "1990-01-01",
                                "gender": "Other", "phone": "+91 90000 99999", "address": payload})
pid = r.headers.get("Location", "/0").rsplit("/", 1)[1]
page = ravi.get(f"/patients/{pid}").text
check("XSS", "payload in address field is encoded", "<img src=x" not in page and "&lt;img" in page)
r = ravi.post("/patients/new", {"csrf_token": ravi.csrf(), "full_name": payload, "dob": "1990-01-01", "gender": "Other", "phone": "+91 90000 99998"})
check("XSS", "payload in name field rejected by validation", r.status == 400 and "<script>alert" not in r.text)
csp = meera.get("/patients/1").headers.get("Content-Security-Policy", "")
check("XSS", "CSP blocks inline scripts", "script-src 'self'" in csp and "unsafe-inline" not in csp)

# ---------------------------------------------------------------- 6. CSRF + sessions
r = meera.post("/patients/1/clinical", {"diagnosis": "forged"})
check("CSRF", "POST without CSRF token -> 400", r.status == 400)
r = meera.post("/patients/1/clinical", {"csrf_token": ravi.csrf(), "diagnosis": "forged"})
check("CSRF", "another user's CSRF token rejected", r.status == 400)
check("CSRF", "forged write did not change data", "forged" not in meera.get("/patients/1").text)

r = anon.get("/login")
cookie = r.headers.get("Set-Cookie", "")
check("Session", "cookie has __Host- prefix, Secure, HttpOnly, SameSite=Strict",
      cookie.startswith("__Host-") and all(f in cookie for f in ("Secure", "HttpOnly", "SameSite=Strict")), cookie[:30] + "...")

stolen = dict(ravi.cookies)
ravi.post("/logout", {"csrf_token": ravi.csrf()})
thief = Client()
thief.cookies = stolen
r = thief.get("/patients/")
check("Session", "cookie reused after logout is rejected", r.status == 302)
fix = Client()
fix.get("/login")
before = dict(fix.cookies)
tok = fix.csrf("/login")
fix.post("/login", {"csrf_token": tok, "username": "kavya", "password": creds["kavya"]})
check("Session", "session ID changes after password step (no fixation)", fix.cookies != before)

# ---------------------------------------------------------------- 7. Brute force / lockout
bf = Client()
for i in range(5):
    tok = bf.csrf("/login")
    r = bf.post("/login", {"csrf_token": tok, "username": "anita", "password": f"Guess-{i}-Wrong"})
check("Brute force", "anita locked after 5 failures", count("SELECT locked_until FROM users WHERE username='anita'") > time.time())
check("Brute force", "anita's live session killed by lockout", anita.get("/patients/").status == 302)
time.sleep(61)                            # let the 10/min IP rate limit reset so we test the lockout, not the limiter
tok = bf.csrf("/login")
r = bf.post("/login", {"csrf_token": tok, "username": "anita", "password": creds["anita"]})
check("Brute force", "correct password refused while locked", r.status == 401, str(r.status))
r1 = bf.post("/login", {"csrf_token": bf.csrf("/login"), "username": "anita", "password": "x"})
r2 = bf.post("/login", {"csrf_token": bf.csrf("/login"), "username": "no_such_user", "password": "x"})
strip = lambda t: re.sub(r'value="[^"]+"', "", t)
check("Brute force", "same error for locked, wrong and unknown user", strip(r1.text) == strip(r2.text))

# ---------------------------------------------------------------- 8. Mass record access
for pid in (1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18):
    meera.get(f"/patients/{pid}")

# ---------------------------------------------------------------- 9. Misc hardening
h = meera.get("/").headers
for name, want in (("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                   ("Cache-Control", "no-store"), ("Strict-Transport-Security", "max-age")):
    check("Headers", f"{name} present", want in h.get(name, ""), h.get(name, "missing"))
check("Headers", "server does not reveal stack traces", "Traceback" not in meera.get("/patients/abc").text)
r = Client().request("POST", "/login", raw_body="a=" + "x" * 100_000)
check("Hardening", "oversized request body refused (413)", r.status == 413, str(r.status))

# ---------------------------------------------------------------- 10. Detection results on the dashboard
summary = json.loads(sharma.get("/security/api/summary").text)
rules = {a["rule"]: a for a in summary["alerts"]}
for rule, sev in (("brute_force", "High"), ("privilege_violation", "High"), ("repeated_authz_failures", "Medium"),
                  ("mass_record_access", "High")):
    check("Detection", f"{rule} alert raised ({sev})", rule in rules and rules[rule]["severity"] == sev,
          rules[rule]["summary"] if rule in rules else "no alert")
lat = [a["created_at"] for a in db().execute("SELECT created_at FROM alerts").fetchall()] if False else None
check("Detection", "dashboard counts locked account", summary["counts"]["Locked accounts"] >= 1)
r = sharma.post("/security/verify-chain", {"csrf_token": sharma.csrf("/security/")})
flash = sharma.get("/security/").text
check("Audit", "hash chain verifies intact after the whole attack run", "Audit chain intact" in flash)
for action in ("login.failure", "access.denied", "patient.view", "clinical.update", "csrf.failure", "logout", "login.success"):
    n = count("SELECT COUNT(*) FROM audit_log WHERE action=?", action)
    check("Audit", f"'{action}' events recorded", n > 0, str(n))
check("Audit", "no plaintext diagnosis in the database file", b"Type 2 diabetes" not in (INSTANCE / "safehealth.db").read_bytes())

passed = sum(1 for r in RESULTS if r[2])
print(f"\n{passed}/{len(RESULTS)} checks passed")
(INSTANCE / "attack_results.json").write_text(json.dumps(RESULTS, indent=1))
