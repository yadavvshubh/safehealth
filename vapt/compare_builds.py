"""Before/after attack run for SafeHealth (proposal section 8.5). LAB USE ONLY - our own instances.

Runs the same 19 attacks against one build and records each as VULNERABLE or BLOCKED with evidence.

    python vapt/compare_builds.py --target http://127.0.0.1:5444  --instance ../SafeHealth-baseline/instance --label baseline
    python vapt/compare_builds.py --target https://127.0.0.1:5443 --instance instance --label hardened
    python vapt/compare_builds.py --report vapt/results_baseline.json vapt/results_hardened.json

Run it on freshly seeded instances (python manage.py seed): it changes data and locks the account 'anita'.
"""
import argparse
import hashlib
import http.client
import json
import re
import sqlite3
import ssl
import sys
import time
import urllib.parse
from pathlib import Path

import pyotp

CHECKS = []          # (id, area, title)


def check(fid, area, title):
    def deco(fn):
        CHECKS.append((fid, area, title, fn))
        return fn
    return deco


class Client:
    def __init__(self, base):
        self.base = urllib.parse.urlparse(base)
        self.cookies = {}

    def request(self, method, path, form=None, raw=None):
        cls = http.client.HTTPSConnection if self.base.scheme == "https" else http.client.HTTPConnection
        kw = {"context": ssl._create_unverified_context()} if self.base.scheme == "https" else {}
        conn = cls(self.base.hostname, self.base.port, timeout=30, **kw)
        headers, body = {}, None
        if form is not None or raw is not None:
            body = raw if raw is not None else urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.text = resp.read().decode("utf-8", "replace")
        resp.set_cookies = resp.headers.get_all("Set-Cookie") or []
        for header in resp.set_cookies:
            name, _, rest = header.partition("=")
            if "Max-Age=0" in header or "01 Jan 1970" in header:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = rest.split(";", 1)[0]
        conn.close()
        return resp

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, form):
        return self.request("POST", path, form=form)

    def token(self, path="/"):
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.get(path).text)
        return m.group(1) if m else ""


class Lab:
    def __init__(self, target, instance):
        self.target, self.instance = target, Path(instance)
        self.creds = {}
        for line in (self.instance / "demo_credentials.txt").read_text().splitlines()[2:]:
            user, _role, pw = line.split()
            self.creds[user] = pw
        self.secrets, self.last_code = {}, {}

    def db(self, sql, *params):
        conn = sqlite3.connect(self.instance / "safehealth.db")
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def password_step(self, username, password=None):
        c = Client(self.target)
        tok = c.token("/login")
        r = c.post("/login", {"csrf_token": tok, "username": username,
                              "password": self.creds.get(username, "") if password is None else password})
        return c, r

    def login(self, username):
        """Full login. Completes TOTP when the build asks for it (waits out the replay window if needed)."""
        c, r = self.password_step(username)
        if r.status != 302:
            raise RuntimeError(f"login for {username} failed ({r.status})")
        loc = r.headers["Location"]
        if loc.endswith("/mfa/enroll") or loc.endswith("/mfa"):
            page = c.get(urllib.parse.urlparse(loc).path)
            if loc.endswith("/mfa/enroll"):
                self.secrets[username] = re.search(r'class="secret">([A-Z2-7 ]+)<', page.text).group(1).replace(" ", "")
            totp = pyotp.TOTP(self.secrets[username])
            while totp.now() == self.last_code.get(username):
                time.sleep(1)
            code = totp.now()
            self.last_code[username] = code
            tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
            r = c.post(urllib.parse.urlparse(loc).path, {"csrf_token": tok, "code": code})
        return c


# ----------------------------------------------------------------------------------------- the checks
@check("F01", "SQL injection", "Login bypass with ' OR '1'='1' --")
def _(lab):
    c = Client(lab.target)
    tok = c.token("/login")
    r = c.post("/login", {"csrf_token": tok, "username": "' OR '1'='1' -- ", "password": "anything"})
    home = c.get("/") if r.status == 302 else None
    who = re.search(r"Welcome, ([^<]+)", home.text) if home is not None else None
    if who:
        return True, f"Logged in as '{who.group(1)}' without any password"
    return False, f"HTTP {r.status}; no session granted"


@check("F02", "SQL injection", "UNION injection in patient search leaks password hashes")
def _(lab):
    c = lab.login("ravi")
    payload = "%' UNION SELECT id, username, password_hash, role FROM users -- "
    r = c.get("/patients/?" + urllib.parse.urlencode({"q": payload}))
    leaked = re.findall(r">(sharma|meera|arjun|anita|kavya|ravi)</a></td><td>([^<]{12,})", r.text)
    if leaked:
        return True, f"{len(leaked)} staff accounts with hashes shown, e.g. {leaked[0][0]} -> {leaked[0][1][:16]}..."
    return False, f"HTTP {r.status}; payload treated as a plain search term"


@check("F03", "Information disclosure", "Database error text shown to the user")
def _(lab):
    c = Client(lab.target)
    tok = c.token("/login")
    r = c.post("/login", {"csrf_token": tok, "username": "'", "password": "x"})
    m = re.search(r"(Database error[^<]{0,80}|sqlite[^<]{0,60}|syntax error[^<]{0,40}|unrecognized token[^<]{0,40})", r.text, re.I)
    return (True, f"HTTP {r.status}: {m.group(1).strip()}") if m else (False, f"HTTP {r.status}; generic message only")


@check("F04", "Authentication", "Password alone gives access (no second factor)")
def _(lab):
    c, r = lab.password_step("meera")
    r2 = c.get("/patients/1")
    if r2.status == 200:
        return True, "Patient record opened after the password step only"
    return False, f"After password: redirected to {r.headers.get('Location', '?').split('/', 3)[-1]}; record request -> {r2.status}"


@check("F05", "Authentication", "No account lockout (10 wrong passwords, then the right one)")
def _(lab):
    for i in range(10):
        lab.password_step("anita", f"Wrong-Guess-{i}")
    c, r = lab.password_step("anita")
    if r.status == 302:
        return True, "Correct password still accepted after 10 failures"
    return False, f"Account locked: correct password refused (HTTP {r.status})"


@check("F06", "Authentication", "Login error reveals which usernames exist")
def _(lab):
    _c, known = lab.password_step("meera", "wrong-password-1")
    _c, unknown = lab.password_step("nobody_here", "wrong-password-1")
    msg = lambda r: (re.search(r'class="flash error">([^<]+)<', r.text) or [None, ""])[1]
    if msg(known) != msg(unknown):
        return True, f"'{msg(known)}' vs '{msg(unknown)}'"
    return False, f"Same message for both: '{msg(known)}'"


@check("F07", "Broken access control", "Receptionist opens the security dashboard and staff admin")
def _(lab):
    c = lab.login("ravi")
    a, b = c.get("/security/").status, c.get("/admin/users").status
    if 200 in (a, b):
        return True, f"/security/ -> {a}, /admin/users -> {b}"
    return False, f"/security/ -> {a}, /admin/users -> {b}"


@check("F08", "Broken access control", "IDOR: doctor opens another doctor's patient by changing the ID")
def _(lab):
    c = lab.login("arjun")
    statuses = [c.get(f"/patients/{pid}").status for pid in (1, 2, 3)]
    if 200 in statuses:
        return True, f"/patients/1,2,3 -> {statuses} (not his patients)"
    return False, f"/patients/1,2,3 -> {statuses}"


@check("F09", "Broken access control", "Receptionist can read diagnosis and allergies")
def _(lab):
    c = lab.login("ravi")
    page = c.get("/patients/1").text
    if "Type 2 diabetes" in page or "Penicillin" in page:
        return True, "Diagnosis 'Type 2 diabetes' and allergy shown to reception"
    return False, "Only name, contact and appointments shown"


@check("F10", "Cross-site scripting", "Stored XSS in the diagnosis field")
def _(lab):
    c = lab.login("meera")
    payload = "<script>alert('sh-xss')</script>"
    c.post("/patients/2/clinical", {"csrf_token": c.token("/patients/2"), "diagnosis": payload, "allergies": "", "history": ""})
    page = c.get("/patients/2").text
    if payload in page:
        return True, "Script tag rendered unescaped on the patient page"
    return False, "Payload shown as text (&lt;script&gt;)" if "&lt;script&gt;alert(&#39;sh-xss" in page or "&lt;script&gt;" in page else "Payload not rendered"


@check("F11", "CSRF", "Forged POST without CSRF token changes a diagnosis")
def _(lab):
    c = lab.login("meera")
    r = c.post("/patients/3/clinical", {"diagnosis": "CSRF-FORGED-ENTRY", "allergies": "", "history": ""})
    page = c.get("/patients/3").text
    if "CSRF-FORGED-ENTRY" in page:
        return True, f"HTTP {r.status}; record changed by a request with no token"
    return False, f"HTTP {r.status}; record unchanged"


@check("F12", "Session management", "Session cookie missing HttpOnly / Secure / SameSite")
def _(lab):
    c = Client(lab.target)
    r = c.get("/login")
    cookie = next((h for h in r.set_cookies if "session" in h.lower()), "")
    missing = [f for f in ("HttpOnly", "Secure", "SameSite") if f.lower() not in cookie.lower()]
    if missing:
        return True, "Missing: " + ", ".join(missing)
    return False, "HttpOnly, Secure, SameSite=Strict, __Host- prefix" if cookie.startswith("__Host-") else "All flags set"


@check("F13", "Session management", "Session still valid after logout (cookie replay)")
def _(lab):
    c = lab.login("kavya")
    stolen = dict(c.cookies)
    c.post("/logout", {"csrf_token": c.token("/")})
    thief = Client(lab.target)
    thief.cookies = stolen
    r = thief.get("/patients/")
    if r.status == 200:
        return True, "Old cookie still opens the patient list"
    return False, f"Old cookie rejected (HTTP {r.status} -> login)"


@check("F14", "Security misconfiguration", "Security headers missing (CSP, X-Frame-Options, nosniff)")
def _(lab):
    h = Client(lab.target).get("/login").headers
    missing = [n for n in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy") if not h.get(n)]
    return (True, "Missing: " + ", ".join(missing)) if missing else (False, "All present")


@check("F15", "Cryptographic failures", "Traffic not encrypted (no HTTPS)")
def _(lab):
    scheme = urllib.parse.urlparse(lab.target).scheme
    return (True, "Served over plain HTTP: logins and records readable on the network") if scheme == "http" \
        else (False, "HTTPS only (TLS); HSTS header set")


@check("F16", "Cryptographic failures", "Sensitive fields stored in plain text")
def _(lab):
    raw = (lab.instance / "safehealth.db").read_bytes()
    if b"Type 2 diabetes" in raw:
        return True, "Diagnosis readable directly in the database file"
    return False, "Diagnosis, allergies, history, notes, prescriptions encrypted (Fernet)"


@check("F17", "Cryptographic failures", "Weak password hashing (fast, unsalted)")
def _(lab):
    stored = lab.db("SELECT password_hash FROM users WHERE username='meera'")[0][0]
    if stored == hashlib.sha256(lab.creds["meera"].encode()).hexdigest():
        return True, "Unsalted SHA-256: identical passwords give identical hashes; GPU-crackable"
    if stored.startswith("$"):
        alg = stored.split("$")[1]
        note = " - test stand-in for Argon2id (real library not installed)" if alg == "stub" else ""
        return False, f"Salted slow hash ({alg}){note}"
    return False, "Not plain SHA-256"


@check("F18", "Logging and monitoring", "Attacks above raised no security alert")
def _(lab):
    rows = lab.db("SELECT rule, severity FROM alerts")
    if not rows:
        return True, "0 alerts after brute force, injection, IDOR and privilege attempts"
    rules = sorted({r[0] for r in rows})
    return False, f"{len(rows)} alerts: " + ", ".join(rules)


@check("F19", "Security misconfiguration", "Oversized request body accepted")
def _(lab):
    r = Client(lab.target).request("POST", "/login", raw="a=" + "x" * 200_000)
    return (True, f"200 KB body processed (HTTP {r.status})") if r.status != 413 else (False, "Refused with HTTP 413")


# ----------------------------------------------------------------------------------------- runner
def run(target, instance, label):
    lab, results = Lab(target, instance), []
    for fid, area, title, fn in CHECKS:
        try:
            vulnerable, evidence = fn(lab)
        except Exception as exc:          # a broken check is reported, never hidden
            vulnerable, evidence = None, f"check error: {exc}"
        status = {True: "VULNERABLE", False: "BLOCKED", None: "ERROR"}[vulnerable]
        results.append({"id": fid, "area": area, "title": title, "status": status, "evidence": evidence})
        print(f"{fid}  {status:<10} {title}\n      {evidence}")
    return {"label": label, "target": target, "when": time.strftime("%Y-%m-%d %H:%M:%S"), "results": results}


def report(paths):
    runs = [json.loads(Path(p).read_text()) for p in paths]
    print(f"{'ID':<4} {'Finding':<62} " + " ".join(f"{r['label']:<11}" for r in runs))
    for i, (fid, _a, title, _f) in enumerate(CHECKS):
        print(f"{fid:<4} {title[:62]:<62} " + " ".join(f"{r['results'][i]['status']:<11}" for r in runs))
    for r in runs:
        n = sum(x["status"] == "VULNERABLE" for x in r["results"])
        print(f"{r['label']}: {n}/{len(r['results'])} vulnerable")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target")
    ap.add_argument("--instance")
    ap.add_argument("--label", default="run")
    ap.add_argument("--report", nargs="+")
    args = ap.parse_args()
    if args.report:
        report(args.report)
        sys.exit(0)
    out = run(args.target, args.instance, args.label)
    path = Path(__file__).with_name(f"results_{args.label}.json")
    path.write_text(json.dumps(out, indent=2))
    print(f"\nSaved {path}")
