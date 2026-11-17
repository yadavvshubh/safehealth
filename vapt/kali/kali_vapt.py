#!/usr/bin/env python3
"""SafeHealth Kali VAPT kit: one command tests the lab builds and packs every log into one archive.

LAB USE ONLY. Run it only against your own SafeHealth instances on the isolated lab network.
It refuses public IP addresses.

Typical run from Kali (192.168.56.1 = the Windows host on the VirtualBox host-only network):

  python3 kali_vapt.py --baseline http://192.168.56.1:5444 --hardened https://192.168.56.1:5443

Accounts default to the seeded demo staff: arjun (doctor), ravi (receptionist), kavya (nurse,
brute-force victim) and sharma (admin, reads the alerts at the end). Passwords come from each
build's instance/demo_credentials.txt: pass the files with --creds, or type them when asked.
Accounts that have not set up MFA are enrolled by the kit; their lab TOTP secrets are saved to
~/safehealth-vapt/lab_mfa_secrets.txt so later runs need no codes. (On the host,
`python manage.py lab-totp USER` always prints a valid code for browser logins.)

Full run: about 1 to 1.5 hours for both builds. --quick: about 15 minutes (no nikto, gobuster,
ZAP or slow sqlmap). Press Ctrl+C once to skip the tool that is running.

Output: ~/safehealth-vapt/<timestamp>/summary.md, results.json, one folder of logs per build,
and ~/safehealth-vapt/<timestamp>.tar.gz to send back for analysis.

Standard library only (Python 3.8+). External tools are used when installed and skipped if not:
nmap, sslscan or testssl, whatweb, nikto, gobuster or ffuf, sqlmap, zaproxy.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.parse
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

VERSION = "1.0"
CTX = ssl._create_unverified_context()          # the lab certificate is self-signed
UA = f"SafeHealth-VAPT-kit/{VERSION} (lab)"
HOME_DIR = Path.home() / "safehealth-vapt"
SECRET_STORE = HOME_DIR / "lab_mfa_secrets.txt"
LOGIN_PATHS = ("/login", "/mfa", "/mfa/enroll")
SHOWN = {"BLOCKED": "blocked", "VULNERABLE": "VULNERABLE", "DETECTED": "detected", "MISSED": "MISSED",
         "INFO": "info", "SKIPPED": "skipped", "ERROR": "ERROR"}
ATTACKS = ("BLOCKED", "VULNERABLE")
RESULTS = []
_LOG = None


# ---------------------------------------------------------------- output helpers

def say(msg=""):
    print(msg, flush=True)
    if _LOG:
        _LOG.write(msg + "\n")
        _LOG.flush()


def record(build, area, check, result, detail="", evidence=""):
    RESULTS.append({"build": build, "area": area, "check": check, "result": result,
                    "detail": detail, "evidence": evidence})
    say(f"  {SHOWN[result]:<10} {area} | {check}" + (f"  ({detail})" if detail else ""))


def text_of(page, limit=160):
    body = re.sub(r"(?is)<(script|style|head|header|nav)\b.*?</\1>", " ", page)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", body))).strip()[:limit]


def flash_error(resp):
    m = re.search(r'class="flash error">([^<]*)<', resp.text)
    return html.unescape(m.group(1)).strip() if m else text_of(resp.text, 80)


def location(resp):
    return urllib.parse.urlparse(resp.getheader("Location") or "").path


# ---------------------------------------------------------------- HTTP client

class Client:
    """Small HTTP client: never follows redirects, keeps cookies and the CSRF token, logs every exchange."""
    MASK = {"password", "current", "new", "confirm"}

    def __init__(self, build, base, ctx):
        self.build, self.base, self.ctx = build, urllib.parse.urlparse(base), ctx
        self.cookies, self.token = {}, ""
        self.transcript = ctx["transcripts"][build]

    def request(self, method, path, form=None, jar=None):
        https = self.base.scheme == "https"
        port = self.base.port or (443 if https else 80)
        conn = (http.client.HTTPSConnection(self.base.hostname, port, context=CTX, timeout=30) if https
                else http.client.HTTPConnection(self.base.hostname, port, timeout=30))
        jar = self.cookies if jar is None else jar
        headers, body = {"User-Agent": UA}, None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.text = resp.read().decode("utf-8", "replace")
        finally:
            conn.close()
        for header in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0]
            if not value or "max-age=0" in header.lower() or "1970" in header:
                jar.pop(name.strip(), None)
            else:
                jar[name.strip()] = value
        m = re.search(r'name="csrf_token" value="([^"]*)"', resp.text)
        if m and jar is self.cookies:
            self.token = m.group(1)
        if method == "POST" and path in LOGIN_PATHS:
            self.ctx["last_login_post"][self.build] = time.time()
        self._log(method, path, form, resp)
        return resp

    def _log(self, method, path, form, resp):
        shown = {k: ("********" if k in self.MASK else v) for k, v in (form or {}).items() if k != "csrf_token"}
        loc = resp.getheader("Location") or ""
        note = flash_error(resp) if ('class="flash' in resp.text or resp.status >= 400) else ""
        self.transcript.write(f"{datetime.now():%H:%M:%S} {method} {path}"
                              + (f" {json.dumps(shown)}" if shown else "")
                              + (" [no CSRF token]" if form is not None and "csrf_token" not in form else "")
                              + f"\n    -> HTTP {resp.status}" + (f" Location: {loc}" if loc else "")
                              + (f" | {note}" if note else "") + "\n")
        self.transcript.flush()

    def get(self, path, jar=None):
        return self.request("GET", path, jar=jar)

    def post(self, path, form, token=True):
        form = dict(form)
        if token:
            form["csrf_token"] = self.token
        return self.request("POST", path, form=form)

    def session_cookie(self):
        return next(((k, v) for k, v in self.cookies.items() if "sh_session" in k), (None, None))


def fresh(build, url, ctx):
    c = Client(build, url, ctx)
    c.get("/login")
    return c


# ---------------------------------------------------------------- MFA + login

def totp(secret, at=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int((at or time.time()) // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def remember_secret(build, username, secret, ctx):
    ctx["secrets"][(build, username)] = secret
    line = f"{build} {username} {secret}\n"
    for path in (SECRET_STORE, ctx["out"] / "lab_mfa_secrets.txt"):
        with open(path, "a") as fh:
            fh.write(line)


def load_secrets(ctx):
    for path in [SECRET_STORE] + [Path(p) for p in ctx["args"].mfa_secrets]:
        if path.exists():
            for line in path.read_text().splitlines():
                parts = line.split()
                if len(parts) == 3:
                    ctx["secrets"][(parts[0], parts[1])] = parts[2]


def login(build, c, username, password, ctx):
    """Log in, then open the home page: a full login starts a new session with a new CSRF token."""
    ok, how = _login(build, c, username, password, ctx)
    if ok:
        c.get("/")
    return ok, how


def _login(build, c, username, password, ctx):
    """Password step, then MFA (code from a saved secret, the kit's own enrolment, or the keyboard)."""
    r = c.post("/login", {"username": username, "password": password})
    if r.status != 302:
        return False, f"password step answered HTTP {r.status}: {flash_error(r)}"
    step = location(r)
    if step.endswith("/mfa/enroll"):
        page = c.get("/mfa/enroll")
        m = re.search(r'class="secret">\s*([A-Z2-7 ]+?)\s*<', page.text)
        if not m:
            return False, "the MFA enrolment page showed no secret"
        secret = m.group(1).replace(" ", "")
        r = c.post("/mfa/enroll", {"code": totp(secret)})
        if r.status == 302 and location(r) in ("/", ""):
            remember_secret(build, username, secret, ctx)
            return True, "MFA enrolled by the kit; lab TOTP secret saved"
        return False, f"MFA enrolment answered HTTP {r.status}"
    if step.endswith("/mfa"):
        c.get("/mfa")
        saved = ctx["secrets"].get((build, username))
        attempts = (["saved", "saved-next", "typed"] if saved else ["typed", "typed"])
        for how in attempts:
            if how == "saved-next":            # a code is single-use: wait for the next 30 s window
                time.sleep(31 - time.time() % 30)
            if how.startswith("saved"):
                code = totp(saved)
            else:
                try:
                    code = input(f"    6-digit MFA code for {username} on the {build} build (authenticator app, "
                                 f"or on the host: python manage.py lab-totp {username}): ").strip()
                except EOFError:
                    return False, "MFA code needed but no keyboard input is available"
            r = c.post("/mfa", {"code": code})
            if r.status == 302 and location(r) in ("/", ""):
                return True, "MFA passed" + (" (saved lab secret)" if how.startswith("saved") else "")
            if location(r).endswith("/login"):
                return False, "MFA failures locked the account"
        return False, "MFA code rejected"
    if step in ("/", ""):
        return True, "logged in with the password alone (no second factor asked)"
    return False, f"unexpected redirect to {step}"


# ---------------------------------------------------------------- tool runner

def run_tool(build, area, name, cmd, ctx, minutes, display=None):
    """Run an external tool with a time box. Ctrl+C stops just this tool. Returns (text, note) or None."""
    if not shutil.which(cmd[0]):
        record(build, area, name, "SKIPPED", f"{cmd[0]} is not installed")
        return None
    log = ctx["out"] / build / f"{re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')}.txt"
    shown = display or shlex.join(cmd)
    say(f"  ...      running {name} (up to {minutes:g} min, Ctrl+C to skip): {shown}")
    note = ""
    with open(log, "w") as fh:
        fh.write(f"$ {shown}\n# started {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
        fh.flush()
        proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                cwd=str(log.parent), start_new_session=True)
        try:
            proc.wait(timeout=minutes * 60)
        except subprocess.TimeoutExpired:
            note = f"stopped at the {minutes:g}-minute time box"
        except KeyboardInterrupt:
            note = "skipped with Ctrl+C"
        if proc.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                    proc.wait(timeout=10)
                    break
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    continue
        fh.write(f"\n# finished {datetime.now():%Y-%m-%d %H:%M:%S}" + (f" ({note})" if note else "") + "\n")
    return log.read_text(errors="replace"), note, log.name


def first_tool(*names):
    return next((n for n in names if shutil.which(n)), names[0])


def wordlist():
    for path in ("/usr/share/wordlists/dirb/small.txt", "/usr/share/dirb/wordlists/small.txt",
                 "/usr/share/wordlists/dirb/common.txt", "/usr/share/seclists/Discovery/Web-Content/common.txt"):
        if Path(path).exists():
            return path
    return None


# ---------------------------------------------------------------- unauthenticated checks

def preflight(build, url, ctx):
    try:
        r = Client(build, url, ctx).get("/login")
    except (OSError, http.client.HTTPException) as exc:
        record(build, "Setup", "Target reachable from Kali", "ERROR", str(exc))
        say(f"\n  Cannot reach {url}. Check: the server window on the host is running and shows the same address;\n"
            "  Windows Firewall allowed Python (tick Private AND Public); from Kali, `curl -k "
            f"{url}/login` works.\n")
        return False
    if r.status != 200 or "csrf_token" not in r.text:
        record(build, "Setup", "Target reachable from Kali", "ERROR", f"HTTP {r.status}: does not look like SafeHealth")
        return False
    try:
        ctx["server_start"][build] = parsedate_to_datetime(r.getheader("Date")).timestamp()
    except (TypeError, ValueError):
        ctx["server_start"][build] = time.time()
    record(build, "Setup", "Target reachable from Kali", "INFO", f"HTTP {r.status} from {url}")
    return True


def unauth_checks(build, url, ctx):
    out, https = ctx["out"] / build, url.startswith("https")
    c = Client(build, url, ctx)
    r = c.get("/login")
    lines = [f"GET /login -> HTTP {r.status}"]
    for k, v in r.getheaders():
        if k.lower() == "set-cookie":
            v = re.sub(r"=([^;]+)", "=<redacted>", v, count=1)
        lines.append(f"{k}: {v}")
    (out / "headers_login.txt").write_text("\n".join(lines) + "\n")
    hdr = {k.lower(): v for k, v in r.getheaders()}
    csp = hdr.get("content-security-policy", "")

    record(build, "Transport", "Passwords and records sent unencrypted (plain HTTP)",
           "BLOCKED" if https else "VULNERABLE",
           "HTTPS only" if https else "plain HTTP: readable by anyone on the network", "headers_login.txt")
    header_checks = [
        ("Page can be framed (clickjacking)", "x-frame-options" in hdr or "frame-ancestors" in csp),
        ("No Content-Security-Policy against injected scripts",
         "script-src 'self'" in csp or ("default-src 'self'" in csp and "unsafe-inline" not in csp)),
        ("MIME sniffing allowed (no X-Content-Type-Options)", hdr.get("x-content-type-options", "").lower() == "nosniff"),
        ("Full URLs leak in the Referer header (no Referrer-Policy)", "referrer-policy" in hdr),
        ("Patient pages kept in the browser cache (no Cache-Control: no-store)", "no-store" in hdr.get("cache-control", "")),
    ]
    if https:
        header_checks.append(("HTTPS downgrade possible (no HSTS)", "strict-transport-security" in hdr))
    for check, ok in header_checks:
        record(build, "Headers", check, "BLOCKED" if ok else "VULNERABLE", "", "headers_login.txt")
    if hdr.get("server"):
        record(build, "Information disclosure", "Server software banner", "INFO", hdr["server"], "headers_login.txt")

    cookie = next((h for h in (r.headers.get_all("Set-Cookie") or []) if "sh_session" in h), "")
    attrs = [p.strip().lower() for p in cookie.split(";")[1:]]
    name = cookie.split("=", 1)[0] if cookie else "(none)"
    detail = f"{name}; " + "; ".join(attrs)
    record(build, "Session", "Session cookie readable by JavaScript (no HttpOnly)",
           "BLOCKED" if "httponly" in attrs else "VULNERABLE", detail)
    record(build, "Session", "Session cookie also sent over plain HTTP (no Secure)",
           "BLOCKED" if "secure" in attrs else "VULNERABLE", detail)
    record(build, "Session", "Session cookie sent on cross-site requests (no SameSite)",
           "BLOCKED" if any(a in ("samesite=strict", "samesite=lax") for a in attrs) else "VULNERABLE", detail)

    victim = ctx["args"].victim
    c = fresh(build, url, ctx)
    e1 = flash_error(c.post("/login", {"username": f"nosuchuser{secrets.token_hex(3)}", "password": "x"}))
    e2 = flash_error(c.post("/login", {"username": victim, "password": f"wrong-{secrets.token_hex(3)}"}))
    record(build, "Authentication", "Username enumeration from login error messages",
           "VULNERABLE" if e1 != e2 else "BLOCKED", f'unknown user: "{e1}" / real user: "{e2}"',
           "http_transcript.log")

    c = fresh(build, url, ctx)
    r = c.post("/login", {"username": "' OR 1=1 --", "password": "x"})
    bypass = r.status == 302 and location(r) in ("/", "", "/mfa", "/mfa/enroll")
    record(build, "Injection", "SQL injection login bypass (username ' OR 1=1 --)",
           "VULNERABLE" if bypass else "BLOCKED",
           f"HTTP {r.status} -> {location(r)}: logged in without a password" if bypass else f"HTTP {r.status}",
           "http_transcript.log")

    c = fresh(build, url, ctx)
    r = c.post("/login", {"username": "'", "password": "x"})
    leak = re.search(r"database error|sqlite|operationalerror|unrecognized token|syntax error|traceback", r.text, re.I)
    record(build, "Information disclosure", "Database error details shown to the attacker",
           "VULNERABLE" if leak else "BLOCKED", f'HTTP {r.status}: "{flash_error(r)}"', "http_transcript.log")

    c = Client(build, url, ctx)
    r = c.post("/login", {"username": f"nosuchuser{secrets.token_hex(3)}", "password": "x"}, token=False)
    record(build, "CSRF", "Login form accepted without a CSRF token",
           "BLOCKED" if r.status == 400 else "VULNERABLE", f"HTTP {r.status}: {flash_error(r)}", "http_transcript.log")

    c = Client(build, url, ctx)
    paths = ["/.git/HEAD", "/.env", "/instance/safehealth.db", "/instance/keys/field.key",
             "/instance/demo_credentials.txt", "/static/../instance/safehealth.db",
             "/static/%2e%2e/instance/safehealth.db", "/backups/", "/run.py"]
    served = [p for p in paths if c.get(p).status == 200]
    record(build, "Exposure", "Database, keys or source files downloadable",
           "VULNERABLE" if served else "BLOCKED",
           ("served: " + ", ".join(served)) if served else f"all {len(paths)} paths refused", "http_transcript.log")


# ---------------------------------------------------------------- authenticated checks

def clinical_checks(build, url, ctx):
    user = ctx["args"].user
    password = ctx["passwords"][build].get(user)
    if not password:
        record(build, "Access control", "Clinical-user tests", "SKIPPED", f"no password for {user}")
        return
    c = fresh(build, url, ctx)
    ok, how = login(build, c, user, password, ctx)
    record(build, "Authentication", f"Login as {user} (clinical user)", "INFO" if ok else "ERROR", how)
    if not ok:
        return
    role = re.search(r'class="role">\s*([^<]+?)\s*<', c.get("/").text)      # also a fresh CSRF token
    role = role.group(1).lower() if role else "unknown"

    codes = {p: c.get(p).status for p in ("/admin/users", "/security/", "/security/audit")}
    record(build, "Access control", "Clinical user opening admin and security pages (privilege escalation)",
           "BLOCKED" if all(s == 403 for s in codes.values()) else "VULNERABLE",
           f"{user} ({role}): " + ", ".join(f"{p} -> {s}" for p, s in codes.items()), "http_transcript.log")
    ctx["ran"][build].add("privilege_violation")

    tally, opened = {}, []
    for pid in range(1, 31):
        status = c.get(f"/patients/{pid}").status
        tally[status] = tally.get(status, 0) + 1
        if status == 200:
            opened.append(pid)
    refused = tally.get(403, 0)
    record(build, "Access control", "Opening patients outside the user's care team (IDOR, IDs 1-30)",
           "BLOCKED" if refused else "VULNERABLE",
           f"{user}: opened {len(opened)}, refused {refused} (403), not found {tally.get(404, 0)}",
           "http_transcript.log")
    if refused >= 5:
        ctx["ran"][build].add("repeated_authz_failures")

    stored_xss(build, c, opened, ctx)

    r = c.post("/account/password", {"current": f"wrong-{secrets.token_hex(3)}", "new": "x", "confirm": "y"},
               token=False)
    if r.status == 400 and "not valid" in r.text:
        record(build, "CSRF", "State-changing form (password change) accepted without a CSRF token", "BLOCKED",
               "HTTP 400: rejected before processing", "http_transcript.log")
    elif "not correct" in r.text:
        record(build, "CSRF", "State-changing form (password change) accepted without a CSRF token", "VULNERABLE",
               "the server processed it (checked the current password)", "http_transcript.log")
    else:
        record(build, "CSRF", "State-changing form (password change) accepted without a CSRF token", "INFO",
               f"HTTP {r.status}: {flash_error(r)}")

    old = dict(c.cookies)
    c.post("/logout", {})
    r = c.get("/", jar=dict(old))
    if r.status == 200:
        record(build, "Session", "Old session cookie still works after logout (session replay)", "VULNERABLE",
               "replayed cookie opened the home page", "http_transcript.log")
    else:
        record(build, "Session", "Old session cookie still works after logout (session replay)", "BLOCKED",
               f"replayed cookie -> HTTP {r.status} {location(r)}", "http_transcript.log")


def stored_xss(build, c, opened, ctx):
    check = "Stored XSS in a patient's diagnosis"
    for pid in opened[:3]:
        page = c.get(f"/patients/{pid}")
        orig = {}
        for field in ("allergies", "diagnosis", "history"):
            m = re.search(rf'<textarea name="{field}"[^>]*>(.*?)</textarea>', page.text, re.S)
            if m:
                orig[field] = html.unescape(m.group(1))
        if len(orig) == 3:
            break
    else:
        record(build, "Injection", check, "SKIPPED", "the user can edit no clinical record")
        return
    marker = f"SH-XSS-{secrets.token_hex(3)}"
    payload = f'<script>alert("{marker}")</script>'
    c.post(f"/patients/{pid}/clinical", {**orig, "diagnosis": payload})
    view = c.get(f"/patients/{pid}").text
    if payload in view:
        result, detail = "VULNERABLE", f"script stored and served raw on patient #{pid}: runs for every viewer"
    elif marker in view:
        result, detail = "BLOCKED", f"stored on patient #{pid} but shown as text (escaped); CSP also forbids inline script"
    else:
        result, detail = "BLOCKED", "rejected by input validation"
    c.post(f"/patients/{pid}/clinical", orig)
    now = re.search(r'<textarea name="diagnosis"[^>]*>(.*?)</textarea>', c.get(f"/patients/{pid}").text, re.S)
    same = now and " ".join(html.unescape(now.group(1)).split()) == " ".join(orig["diagnosis"].split())
    detail += "; original record restored" if same else (
        f"; WARNING: restore failed, re-enter patient #{pid} diagnosis: {orig['diagnosis']!r}")
    record(build, "Injection", check, result, detail, "http_transcript.log")


def search_checks(build, url, ctx):
    user = ctx["args"].search_user
    password = ctx["passwords"][build].get(user)
    if not password:
        record(build, "Injection", "Patient-search tests", "SKIPPED", f"no password for {user}")
        return
    c = fresh(build, url, ctx)
    ok, how = login(build, c, user, password, ctx)
    record(build, "Authentication", f"Login as {user} (receptionist, patient search)", "INFO" if ok else "ERROR", how)
    if not ok:
        return
    probe = "zz%' UNION SELECT id, username, password_hash, role FROM users --"
    r = c.get("/patients/?q=" + urllib.parse.quote(probe))
    hashes = set(re.findall(r"\b[0-9a-f]{64}\b", r.text))
    quote = c.get("/patients/?q=" + urllib.parse.quote("'"))
    if hashes:
        result, detail = "VULNERABLE", f"UNION probe returned {len(hashes)} password hashes from the users table"
    elif quote.status >= 500:
        result, detail = "VULNERABLE", f"a single quote breaks the query (HTTP {quote.status}): {flash_error(quote)}"
    else:
        result, detail = "BLOCKED", f"quote and UNION probes answered HTTP {quote.status}/{r.status}, no extra data"
    record(build, "Injection", "SQL injection in patient search (manual UNION probe)", result, detail,
           "http_transcript.log")

    payload = '"><script>alert(7)</script>'
    r = c.get("/patients/?q=" + urllib.parse.quote(payload))
    record(build, "Injection", "Reflected XSS in patient search",
           "VULNERABLE" if payload in r.text else "BLOCKED",
           "payload echoed raw" if payload in r.text else "payload echoed escaped", "http_transcript.log")

    if "sqlmap" in ctx["skip"]:
        record(build, "Injection", "sqlmap: patient search (authenticated)", "SKIPPED", "--skip sqlmap")
    else:
        name, value = c.session_cookie()
        cmd = ["sqlmap", "-u", f"{url}/patients/?q=test", "-p", "q", "--cookie", f"{name}={value}",
               "--batch", "--dbms", "SQLite", "--level", "1" if ctx["args"].quick else "2", "--risk", "1",
               "--flush-session", "--disable-coloring", "--output-dir", str(ctx["out"] / build / "sqlmap_search"),
               "--tables"]
        if url.startswith("https"):
            cmd += ["--delay", "0.25"]               # stay under the hardened build's 300/min default limit
        shown = shlex.join(cmd).replace(value or "", "<session>")
        res = run_tool(build, "Injection", "sqlmap: patient search (authenticated)", cmd, ctx,
                       4 if ctx["args"].quick else ctx["args"].sqlmap_minutes, display=shown)
        sqlmap_record(build, "sqlmap: patient search (authenticated)", res)
    c.post("/logout", {})


def sqlmap_record(build, check, res):
    if res is None:
        return
    text, note, log = res
    entries = re.findall(r"\[(\d+) entr(?:y|ies)\]", text)
    rate = " Server answered 429 (rate limited) during the scan." if re.search(r"\b429\b", text) else ""
    if re.search(r"sqlmap identified the following injection point|parameter '.*?' is vulnerable", text):
        detail = "injectable" + (f"; dumped {entries[0]} rows" if entries else "")
        record(build, "Injection", check, "VULNERABLE", detail + rate, log)
    elif "do not appear to be injectable" in text:
        record(build, "Injection", check, "BLOCKED", "sqlmap: not injectable." + rate, log)
    else:
        record(build, "Injection", check, "INFO", (note or "inconclusive") + "; see log." + rate, log)


# ---------------------------------------------------------------- tools against each target

def recon_tools(build, url, ctx):
    u = urllib.parse.urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    skip = ctx["skip"]
    if "nmap" not in skip and host not in ctx["hosts_scanned"]:
        ctx["hosts_scanned"].add(host)
        res = run_tool(build, "Exposure", f"nmap: top 1000 TCP ports on {host}",
                       ["nmap", "-Pn", "-sT", "--top-ports", "1000", "-T4", host], ctx, 10)
        if res:
            ports = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)", res[0], re.M)
            record(build, "Exposure", f"nmap: top 1000 TCP ports on {host}", "INFO",
                   "open: " + (", ".join(f"{p}/{s}" for p, s in ports) or "none"), res[2])
    if "nmap" not in skip:
        res = run_tool(build, "Exposure", "nmap: service, headers and TLS scripts on the app port",
                       ["nmap", "-Pn", "-sT", "-sV", "-p", str(port), "--script",
                        "default,http-security-headers,http-methods,ssl-enum-ciphers",
                        "-oX", f"nmap_{build}_service.xml", host], ctx, 10)
        if res:
            svc = re.search(rf"^{port}/tcp\s+\S+\s+(.*)$", res[0], re.M)
            grade = re.search(r"least strength: (\S+)", res[0])
            record(build, "Exposure", "nmap: service, headers and TLS scripts on the app port", "INFO",
                   (svc.group(1).strip() if svc else "see log") + (f"; TLS grade {grade.group(1)}" if grade else ""),
                   res[2])
    if u.scheme == "https" and "tls" not in skip:
        tool = first_tool("sslscan", "testssl", "testssl.sh")
        cmd = (["sslscan", "--no-colour", f"{host}:{port}"] if tool == "sslscan"
               else [tool, "--quiet", "--color", "0", "--protocols", f"{host}:{port}"])
        res = run_tool(build, "Transport", "Weak TLS protocols offered (SSLv3, TLS 1.0/1.1)", cmd, ctx, 6)
        if res:
            weak = sorted(set(re.findall(r"^(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+enabled", res[0], re.M)
                              + re.findall(r"^\s*(SSLv2|SSLv3|TLS 1(?:\.1)?)\s+offered", res[0], re.M)))
            record(build, "Transport", "Weak TLS protocols offered (SSLv3, TLS 1.0/1.1)",
                   "VULNERABLE" if weak else "BLOCKED", ("enabled: " + ", ".join(weak)) if weak else "none enabled",
                   res[2])
    if "whatweb" not in skip:
        res = run_tool(build, "Information disclosure", "whatweb fingerprint",
                       ["whatweb", "--color=never", "-a", "1", f"{url}/login"], ctx, 3)
        if res:
            line = next((l for l in res[0].splitlines() if l.startswith("http")), "see log")
            record(build, "Information disclosure", "whatweb fingerprint", "INFO", line[:200], res[2])


def web_scanners(build, url, ctx):
    skip, quick = ctx["skip"], ctx["args"].quick
    if quick or "nikto" in skip:
        record(build, "Scanners", "nikto web server scan", "SKIPPED", "--quick" if quick else "--skip nikto")
    else:
        m = ctx["args"].nikto_minutes
        res = run_tool(build, "Scanners", "nikto web server scan",
                       ["nikto", "-h", url, "-maxtime", f"{m}m", "-nointeractive", "-ask", "no"], ctx, m + 1)
        if res:
            noise = ("+ Target", "+ Start Time", "+ End Time", "+ Server:", "+ SSL Info", "+ 1 host(s)", "+ Platform")
            items = [l for l in res[0].splitlines() if l.startswith("+ ") and not l.startswith(noise)]
            record(build, "Scanners", "nikto web server scan", "INFO",
                   f"{len(items)} items reported" + (f"; {res[1]}" if res[1] else ""), res[2])
    if quick or "gobuster" in skip:
        record(build, "Scanners", "Content discovery (hidden paths)", "SKIPPED", "--quick" if quick else "--skip gobuster")
        return
    wl = wordlist()
    if not wl:
        record(build, "Scanners", "Content discovery (hidden paths)", "SKIPPED", "no dirb/seclists wordlist found")
        return
    if shutil.which("gobuster") or not shutil.which("ffuf"):
        cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-k", "-t", "1", "--delay", "200ms", "-q", "--no-error",
               "-b", "404"]
    else:
        cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wl, "-p", "0.2", "-t", "1", "-fc", "404", "-noninteractive"]
    res = run_tool(build, "Scanners", "Content discovery (hidden paths)", cmd, ctx, 10)
    if res:
        found = re.findall(r"^/?(\S+)\s+\(Status: (\d+)\)", res[0], re.M) or \
            re.findall(r"^(\S+)\s+\[Status: (\d+)", res[0], re.M)
        limited = sum(1 for _, s in found if s == "429")
        real = [f"/{p.lstrip('/')} ({s})" for p, s in found if s != "429"]
        record(build, "Scanners", "Content discovery (hidden paths)", "INFO",
               ("found: " + ", ".join(real[:12]) if real else "nothing beyond the app routes")
               + (f"; {limited} requests rate-limited (429)" if limited else "") + (f"; {res[1]}" if res[1] else ""),
               res[2])


def sqlmap_login(build, url, ctx):
    check = "sqlmap: login form"
    if "sqlmap" in ctx["skip"]:
        record(build, "Injection", check, "SKIPPED", "--skip sqlmap")
        return
    https = url.startswith("https")
    if https and ctx["args"].quick:
        record(build, "Injection", check, "SKIPPED", "--quick (the 10/min login limit makes it slow)")
        return
    cmd = ["sqlmap", "-u", f"{url}/login", "-p", "username", "--batch", "--dbms", "SQLite", "--level", "1",
           "--risk", "1", "--flush-session", "--disable-coloring", "--answers", "crack=N",
           "--output-dir", str(ctx["out"] / build / "sqlmap_login")]
    if https:      # real CSRF token per request, and pace below the 10-per-minute login limit
        cmd += ["--data", "csrf_token=x&username=test&password=test", "--csrf-token", "csrf_token",
                "--csrf-url", f"{url}/login", "--delay", "7"]
    else:
        cmd += ["--data", "username=test&password=test", "-T", "users", "--dump"]
    sqlmap_record(build, check, run_tool(build, "Injection", check, cmd, ctx, ctx["args"].sqlmap_minutes))


def wait_window(build, ctx):
    remaining = ctx["args"].rate_window - (time.time() - ctx["last_login_post"].get(build, 0))
    if remaining > 0:
        say(f"  ...      waiting {remaining:.0f} s for the login rate-limit window to reset")
        time.sleep(remaining)


def brute_force(build, url, ctx):
    if "bruteforce" in ctx["skip"]:
        record(build, "Authentication", "Password guessing", "SKIPPED", "--skip bruteforce")
        return
    victim = ctx["args"].victim
    real = ctx["passwords"][build].get(victim)
    check = "Account lockout after repeated wrong passwords"
    wait_window(build, ctx)
    attempts = 0
    if real:          # an earlier run may have left the victim locked (15 min): then no new alert can fire
        attempts += 1
        if fresh(build, url, ctx).post("/login", {"username": victim, "password": real}).status != 302:
            record(build, "Authentication", check, "INFO",
                   f"{victim} was already locked before this test (earlier run?); wait 15 min or use --victim anita")
            real = None
    c = fresh(build, url, ctx)
    for i in range(6):
        c.post("/login", {"username": victim, "password": f"wrong-{i}-{secrets.token_hex(3)}"})
    attempts += 6
    if real:
        r = c.post("/login", {"username": victim, "password": real})
        attempts += 1
        if r.status == 302:
            record(build, "Authentication", check, "VULNERABLE",
                   f"{victim}: correct password accepted right after 6 wrong ones (no lockout)", "http_transcript.log")
        elif r.status == 401:
            record(build, "Authentication", check, "BLOCKED",
                   f"{victim}: correct password refused after 6 wrong ones: account locked", "http_transcript.log")
        else:
            record(build, "Authentication", check, "INFO", f"HTTP {r.status} on the 7th attempt")
        ctx["ran"][build].add("brute_force")
    elif not any(r["build"] == build and r["check"] == check for r in RESULTS):
        record(build, "Authentication", check, "INFO",
               "lockout is invisible to an attacker by design; give the victim's password to prove it")
        ctx["ran"][build].add("brute_force")
    c = fresh(build, url, ctx)
    codes = []
    for _ in range(15):
        codes.append(c.post("/login", {"username": "ratelimit-probe", "password": "x"}).status)
        if codes[-1] == 429:
            break
    record(build, "Authentication", "Unlimited password guessing (no rate limit)",
           "BLOCKED" if 429 in codes else "VULNERABLE",
           f"HTTP 429 after {attempts + codes.index(429)} login attempts within a minute" if 429 in codes
           else f"{attempts + len(codes)} attempts in under a minute, none refused", "http_transcript.log")


def zap_scan(build, url, ctx):
    check = "OWASP ZAP quick scan (spider + active scan)"
    if ctx["args"].quick or "zap" in ctx["skip"]:
        record(build, "Scanners", check, "SKIPPED", "--quick" if ctx["args"].quick else "--skip zap")
        return
    report = ctx["out"] / build / "zap_report.html"
    res = run_tool(build, "Scanners", check,
                   [first_tool("zaproxy", "zap.sh"), "-cmd", "-quickurl", url, "-quickout", str(report),
                    "-quickprogress"], ctx, ctx["args"].zap_minutes)
    if res:
        counts = {}
        if report.exists():
            page = report.read_text(errors="replace")
            for risk in ("High", "Medium", "Low", "Informational"):
                m = re.search(rf">\s*{risk}\s*<.{{0,200}}?>\s*(\d+)\s*<", page, re.S)
                if m:
                    counts[risk] = m.group(1)
        detail = (", ".join(f"{k} {v}" for k, v in counts.items()) if counts
                  else ("report saved" if report.exists() else "no report written"))
        record(build, "Scanners", check, "INFO", detail + (f"; {res[1]}" if res[1] else ""),
               report.name if report.exists() else res[2])


def detection_checks(build, url, ctx):
    admin = ctx["args"].admin
    password = ctx["passwords"][build].get(admin)
    if "alerts" in ctx["skip"] or not password:
        record(build, "Detection", "Alerts raised by this run", "SKIPPED",
               "--skip alerts" if "alerts" in ctx["skip"] else f"no password for {admin}")
        return
    wait_window(build, ctx)
    c = fresh(build, url, ctx)
    ok, how = login(build, c, admin, password, ctx)
    if not ok:
        record(build, "Detection", "Alerts raised by this run", "ERROR", f"admin login failed: {how}")
        return
    r = c.get("/security/api/summary")
    try:
        summary = json.loads(r.text)
    except ValueError:
        record(build, "Detection", "Alerts raised by this run", "ERROR", f"/security/api/summary HTTP {r.status}")
        return
    since = ctx["server_start"].get(build, 0) - 60
    mine = [a for a in summary.get("alerts", []) if a.get("last_seen", 0) >= since]
    (ctx["out"] / build / "alerts.json").write_text(json.dumps({"counts": summary.get("counts"), "alerts": mine},
                                                               indent=2))
    for rule in ("brute_force", "privilege_violation", "repeated_authz_failures"):
        if rule not in ctx["ran"][build]:
            continue
        hits = [a for a in mine if a.get("rule") == rule]
        record(build, "Detection", f"Alert raised: {rule}", "DETECTED" if hits else "MISSED",
               "; ".join(f"{a['severity']}: {a['summary']} -> {a.get('response', '')}" for a in hits)[:300],
               "alerts.json")
    other = sorted({a["rule"] for a in mine} - ctx["ran"][build])
    if other:
        record(build, "Detection", "Other alerts during the run", "INFO", ", ".join(other), "alerts.json")
    locked = (summary.get("counts") or {}).get("Locked accounts")
    if locked is not None:
        record(build, "Detection", "Accounts locked at the end of the run", "INFO", str(locked), "alerts.json")
    c.post("/security/verify-chain", {})
    flash = re.search(r'class="flash[^"]*">([^<]*)<', c.get("/security/").text)
    if flash:
        intact = "intact" in flash.group(1).lower()
        record(build, "Integrity", "Audit log hash chain after the attack", "BLOCKED" if intact else "VULNERABLE",
               html.unescape(flash.group(1)).strip())
    c.post("/logout", {})


# ---------------------------------------------------------------- summary + archive

def write_summary(ctx):
    builds = [b for b in ("baseline", "hardened") if b in ctx["targets"]]
    rows, seen = [], set()
    for r in RESULTS:
        if (r["area"], r["check"]) not in seen and r["area"] != "Setup" and not r["check"].startswith("Login as"):
            seen.add((r["area"], r["check"]))
            rows.append((r["area"], r["check"]))
    cell = {(r["build"], r["area"], r["check"]): r for r in RESULTS}
    lines = [f"# SafeHealth VAPT run {ctx['stamp']}", "",
             f"Kit {VERSION} on {ctx['meta']['kali']} | started {ctx['meta']['started']} | "
             f"finished {datetime.now():%Y-%m-%d %H:%M:%S}", ""]
    for b in builds:
        lines.append(f"- **{b}**: {ctx['targets'][b]}")
    lines += ["", "Tools: " + "; ".join(f"{k} {v}" for k, v in ctx["meta"]["tools"].items()), ""]
    for b in builds:
        attacks = [r for r in RESULTS if r["build"] == b and r["result"] in ATTACKS]
        held = sum(r["result"] == "BLOCKED" for r in attacks)
        det = [r for r in RESULTS if r["build"] == b and r["result"] in ("DETECTED", "MISSED")]
        lines.append(f"- **{b}**: blocked {held} of {len(attacks)} attack checks"
                     + (f"; detection fired on {sum(r['result'] == 'DETECTED' for r in det)} of {len(det)} rules"
                        if det else ""))
    lines += ["", "| Area | Attack or weakness tested | " + " | ".join(b.capitalize() for b in builds) + " |",
              "|---|---|" + "---|" * len(builds)]
    for area, check in rows:
        vals = [SHOWN[cell[(b, area, check)]["result"]] if (b, area, check) in cell else "-" for b in builds]
        lines.append(f"| {area} | {check} | " + " | ".join(vals) + " |")
    problems = [r for r in RESULTS if r["build"] == "hardened" and r["result"] in ("VULNERABLE", "MISSED", "ERROR")]
    lines += ["", "## Hardened build: items to look at", ""]
    lines += [f"- **{r['area']} / {r['check']}**: {r['result']}. {r['detail']}" for r in problems] or ["- None."]
    for b in builds:
        lines += ["", f"## Details: {b}", ""]
        lines += [f"- **{r['area']} / {r['check']}**: {SHOWN[r['result']]}"
                  + (f". {r['detail']}" if r["detail"] else "") + (f" (`{b}/{r['evidence']}`)" if r["evidence"] else "")
                  for r in RESULTS if r["build"] == b]
    (ctx["out"] / "summary.md").write_text("\n".join(lines) + "\n")
    (ctx["out"] / "results.json").write_text(json.dumps({"meta": ctx["meta"], "targets": ctx["targets"],
                                                         "results": RESULTS}, indent=2))


def archive(ctx):
    path = ctx["out"].with_suffix(".tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        tar.add(ctx["out"], arcname=ctx["out"].name)
    return path


# ---------------------------------------------------------------- setup

def lab_only(url, allow_public):
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        sys.exit(f"Not a URL: {url}")
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, u.port or 80)}
    except socket.gaierror:
        sys.exit(f"Cannot resolve {u.hostname}")
    public = [a for a in addrs if not (ipaddress.ip_address(a).is_private or ipaddress.ip_address(a).is_loopback)]
    if public and not allow_public:
        sys.exit(f"Refusing {url}: {', '.join(public)} is not a private lab address. "
                 "This kit is for your own lab instances only.")
    return url.rstrip("/")


def kali_ip(url):
    u = urllib.parse.urlparse(url)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((u.hostname, u.port or 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "unknown"


def tool_versions():
    probes = {"nmap": ["nmap", "--version"], "sqlmap": ["sqlmap", "--version"], "nikto": ["nikto", "-Version"],
              "gobuster": ["gobuster", "version"], "sslscan": ["sslscan", "--version"],
              "whatweb": ["whatweb", "--version"]}
    found = {}
    for name, cmd in probes.items():
        if not shutil.which(cmd[0]):
            found[name] = "not installed"
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
            m = re.search(r"\d+\.\d+[\w.#-]*", out)
            found[name] = m.group(0) if m else "installed"
        except (OSError, subprocess.SubprocessError):
            found[name] = "installed"
    found["zaproxy"] = "installed" if shutil.which("zaproxy") or shutil.which("zap.sh") else "not installed"
    return found


def read_creds(spec):
    build, _, path = spec.partition("=")
    if build not in ("baseline", "hardened") or not path:
        sys.exit(f"--creds expects baseline=FILE or hardened=FILE, got {spec!r}")
    found = {}
    for line in Path(path).expanduser().read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("admin", "doctor", "nurse", "receptionist"):
            found[parts[0]] = parts[2]
    return build, found


def main():
    global _LOG
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hardened", help="hardened build URL, e.g. https://192.168.56.1:5443")
    p.add_argument("--baseline", help="vulnerable baseline URL, e.g. http://192.168.56.1:5444")
    p.add_argument("--user", default="arjun", help="doctor or nurse for access-control tests (default arjun)")
    p.add_argument("--search-user", default="ravi", help="receptionist for patient-search tests (default ravi)")
    p.add_argument("--victim", default="kavya", help="account to brute-force; gets locked 15 min (default kavya)")
    p.add_argument("--admin", default="sharma", help="admin who reads the alerts at the end (default sharma)")
    p.add_argument("--creds", action="append", default=[], metavar="BUILD=FILE",
                   help="a build's demo_credentials.txt, e.g. hardened=/media/sf_SafeHealth/instance/demo_credentials.txt")
    p.add_argument("--mfa-secrets", action="append", default=[], metavar="FILE",
                   help="extra 'build user secret' lines (the kit's own file is loaded automatically)")
    p.add_argument("--quick", action="store_true", help="about 15 minutes: skip nikto, gobuster, ZAP, slow sqlmap")
    p.add_argument("--skip", action="append", default=[],
                   help="nmap, tls, whatweb, nikto, gobuster, sqlmap, zap, bruteforce, alerts (repeatable)")
    p.add_argument("--sqlmap-minutes", type=float, default=12)
    p.add_argument("--nikto-minutes", type=float, default=8)
    p.add_argument("--zap-minutes", type=float, default=15)
    p.add_argument("--rate-window", type=float, default=65, help="seconds to let the login limit reset (default 65)")
    p.add_argument("--out", help="results folder (default ~/safehealth-vapt/<timestamp>)")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--i-own-this-public-target", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()

    targets = {}
    for build in ("baseline", "hardened"):
        if getattr(args, build):
            targets[build] = lab_only(getattr(args, build), args.i_own_this_public_target)
    if not targets:
        p.error("give --hardened and/or --baseline")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out).expanduser() if args.out else HOME_DIR / stamp
    for build in targets:
        (out / build).mkdir(parents=True, exist_ok=True)
    HOME_DIR.mkdir(parents=True, exist_ok=True)
    _LOG = open(out / "console.log", "w")
    ctx = {"args": args, "out": out, "stamp": stamp, "targets": targets, "secrets": {},
           "skip": {s.strip().lower() for item in args.skip for s in item.split(",")},
           "passwords": {b: {} for b in targets}, "last_login_post": {}, "server_start": {},
           "ran": {b: set() for b in targets}, "hosts_scanned": set(),
           "transcripts": {b: open(out / b / "http_transcript.log", "a") for b in targets}}
    load_secrets(ctx)
    for spec in args.creds:
        build, found = read_creds(spec)
        if build in targets:
            ctx["passwords"][build].update(found)

    say(f"SafeHealth Kali VAPT kit {VERSION}")
    say("Rules of engagement: your own lab instances only, isolated network, guide's permission on file.")
    for b, u in targets.items():
        say(f"  {b:<9} {u}")
    say(f"  mode      {'quick (~15 min)' if args.quick else 'full (~1-1.5 h for both builds)'}; results in {out}")
    say(f"  accounts  user={args.user} search={args.search_user} victim={args.victim} "
        f"(locked 15 min on hardened) admin={args.admin}")
    for build in targets:
        for user in dict.fromkeys([args.user, args.search_user, args.victim, args.admin]):
            if user not in ctx["passwords"][build]:
                pw = getpass.getpass(f"Password for {user} on the {build} build "
                                     "(from its instance/demo_credentials.txt; Enter to skip): ")
                if pw:
                    ctx["passwords"][build][user] = pw
    if not args.yes and input("Type YES to start: ").strip() != "YES":
        sys.exit("Not started.")

    first = next(iter(targets.values()))
    ctx["meta"] = {"kit": VERSION, "kali": f"Kali {kali_ip(first)}", "started": f"{datetime.now():%Y-%m-%d %H:%M:%S}",
                   "quick": args.quick, "skip": sorted(ctx["skip"]), "tools": tool_versions()}
    say("Tools: " + ", ".join(f"{k} {v}" for k, v in ctx["meta"]["tools"].items()))
    try:
        for build, url in targets.items():
            say(f"\n=== {build.upper()} build: {url} ===")
            if not preflight(build, url, ctx):
                continue
            for step in (unauth_checks, clinical_checks, search_checks, recon_tools, web_scanners,
                         sqlmap_login, brute_force, zap_scan, detection_checks):
                try:
                    step(build, url, ctx)
                except Exception as exc:          # one failing step must not lose the rest of the run
                    _LOG.write(traceback.format_exc())
                    record(build, "Setup", f"{step.__name__} interrupted", "ERROR", f"{type(exc).__name__}: {exc}")
    except KeyboardInterrupt:
        say("\nStopped by the user; writing what was collected so far.")
    finally:
        write_summary(ctx)
        for fh in ctx["transcripts"].values():
            fh.close()
        say(f"\nSummary: {out / 'summary.md'}")
        path = archive(ctx)
        say(f"Archive: {path}\nSend this .tar.gz back for analysis (copy it to the host or attach it in the chat).")
        _LOG.close()


if __name__ == "__main__":
    main()
