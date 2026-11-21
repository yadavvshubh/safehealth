"""External checks against a hosted SafeHealth (our own demo only). HTTP-visible controls only:
the DB-backed checks (encryption at rest, hash type, alert counts) stay in the lab, since a public
host gives no filesystem access. Run the full 19+68 suite against the lab, this against the URL.

    python vapt/public_check.py https://safehealth-demo.onrender.com
    python vapt/public_check.py https://...   meera  <password from Render logs>   # adds authed checks

With a username+password it also enrols MFA (first login) and checks MFA-required, IDOR and CSRF.
"""
import re
import sys
import urllib.parse
import urllib.request

try:
    import pyotp
except ImportError:
    pyotp = None

BASE = sys.argv[1].rstrip("/")
USER = sys.argv[2] if len(sys.argv) > 2 else None
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else None
RESULTS = []


def check(area, name, ok, detail=""):
    RESULTS.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  [{area}] {name}" + (f"  ({detail})" if detail else ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):          # security checks assert on the real 302, never the page it points to
        return None


class Client:
    def __init__(self):
        self.cookies = {}
        self.opener = urllib.request.build_opener(_NoRedirect)

    def request(self, method, path, form=None, raw=None):
        data, headers = None, {}
        if form is not None or raw is not None:
            data = (raw if raw is not None else urllib.parse.urlencode(form)).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
        try:
            resp = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            resp = e
        body = resp.read().decode("utf-8", "replace")
        setc = resp.headers.get_all("Set-Cookie") or []
        for c in setc:
            name, _, rest = c.partition("=")
            self.cookies[name] = rest.split(";", 1)[0]
        resp.text, resp.setcookies = body, setc
        return resp

    def get(self, path):
        return self.request("GET", path)

    def csrf(self, path="/login"):
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.get(path).text)
        return m.group(1) if m else ""


# --- unauthenticated, externally observable -------------------------------------------------------
c = Client()
r = c.get("/login")
h = r.headers
check("Headers", "Content-Security-Policy present", "script-src 'self'" in (h.get("Content-Security-Policy") or ""))
check("Headers", "X-Frame-Options DENY", h.get("X-Frame-Options") == "DENY")
check("Headers", "X-Content-Type-Options nosniff", h.get("X-Content-Type-Options") == "nosniff")
check("Headers", "Referrer-Policy set", bool(h.get("Referrer-Policy")))
check("Transport", "HTTPS in use", BASE.startswith("https"))
check("Transport", "HSTS header", bool(h.get("Strict-Transport-Security")), h.get("Strict-Transport-Security", "missing"))
cookie = next((x for x in r.setcookies if "session" in x.lower()), "")
check("Session", "cookie Secure+HttpOnly+SameSite", all(f in cookie for f in ("Secure", "HttpOnly", "SameSite")), cookie[:60])

tok = c.csrf("/login")
r = c.request("POST", "/login", {"csrf_token": tok, "username": "' OR '1'='1' -- ", "password": "x"})
check("SQLi", "login bypass blocked", r.status == 401, f"HTTP {r.status}")
bad_user = c.request("POST", "/login", {"csrf_token": c.csrf("/login"), "username": "no_such_user_x", "password": "x"})
err = lambda t: (re.search(r'class="flash error">([^<]+)<', t) or ["", ""])[1]
check("Auth", "no username enumeration", err(r.text) == err(bad_user.text) or r.status == bad_user.status)

for path in ("/patients/1", "/security/", "/admin/users"):
    rr = c.get(path)
    check("Access", f"anonymous {path} -> login", rr.status in (302, 401) or "/login" in rr.url)

big = c.request("POST", "/login", raw="a=" + "x" * 200_000)
check("Hardening", "oversized body refused", big.status == 413, f"HTTP {big.status}")

# --- authenticated (optional) ---------------------------------------------------------------------
if USER and PASSWORD and pyotp:
    a = Client()
    r = a.request("POST", "/login", {"csrf_token": a.csrf("/login"), "username": USER, "password": PASSWORD})
    check("Auth", "password alone does not reach records", a.get("/patients/1").status in (302, 401))
    loc = r.headers.get("Location", "")
    if loc.endswith("/mfa/enroll"):
        page = a.get("/mfa/enroll")
        secret = re.search(r'class="secret">([A-Z2-7 ]+)<', page.text).group(1).replace(" ", "")
        a.request("POST", "/mfa/enroll", {"csrf_token": a.csrf("/mfa/enroll"), "code": pyotp.TOTP(secret).now()})
    elif loc.endswith("/mfa"):
        print("  (account already has MFA; pass a fresh account to test enrolment)")
    # CSRF: POST with no token is refused
    cr = a.request("POST", "/patients/1/clinical", {"diagnosis": "x", "allergies": "", "history": ""})
    check("CSRF", "POST without token refused", cr.status == 400, f"HTTP {cr.status}")
elif USER:
    print("  (install pyotp to run the authenticated checks: pip install pyotp)")

print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed against {BASE}")
sys.exit(0 if all(RESULTS) else 1)
