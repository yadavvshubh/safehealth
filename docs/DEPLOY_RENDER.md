# Public demo on Render (hardened build only)

A free public HTTPS demo of the **hardened** build. The deliberately vulnerable baseline is never
deployed this way. Synthetic data only; the disk resets on every restart, so demo accounts are
re-seeded fresh each boot.

## One-time setup

1. Sign in at <https://render.com> with your GitHub account and authorise access to `yadavvshubh/safehealth`.
2. **New → Blueprint**, pick the `safehealth` repo. Render reads `render.yaml` and proposes the
   `safehealth-demo` web service. Click **Apply**.
3. Wait for the first deploy (a few minutes). The URL is `https://safehealth-demo.onrender.com`
   (Render may add a suffix if the name is taken; use whatever it shows).

## Get the demo passwords

`manage.py seed` runs on every boot and prints the accounts. Open the service → **Logs** and find the
block that starts `SafeHealth demo accounts`. Passwords change on each restart. Accounts:
`sharma` (admin), `meera`/`arjun` (doctors), `anita`/`kavya` (nurses), `ravi` (receptionist).

At first login each account sets up an authenticator app (scan the QR with Google/Microsoft
Authenticator or Aegis). This is the real MFA, now on your phone.

## Notes

- **Sleeps when idle.** After 15 min with no traffic the free instance sleeps; the next visit takes
  ~50 s to wake. Fine for a demo; mention it in the viva.
- **Why the hosting changes are safe.** `wsgi.py` + `SAFEHEALTH_TRUST_PROXY=1` make the app read the
  real client IP and HTTPS scheme from Render's single proxy, so the per-IP lockout and HSTS work.
  No security control or threshold changed; the 138 tests still pass and the lab stays on `run.py`.

## Test the public site

External, HTTP-visible checks (the DB-backed checks stay in the lab — a host gives no file access):

```
python vapt/public_check.py https://safehealth-demo.onrender.com
python vapt/public_check.py https://safehealth-demo.onrender.com meera <password-from-logs>
```

The first form needs no login (headers, HTTPS/HSTS, cookie flags, SQLi login bypass blocked, no user
enumeration, anonymous access blocked, oversized body refused). Adding an account also checks
MFA-is-required and CSRF. Keep this to your own demo instance, under your rules of engagement.
