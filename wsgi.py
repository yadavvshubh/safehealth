"""Production entry point (gunicorn wsgi:app). The lab uses run.py; this is for a hosted demo.

Behind a hosting proxy that terminates HTTPS (Render, Koyeb, ...), set SAFEHEALTH_TRUST_PROXY=1 so
the app reads the real client IP and scheme from the proxy's one X-Forwarded-* hop. Without it, every
visitor shares the proxy's IP and the brute-force lockout would hit them all at once. Only enable it
when a single trusted proxy sits in front: never in the lab, where run.py is used instead.
"""
import os

from safehealth import create_app

app = create_app()

if os.environ.get("SAFEHEALTH_TRUST_PROXY") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
