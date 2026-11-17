"""SafeHealth - secure clinic records prototype (Prevent -> Detect -> Respond -> Recover)."""
import os
from datetime import datetime
from pathlib import Path

from flask import Flask, g, render_template, request

from . import audit, db, rbac, sessions
from .config import defaults
from .crypto import FieldCipher, load_or_create_key
from .limiter import limiter

ERRORS = {
    400: "The request could not be processed.",
    403: "You do not have permission to view this page. This attempt has been logged.",
    404: "Page not found.",
    405: "Method not allowed.",
    413: "The submitted form is too large.",
    429: "Too many requests. Please wait a minute and try again.",
    500: "Something went wrong. The error has been recorded.",
}


def create_app(instance_dir=None, **overrides):
    root = Path(__file__).resolve().parent.parent
    instance = Path(instance_dir or os.environ.get("SAFEHEALTH_INSTANCE") or root / "instance")
    app = Flask(__name__, instance_path=str(instance.resolve()))
    app.config.update(defaults(instance))
    if os.environ.get("SAFEHEALTH_KEY_DIR"):
        app.config["KEY_DIR"] = os.environ["SAFEHEALTH_KEY_DIR"]
    app.config.update(overrides)
    for key in ("INSTANCE", "KEY_DIR", "BACKUP_DIR"):
        Path(app.config[key]).mkdir(parents=True, exist_ok=True)
    app.extensions["field_cipher"] = FieldCipher(
        load_or_create_key(Path(app.config["KEY_DIR"]) / "field.key", "SAFEHEALTH_FIELD_KEY"))

    app.teardown_appcontext(db.close_db)
    app.before_request(sessions.load)
    app.before_request(sessions.check_csrf)
    app.before_request(rbac.enforce)
    limiter.init_app(app)
    app.after_request(sessions.save_cookie)
    app.after_request(_security_headers)

    from .routes import admin, appointments, auth, main, patients, security
    for module in (auth, main, patients, appointments, admin, security):
        app.register_blueprint(module.bp)

    @app.context_processor
    def _template_helpers():
        return {"csrf_token": sessions.csrf_token, "current_user": g.get("user"), "can": rbac.can,
                "flashes": sessions.pop_flashes}

    @app.template_filter("dt")
    def _format_time(epoch):
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S") if epoch else ""

    def _error(exc):
        code = getattr(exc, "code", 500) or 500
        if code == 429:
            audit.log("ratelimit.hit", result="denied", detail={"path": request.path})
        message = ERRORS.get(code, "Error.")
        if code == 400 and getattr(exc, "description", "").startswith("Your session"):
            message = exc.description
        return render_template("error.html", code=code, message=message), code   # never leak stack traces

    for code in ERRORS:
        app.register_error_handler(code, _error)

    with app.app_context():
        db.init_db()
    return app


def _security_headers(response):
    """SR12: browser-side hardening headers on every response."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"      # patient pages must not sit in browser caches
    return response
