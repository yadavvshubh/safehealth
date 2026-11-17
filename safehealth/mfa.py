"""SR3: TOTP multi-factor authentication (PyOTP, RFC 6238)."""
import re
import time

import pyotp
from markupsafe import Markup

from .crypto import cipher
from .db import get_db


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SafeHealth")


def check(secret: str, code: str) -> bool:
    if not re.fullmatch(r"\d{6}", code or ""):
        return False
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))   # +/- 30 s clock drift


def verify(user, code: str) -> bool:
    """Check a code for an enrolled user and refuse a code that was already used (replay)."""
    code = (code or "").strip().replace(" ", "")
    secret = cipher().decrypt(user["totp_secret_enc"])
    if not check(secret, code):
        return False
    now = time.time()
    if user["last_totp_code"] == code and now - user["last_totp_at"] < 120:
        return False
    db = get_db()
    db.execute("UPDATE users SET last_totp_code=?, last_totp_at=? WHERE id=?", (code, now, user["id"]))
    db.commit()
    return True


def qr_svg(uri: str):
    """Inline SVG QR code if the optional `qrcode` package is installed; otherwise None."""
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
        return Markup(img.to_string(encoding="unicode"))
    except Exception:
        return None
