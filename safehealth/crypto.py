"""SR5: field-level encryption with Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` library.

No home-made cryptography. Keys are files outside the database (or environment variables),
so a stolen database or backup on its own does not reveal the sensitive fields.
"""
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def load_or_create_key(path: Path, env_var: str) -> bytes:
    if os.environ.get(env_var):
        return os.environ[env_var].encode()
    path = Path(path)
    if path.exists():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


class FieldCipher:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    def encrypt(self, value):
        if value is None or value == "":
            return None
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, token):
        if not token:
            return ""
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return "[unreadable: wrong key or tampered data]"


def cipher() -> FieldCipher:
    return current_app.extensions["field_cipher"]
