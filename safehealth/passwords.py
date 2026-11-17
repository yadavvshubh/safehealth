"""SR1: Argon2id password hashing and the password policy."""
import argon2
from argon2 import PasswordHasher

_hasher = PasswordHasher()          # argon2-cffi defaults = Argon2id with RFC 9106 low-memory profile
_DUMMY = None

COMMON = {
    "password1234", "password12345", "123456789012", "qwertyuiop12", "letmein12345",
    "admin1234567", "welcome12345", "safehealth123", "iloveyou1234", "changeme1234",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (argon2.exceptions.VerificationError, argon2.exceptions.InvalidHashError):
        return False


def dummy_verify(password: str) -> bool:
    """Burn the same time for unknown users so response time does not reveal valid usernames."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("not-a-real-account-password")
    verify(_DUMMY, password)
    return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def policy_errors(password: str, username: str = "") -> list:
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters.")
    if len(password) > 128:
        errors.append("Password must be at most 128 characters.")
    if not (any(c.islower() for c in password) and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)):
        errors.append("Password needs lower-case, upper-case and a digit.")
    if username and username.lower() in password.lower():
        errors.append("Password must not contain the username.")
    if password.lower() in COMMON:
        errors.append("Password is too common.")
    return errors
