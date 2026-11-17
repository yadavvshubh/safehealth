"""SR7: server-side input validation. Output encoding is done by Jinja2 auto-escaping."""
import re
from datetime import date, datetime


class Invalid(ValueError):
    pass


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
NAME = r"[A-Za-zÀ-ɏऀ-ॿ][A-Za-zÀ-ɏऀ-ॿ .'\-]{1,79}"
USERNAME = r"[a-z][a-z0-9_.]{2,31}"
PHONE = r"\+?[0-9][0-9 \-]{6,17}"


def text(form, name, label, max_len, required=True, pattern=None, multiline=False):
    value = (form.get(name) or "").strip()
    if not value:
        if required:
            raise Invalid(f"{label} is required.")
        return ""
    if len(value) > max_len:
        raise Invalid(f"{label} must be at most {max_len} characters.")
    if _CONTROL.search(value) or (not multiline and re.search(r"[\r\n]", value)):
        raise Invalid(f"{label} contains invalid characters.")
    if pattern and not re.fullmatch(pattern, value):
        raise Invalid(f"{label} has an invalid format.")
    return value


def choice(form, name, label, options):
    value = (form.get(name) or "").strip()
    if value not in options:
        raise Invalid(f"{label} is not a valid choice.")
    return value


def number(form, name, label, low, high, required=False, kind=float):
    raw = (form.get(name) or "").strip()
    if not raw:
        if required:
            raise Invalid(f"{label} is required.")
        return None
    try:
        value = kind(raw)
    except ValueError:
        raise Invalid(f"{label} must be a number.") from None
    if not (low <= value <= high):
        raise Invalid(f"{label} must be between {low} and {high}.")
    return value


def past_date(form, name, label):
    raw = (form.get(name) or "").strip()
    try:
        value = datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        raise Invalid(f"{label} must be a date (YYYY-MM-DD).") from None
    if value > date.today() or value.year < 1900:
        raise Invalid(f"{label} is out of range.")
    return value.isoformat()


def when(form, name, label):
    raw = (form.get(name) or "").strip()
    try:
        value = datetime.strptime(raw, "%Y-%m-%dT%H:%M")
    except ValueError:
        raise Invalid(f"{label} must be a date and time.") from None
    return value.strftime("%Y-%m-%dT%H:%M")
