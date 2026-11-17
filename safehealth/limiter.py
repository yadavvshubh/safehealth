"""SR2: request rate limiting (Flask-Limiter). Keyed on the socket address; no proxy headers are trusted."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
