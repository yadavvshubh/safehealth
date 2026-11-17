"""Start SafeHealth over HTTPS:  python run.py   ->  https://127.0.0.1:5443

Set SAFEHEALTH_HOST=0.0.0.0 to reach it from the Kali VM on the isolated lab network.
This is Flask's development server: fine for the lab demo, not for production.
"""
import os

from safehealth import create_app
from safehealth.tls import ensure_cert

app = create_app()

if __name__ == "__main__":
    cert, key = ensure_cert(app.config["INSTANCE"])
    app.run(host=os.environ.get("SAFEHEALTH_HOST", "127.0.0.1"),
            port=int(os.environ.get("SAFEHEALTH_PORT", "5443")), ssl_context=(cert, key), debug=False)
