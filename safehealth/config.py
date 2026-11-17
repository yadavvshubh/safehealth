"""Central configuration. Every security threshold lives here so it can be tuned and cited."""
from pathlib import Path


def defaults(instance: Path) -> dict:
    instance = Path(instance)
    return {
        "INSTANCE": str(instance),
        "DB_PATH": str(instance / "safehealth.db"),
        # SR5: keys live outside the database. Point SAFEHEALTH_KEY_DIR at another disk in the lab.
        "KEY_DIR": str(instance / "keys"),
        "BACKUP_DIR": str(instance / "backups"),
        "QUARANTINE_DIR": str(instance / "quarantine"),
        "LAB_DIR": str(instance / "lab_files"),          # dummy files for the ransomware drill
        "FIM_BASELINE": str(instance / "fim_baseline.json"),
        "BACKUP_KEEP": 14,
        # SR8 sessions
        "COOKIE_SECURE": True,
        "SESSION_IDLE_SECONDS": 15 * 60,
        "SESSION_ABSOLUTE_SECONDS": 8 * 3600,
        "PRELOGIN_SECONDS": 10 * 60,
        # SR2 lockout + rate limiting
        "LOCKOUT_THRESHOLD": 5,
        "LOCKOUT_WINDOW": 120,
        "LOCKOUT_SECONDS": 15 * 60,
        "LOGIN_RATE": "10 per minute",
        "RATELIMIT_DEFAULT": "300 per minute",
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_ENABLED": True,
        # SR10 detection rules (section 8.3 of the proposal)
        "MASS_ACCESS_THRESHOLD": 15,
        "MASS_ACCESS_WINDOW": 120,
        "MASS_ACCESS_TERMINATE": False,   # True = also kill the user's sessions
        "PRIV_REPEAT_THRESHOLD": 3,
        "PRIV_REPEAT_WINDOW": 600,
        "AUTHZ_FAIL_THRESHOLD": 5,
        "AUTHZ_FAIL_WINDOW": 120,
        "CLINIC_HOURS": (7, 21),          # logins outside 07:00-21:00 local time are flagged
        "FIM_CHANGE_THRESHOLD": 5,
        # NFR targets
        "RTO_SECONDS": 30 * 60,
        "RPO_SECONDS": 24 * 3600,
        "MAX_CONTENT_LENGTH": 64 * 1024,
    }
