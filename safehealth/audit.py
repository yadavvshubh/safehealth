"""SR9: tamper-evident audit log.

Each entry stores the SHA-256 of (previous entry's hash + its own fields). Changing, removing or
re-ordering any entry breaks every hash after it, which verify_chain() reports.
"""
import hashlib
import json
import sqlite3
import threading
import time

from flask import current_app, g, has_request_context, request

from .db import get_db

GENESIS = "0" * 64
FIELDS = ("ts", "user_id", "username", "role", "action", "patient_id", "ip", "result", "detail")
_lock = threading.RLock()


def _digest(prev_hash, record):
    payload = json.dumps([prev_hash] + [record[f] for f in FIELDS], separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log(action, result="success", patient_id=None, detail=None, system=False, username=None):
    """Append one event. Commits any pending work on the request's connection first."""
    db = get_db()
    user = None if system else (g.get("user") or g.get("pending_user"))
    record = {
        "ts": time.time(),
        "user_id": user["id"] if user else None,
        "username": (username or (user["username"] if user else ("system" if system else "anonymous")))[:64],
        "role": user["role"] if user else ("system" if system else "none"),
        "action": action,
        "patient_id": patient_id,
        "ip": (request.remote_addr or "unknown") if has_request_context() else "local",
        "result": result,
        "detail": json.dumps(detail or {}, sort_keys=True),
    }
    with _lock:
        for _attempt in range(5):
            db.commit()
            try:
                db.execute("BEGIN IMMEDIATE")
                last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                record["prev_hash"] = last["hash"] if last else GENESIS
                record["hash"] = _digest(record["prev_hash"], record)
                cur = db.execute(
                    "INSERT INTO audit_log (ts,user_id,username,role,action,patient_id,ip,result,detail,prev_hash,hash)"
                    " VALUES (:ts,:user_id,:username,:role,:action,:patient_id,:ip,:result,:detail,:prev_hash,:hash)",
                    record,
                )
                db.commit()
                record["id"] = cur.lastrowid
                break
            except sqlite3.IntegrityError:      # another process appended first: retry on the new head
                db.rollback()
        else:
            raise RuntimeError("could not append to the audit log")
    from . import detection
    try:
        detection.evaluate(record)
    except Exception:                           # detection must never break the clinic workflow
        current_app.logger.exception("detection rule failed")
    return record


def verify_chain(conn=None):
    """Walk the whole chain. Returns {'ok', 'count', 'bad_id', 'head'}."""
    conn = conn or get_db()
    prev, count = GENESIS, 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        record = {f: row[f] for f in FIELDS}
        if row["prev_hash"] != prev or row["hash"] != _digest(prev, record):
            return {"ok": False, "count": count, "bad_id": row["id"], "head": prev}
        prev, count = row["hash"], count + 1
    return {"ok": True, "count": count, "bad_id": None, "head": prev}
