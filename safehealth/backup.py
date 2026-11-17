"""SR11: encrypted backups, extra/offline copies, verified restore and the timed ransomware drill."""
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from . import audit, db as dbmod, fim
from .crypto import load_or_create_key


class BackupError(Exception):
    pass


def _fernet():
    # A separate key from the field key, so one leaked key does not expose everything.
    key = load_or_create_key(Path(current_app.config["KEY_DIR"]) / "backup.key", "SAFEHEALTH_BACKUP_KEY")
    return Fernet(key)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def create_backup(copy_to=()):
    """Consistent snapshot (SQLite online-backup API) -> encrypt -> write with a manifest."""
    cfg = current_app.config
    chain = audit.verify_chain()
    audit.log("backup.create", system=True, detail={"audit_entries": chain["count"] + 1})
    dbmod.get_db().commit()
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "snapshot.db"
        src, dst = sqlite3.connect(cfg["DB_PATH"]), sqlite3.connect(snapshot)
        try:
            src.backup(dst)
        finally:
            src.close(); dst.close()
        plain = snapshot.read_bytes()
    blob = _fernet().encrypt(plain)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    name = f"safehealth-{stamp}.db.enc"
    manifest = {"file": name, "created": time.time(), "sha256": _sha256(blob), "bytes": len(blob),
                "audit_chain_ok": chain["ok"]}
    targets = [Path(cfg["BACKUP_DIR"])] + [Path(p) for p in copy_to]
    for folder in targets:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(blob)
        (folder / (name + ".json")).write_text(json.dumps(manifest, indent=2))
    _prune(Path(cfg["BACKUP_DIR"]), cfg["BACKUP_KEEP"])
    manifest["path"] = str(targets[0] / name)
    manifest["copies"] = [str(t / name) for t in targets]
    return manifest


def _prune(folder, keep):
    backups = sorted(folder.glob("safehealth-*.db.enc"))
    for old in backups[:-keep]:
        old.unlink()
        Path(str(old) + ".json").unlink(missing_ok=True)


def latest_backup(folder=None):
    backups = sorted(Path(folder or current_app.config["BACKUP_DIR"]).glob("safehealth-*.db.enc"))
    if not backups:
        raise BackupError("No backups found.")
    return backups[-1]


def restore(backup_file=None):
    """Verify, decrypt, check, then swap in. The damaged database is kept in quarantine as evidence."""
    cfg = current_app.config
    started = time.time()
    backup_file = Path(backup_file) if backup_file else latest_backup()
    blob = backup_file.read_bytes()
    manifest_path = Path(str(backup_file) + ".json")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest["sha256"] != _sha256(blob):
            raise BackupError("Backup file does not match its manifest checksum - refusing to restore.")
    try:
        plain = _fernet().decrypt(blob)          # Fernet also authenticates: a modified backup fails here
    except InvalidToken:
        raise BackupError("Backup cannot be decrypted (wrong key or tampered file).") from None

    live = Path(cfg["DB_PATH"])
    candidate = live.with_suffix(".restoring")
    candidate.write_bytes(plain)
    conn = dbmod.connect(candidate)
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise BackupError("Restored database failed SQLite integrity_check.")
        chain = audit.verify_chain(conn)
        if not chain["ok"]:
            raise BackupError(f"Audit chain in the backup is broken at entry {chain['bad_id']}.")
    finally:
        conn.close()

    dbmod.close_db()
    quarantined = None
    if live.exists():
        quarantine = Path(cfg["QUARANTINE_DIR"])
        quarantine.mkdir(parents=True, exist_ok=True)
        quarantined = quarantine / f"safehealth-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.db"
        shutil.move(str(live), str(quarantined))
    os.replace(candidate, live)
    seconds = time.time() - started
    audit.log("backup.restore", system=True, detail={"file": backup_file.name, "seconds": round(seconds, 3)})
    dbmod.get_db().execute("DELETE FROM sessions")          # everyone signs in again after an incident
    dbmod.get_db().commit()
    return {"file": str(backup_file), "seconds": seconds, "audit_entries": chain["count"],
            "quarantined": str(quarantined) if quarantined else None}


def drill():
    """Timed ransomware exercise (proposal 8.4 / demo step 5). Lab use only.

    1. take a backup          2. do some work after it (this is what will be lost)
    3. scramble the dummy lab files and detect it with file-integrity monitoring
    4. destroy the live database file (a copy of the real one goes to quarantine first)
    5. restore from the backup and measure time and data lost
    """
    cfg = current_app.config
    report = {"started": datetime.now().isoformat(timespec="seconds")}
    backup = create_backup()
    audit.log("drill.post_backup_activity", system=True, detail={"note": "work done after the last backup"})

    fim.make_lab_files()
    fim.baseline()
    t_attack = time.time()
    scrambled = fim.simulate_ransomware()
    finding = fim.check()
    report["detection"] = {"files_scrambled": scrambled, "files_flagged": finding["changed"] + finding["missing"],
                           "alert_id": finding["alert_id"], "seconds_to_alert": round(time.time() - t_attack, 3)}

    entries_before = dbmod.get_db().execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    live = Path(cfg["DB_PATH"])
    dbmod.close_db()
    quarantine = Path(cfg["QUARANTINE_DIR"])
    quarantine.mkdir(parents=True, exist_ok=True)
    shutil.copy2(live, quarantine / f"pre-drill-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db")
    live.write_bytes(os.urandom(4096))                      # the "encrypted" database: unreadable garbage
    t_incident = time.time()

    result = restore(backup["path"])
    entries_after = dbmod.get_db().execute(
        "SELECT COUNT(*) FROM audit_log WHERE action NOT IN ('backup.restore')").fetchone()[0]
    restore_seconds = time.time() - t_incident
    data_loss_seconds = t_incident - backup["created"]
    report["recovery"] = {
        "backup_used": Path(result["file"]).name,
        "restore_seconds": round(restore_seconds, 3),
        "rto_target_seconds": cfg["RTO_SECONDS"],
        "rto_met": restore_seconds <= cfg["RTO_SECONDS"],
        "data_loss_window_seconds": round(data_loss_seconds, 3),
        "rpo_target_seconds": cfg["RPO_SECONDS"],
        "rpo_met": data_loss_seconds <= cfg["RPO_SECONDS"],
        "audit_entries_lost": entries_before - entries_after,
        "audit_chain_ok_after_restore": audit.verify_chain()["ok"],
    }
    fim.make_lab_files()                                    # reset the lab folder for the next run
    fim.baseline()
    audit.log("drill.completed", system=True, detail=report["recovery"])
    Path(cfg["INSTANCE"], "drill_report.json").write_text(json.dumps(report, indent=2))
    return report
