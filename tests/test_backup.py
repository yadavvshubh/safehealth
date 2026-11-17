"""SR11 + success criteria: encrypted backup, verified restore, timed ransomware drill."""
from pathlib import Path

import pytest

from conftest import rows
from safehealth import audit, backup, fim
from safehealth.db import get_db


def test_backup_is_encrypted_and_restores(app, tmp_path):
    offline = tmp_path / "usb"
    with app.app_context():
        made = backup.create_backup(copy_to=[offline])
        blob = Path(made["path"]).read_bytes()
        assert b"SQLite format 3" not in blob and b"Test Patient" not in blob
        assert (offline / made["file"]).exists() and len(made["copies"]) == 2
        get_db().execute("DELETE FROM patients")
        get_db().commit()
        result = backup.restore()
        assert get_db().execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 20
        assert Path(result["quarantined"]).exists() and audit.verify_chain()["ok"]
        assert backup.restore(offline / made["file"])["audit_entries"] >= 1      # offline copy works too


def test_tampered_backup_is_refused(app):
    with app.app_context():
        made = backup.create_backup()
        path = Path(made["path"])
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 1
        path.write_bytes(bytes(data))
        with pytest.raises(backup.BackupError):
            backup.restore()
        Path(str(path) + ".json").unlink()                         # even without the manifest, Fernet refuses
        with pytest.raises(backup.BackupError):
            backup.restore()
        assert get_db().execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 20   # live data untouched


def test_backup_key_is_separate_and_outside_database(app):
    with app.app_context():
        backup.create_backup()
    keys = Path(app.config["KEY_DIR"])
    assert (keys / "field.key").read_bytes() != (keys / "backup.key").read_bytes()
    assert (keys / "field.key").read_bytes().strip() not in open(app.config["DB_PATH"], "rb").read()


def test_fim_detects_simulated_ransomware_only_in_lab_folder(app, tmp_path):
    with app.app_context():
        fim.make_lab_files()
        fim.baseline()
        assert fim.check() == {"changed": 0, "missing": 0, "new": 0, "alert_id": None}
        outside = tmp_path / "important.txt"
        outside.write_text("must survive")
        assert fim.simulate_ransomware() == 30
        result = fim.check()
        assert result["missing"] == 30 and result["new"] == 30 and result["alert_id"]
        assert outside.read_text() == "must survive"
    alert = rows(app, "SELECT * FROM alerts WHERE rule='ransomware_file_integrity'")
    assert len(alert) == 1 and alert[0]["severity"] == "High"


def test_simulator_refuses_uninitialised_folder(app):
    with app.app_context():
        with pytest.raises(RuntimeError):
            fim.simulate_ransomware()


def test_full_ransomware_drill_meets_targets(app):
    with app.app_context():
        report = backup.drill()
        rec = report["recovery"]
        assert report["detection"]["alert_id"] and report["detection"]["seconds_to_alert"] < 60
        assert rec["rto_met"] and rec["restore_seconds"] < 30 * 60
        assert rec["rpo_met"] and rec["audit_chain_ok_after_restore"]
        assert rec["audit_entries_lost"] >= 1                      # honest: post-backup work is lost
        assert get_db().execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 20
    assert Path(app.config["INSTANCE"], "drill_report.json").exists()
