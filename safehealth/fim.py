"""File-integrity monitoring and the harmless ransomware *simulator* for the recovery drill.

Safety design: the simulator has no path argument. It only ever touches the dummy files that
make_lab_files() itself generated inside LAB_DIR (checked against a marker and a manifest), and
it only overwrites them with random bytes. It contains no encryption, spreading or persistence.
"""
import hashlib
import json
import os
from pathlib import Path

from flask import current_app

MARKER = ".safehealth_lab_folder"
MANIFEST = ".lab_manifest.json"
LAB_FILE_COUNT = 30


def _lab():
    return Path(current_app.config["LAB_DIR"])


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def make_lab_files():
    """(Re)create the dummy 'clinic documents' used only for the drill."""
    lab = _lab()
    lab.mkdir(parents=True, exist_ok=True)
    (lab / MARKER).write_text("Dummy files for the SafeHealth ransomware drill. Nothing here is real.\n")
    for stale in lab.glob("*.locked"):
        stale.unlink()
    names = []
    for i in range(1, LAB_FILE_COUNT + 1):
        name = f"dummy_report_{i:02d}.txt"
        (lab / name).write_text(f"SYNTHETIC LAB FILE {i}\n" + "This is placeholder text for the drill.\n" * 20)
        names.append(name)
    (lab / MANIFEST).write_text(json.dumps(names))
    return len(names)


def _watched():
    return sorted(p for p in _lab().iterdir() if p.is_file() and p.name not in (MARKER, MANIFEST))


def baseline():
    hashes = {p.name: _hash(p) for p in _watched()}
    Path(current_app.config["FIM_BASELINE"]).write_text(json.dumps(hashes, indent=1))
    return len(hashes)


def check():
    """Compare the folder with the baseline; many changes at once raises a High alert."""
    from . import detection
    baseline_path = Path(current_app.config["FIM_BASELINE"])
    if not baseline_path.exists():
        raise FileNotFoundError("No FIM baseline yet - run: python manage.py fim-baseline")
    known = json.loads(baseline_path.read_text())
    current = {p.name: _hash(p) for p in _watched()}
    changed = [n for n in known if n in current and current[n] != known[n]]
    missing = [n for n in known if n not in current]
    new = [n for n in current if n not in known]
    result = {"changed": len(changed), "missing": len(missing), "new": len(new), "alert_id": None}
    if len(changed) + len(missing) >= current_app.config["FIM_CHANGE_THRESHOLD"]:
        result["alert_id"] = detection.raise_alert(
            "ransomware_file_integrity", "High",
            f"{len(changed) + len(missing)} monitored files were modified or removed at once"
            f" ({len(new)} new files appeared) - possible ransomware",
            key="fim", evidence={"changed": changed[:10], "missing": missing[:10], "new": new[:10]},
            response="Isolate the host, preserve logs, restore from the last clean backup (see docs/RUNBOOKS.md).")
    return result


def simulate_ransomware():
    """Scramble ONLY the generated dummy files. Returns how many were hit."""
    lab = _lab()
    if not (lab / MARKER).exists() or not (lab / MANIFEST).exists():
        raise RuntimeError("Lab folder is not initialised - run: python manage.py lab-setup")
    count = 0
    for name in json.loads((lab / MANIFEST).read_text()):
        path = lab / Path(name).name                 # never leaves the lab folder
        if path.is_file() and not path.is_symlink() and path.name.startswith("dummy_report_"):
            path.write_bytes(os.urandom(256))
            path.rename(path.with_suffix(".locked"))
            count += 1
    return count
