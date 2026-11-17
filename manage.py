"""SafeHealth command line.  Usage: python manage.py <command>

  seed               create demo staff + synthetic patients (prints the generated passwords)
  backup             encrypted backup; add --copy-to E:\\offline for the offline copy
  restore            restore the latest backup (or --file PATH)
  verify-audit       check the audit-log hash chain
  lab-setup          create the dummy drill files and take the file-integrity baseline
  fim-baseline       re-take the file-integrity baseline
  fim-check          compare files with the baseline (--watch 10 = repeat every 10 s)
  simulate-ransomware  scramble the dummy drill files only (harmless; lab folder only)
  drill              full timed ransomware drill: backup -> attack -> detect -> restore
  lab-totp USER      print USER's current TOTP code (LAB ONLY - for scripted tests)
"""
import argparse
import json
import sys
import time

from safehealth import audit, backup, create_app, fim, seed
from safehealth.crypto import cipher
from safehealth.db import get_db


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command")
    parser.add_argument("user", nargs="?")
    parser.add_argument("--copy-to", action="append", default=[])
    parser.add_argument("--file")
    parser.add_argument("--watch", type=int)
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    try:
        run(parser, args)
    except (backup.BackupError, RuntimeError, FileNotFoundError) as exc:
        sys.exit(f"Refused: {exc}")


def run(parser, args):
    app = create_app()
    with app.app_context():
        cmd = args.command
        if cmd == "seed":
            credentials, path = seed.run()
            for username, role, password in credentials:
                print(f"{username:<8} {role:<13} {password}")
            print(f"\nSaved to {path}. Each user sets up their authenticator app at first login.")
        elif cmd == "backup":
            print(json.dumps(backup.create_backup(args.copy_to), indent=2))
        elif cmd == "restore":
            if not args.yes:
                sys.exit("This replaces the live database. Stop the server, then re-run with --yes")
            print(json.dumps(backup.restore(args.file), indent=2))
        elif cmd == "verify-audit":
            result = audit.verify_chain()
            print(json.dumps(result, indent=2))
            sys.exit(0 if result["ok"] else 1)
        elif cmd == "lab-setup":
            print(f"{fim.make_lab_files()} dummy files created; baseline of {fim.baseline()} files taken.")
        elif cmd == "fim-baseline":
            print(f"Baseline of {fim.baseline()} files taken.")
        elif cmd == "fim-check":
            while True:
                print(time.strftime("%H:%M:%S"), json.dumps(fim.check()))
                if not args.watch:
                    break
                time.sleep(args.watch)
        elif cmd == "simulate-ransomware":
            print(f"{fim.simulate_ransomware()} dummy files scrambled in {app.config['LAB_DIR']}.")
        elif cmd == "drill":
            if not args.yes:
                sys.exit("The drill destroys and restores the live LAB database (a copy is quarantined first).\n"
                         "Anything entered after the drill's backup is lost on purpose. Re-run with --yes")
            print(json.dumps(backup.drill(), indent=2))
        elif cmd == "lab-totp":
            import pyotp
            row = get_db().execute("SELECT totp_secret_enc FROM users WHERE username=?", (args.user or "",)).fetchone()
            if not row or not row["totp_secret_enc"]:
                sys.exit("User not found or MFA not set up yet.")
            print(pyotp.TOTP(cipher().decrypt(row["totp_secret_enc"])).now())
        else:
            parser.error(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
