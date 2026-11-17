"""FR3: appointments. Receptionists manage all of them; doctors see only their own."""
import time

from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import audit, sessions, validators as v
from ..db import get_db
from ..rbac import require

bp = Blueprint("appointments", __name__, url_prefix="/appointments")
STATUSES = ("scheduled", "completed", "cancelled")


@bp.route("/")
@require("appointments.view")
def index():
    db = get_db()
    sql = ("SELECT a.*, p.full_name AS patient, u.full_name AS doctor FROM appointments a"
           " JOIN patients p ON p.id=a.patient_id JOIN users u ON u.id=a.doctor_id")
    if g.user["role"] == "doctor":
        rows = db.execute(sql + " WHERE a.doctor_id=? ORDER BY a.scheduled_at DESC LIMIT 200", (g.user["id"],)).fetchall()
    else:
        rows = db.execute(sql + " ORDER BY a.scheduled_at DESC LIMIT 200").fetchall()
    audit.log("appointments.list", detail={"results": len(rows)})
    return render_template("appointments/list.html", appointments=rows, statuses=STATUSES)


@bp.route("/new", methods=["GET", "POST"])
@require("appointments.manage")
def new():
    db = get_db()
    patients = db.execute("SELECT id, full_name FROM patients ORDER BY full_name").fetchall()
    doctors = db.execute("SELECT id, full_name FROM users WHERE role='doctor' AND is_active=1 ORDER BY full_name").fetchall()
    if request.method == "POST":
        try:
            patient_id = v.number(request.form, "patient_id", "Patient", 1, 10**9, required=True, kind=int)
            doctor_id = v.number(request.form, "doctor_id", "Doctor", 1, 10**9, required=True, kind=int)
            scheduled = v.when(request.form, "scheduled_at", "Date and time")
            note = v.text(request.form, "note", "Note", 200, required=False)
            if patient_id not in {p["id"] for p in patients} or doctor_id not in {d["id"] for d in doctors}:
                raise v.Invalid("Choose a patient and a doctor from the lists.")
        except v.Invalid as exc:
            return render_template("appointments/form.html", patients=patients, doctors=doctors,
                                   form=request.form, error=str(exc)), 400
        cur = db.execute("INSERT INTO appointments (patient_id,doctor_id,scheduled_at,note,created_by,created_at)"
                         " VALUES (?,?,?,?,?,?)", (patient_id, doctor_id, scheduled, note, g.user["id"], time.time()))
        # Booking with a doctor puts that doctor on the patient's care team (this is how "assigned" starts).
        db.execute("INSERT OR IGNORE INTO assignments (patient_id,user_id) VALUES (?,?)", (patient_id, doctor_id))
        db.commit()
        audit.log("appointment.create", patient_id=patient_id, detail={"appointment_id": cur.lastrowid, "doctor_id": doctor_id})
        sessions.flash("Appointment booked.", "ok")
        return redirect(url_for("appointments.index"))
    return render_template("appointments/form.html", patients=patients, doctors=doctors,
                           form={"patient_id": request.args.get("patient_id", "")})


@bp.route("/<int:appointment_id>/status", methods=["POST"])
@require("appointments.manage")
def status(appointment_id):
    db = get_db()
    row = db.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()
    if row is None:
        return redirect(url_for("appointments.index"))
    try:
        new_status = v.choice(request.form, "status", "Status", STATUSES)
    except v.Invalid as exc:
        sessions.flash(str(exc), "error")
        return redirect(url_for("appointments.index"))
    db.execute("UPDATE appointments SET status=? WHERE id=?", (new_status, appointment_id))
    db.commit()
    audit.log("appointment.update", patient_id=row["patient_id"],
              detail={"appointment_id": appointment_id, "status": new_status})
    return redirect(url_for("appointments.index"))
