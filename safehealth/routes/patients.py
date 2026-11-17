"""FR1, FR2, FR4: patients, medical records, vitals, prescriptions - filtered by role and assignment."""
import json
import time

from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import audit, sessions, validators as v
from ..crypto import cipher
from ..db import get_db
from ..rbac import RECORD_SCOPE, patient_or_403, require

bp = Blueprint("patients", __name__, url_prefix="/patients")
GENDERS = ("Female", "Male", "Other")


def _like(term):
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@bp.route("/")
@require("patients.list")
def index():
    db, q = get_db(), (request.args.get("q") or "").strip()[:80]
    if g.user["role"] == "receptionist":
        rows = db.execute("SELECT id, full_name, dob, phone FROM patients WHERE full_name LIKE ? ESCAPE '\\'"
                          " ORDER BY full_name LIMIT 200", (_like(q),)).fetchall()
    else:   # doctors and nurses only ever see their assigned patients
        rows = db.execute(
            "SELECT p.id, p.full_name, p.dob, p.phone FROM patients p JOIN assignments a ON a.patient_id=p.id"
            " WHERE a.user_id=? AND p.full_name LIKE ? ESCAPE '\\' ORDER BY p.full_name LIMIT 200",
            (g.user["id"], _like(q))).fetchall()
    audit.log("patients.list", detail={"q": q, "results": len(rows)})
    return render_template("patients/list.html", patients=rows, q=q)


def _demographics(form):
    return {
        "full_name": v.text(form, "full_name", "Full name", 80, pattern=v.NAME),
        "dob": v.past_date(form, "dob", "Date of birth"),
        "gender": v.choice(form, "gender", "Gender", GENDERS),
        "phone": v.text(form, "phone", "Phone", 18, pattern=v.PHONE),
        "address": v.text(form, "address", "Address", 200, required=False),
    }


@bp.route("/new", methods=["GET", "POST"])
@require("patients.register")
def new():
    if request.method == "POST":
        try:
            d = _demographics(request.form)
        except v.Invalid as exc:
            return render_template("patients/form.html", patient=None, form=request.form,
                                   genders=GENDERS, error=str(exc)), 400
        db, now = get_db(), time.time()
        cur = db.execute(
            "INSERT INTO patients (full_name,dob,gender,phone,address_enc,created_by,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (d["full_name"], d["dob"], d["gender"], d["phone"], cipher().encrypt(d["address"]), g.user["id"], now, now))
        db.commit()
        audit.log("patient.create", patient_id=cur.lastrowid)
        sessions.flash("Patient registered. Assign a doctor and nurse below.", "ok")
        return redirect(url_for("patients.detail", patient_id=cur.lastrowid))
    return render_template("patients/form.html", patient=None, form={}, genders=GENDERS)


@bp.route("/<int:patient_id>")
@require("patient.view")
def detail(patient_id):
    patient = patient_or_403(patient_id)
    db, c, scope = get_db(), cipher(), RECORD_SCOPE[g.user["role"]]
    # Only the fields this role may see are ever decrypted - not just hidden in the template.
    record = {"id": patient["id"], "full_name": patient["full_name"], "dob": patient["dob"],
              "gender": patient["gender"], "phone": patient["phone"], "address": c.decrypt(patient["address_enc"])}
    if "allergies" in scope:
        record["allergies"] = c.decrypt(patient["allergies_enc"])
    if "diagnosis" in scope:
        record["diagnosis"] = c.decrypt(patient["diagnosis_enc"])
    if "history" in scope:
        record["history"] = c.decrypt(patient["history_enc"])
    vitals, prescriptions, appointments, team, staff = [], [], [], [], []
    if "vitals" in scope:
        for row in db.execute("SELECT v.*, u.full_name AS by_name FROM vitals v JOIN users u ON u.id=v.recorded_by"
                              " WHERE v.patient_id=? ORDER BY v.recorded_at DESC LIMIT 20", (patient_id,)):
            item = dict(row)
            item["notes"] = c.decrypt(row["notes_enc"])
            vitals.append(item)
    if "prescriptions" in scope:
        for row in db.execute("SELECT p.*, u.full_name AS doctor FROM prescriptions p JOIN users u ON u.id=p.doctor_id"
                              " WHERE p.patient_id=? ORDER BY p.created_at DESC", (patient_id,)):
            item = json.loads(c.decrypt(row["body_enc"]))
            item.update(created_at=row["created_at"], doctor=row["doctor"])
            prescriptions.append(item)
    if "appointments" in scope:
        appointments = db.execute(
            "SELECT a.*, u.full_name AS doctor FROM appointments a JOIN users u ON u.id=a.doctor_id"
            " WHERE a.patient_id=? ORDER BY a.scheduled_at DESC", (patient_id,)).fetchall()
    if "care_team" in scope:
        team = db.execute("SELECT u.id, u.full_name, u.role FROM assignments a JOIN users u ON u.id=a.user_id"
                          " WHERE a.patient_id=? ORDER BY u.role, u.full_name", (patient_id,)).fetchall()
        staff = db.execute("SELECT id, full_name, role FROM users WHERE role IN ('doctor','nurse') AND is_active=1"
                           " ORDER BY role, full_name").fetchall()
    audit.log("patient.view", patient_id=patient_id, detail={"scope": sorted(scope)})
    return render_template("patients/detail.html", p=record, scope=scope, vitals=vitals,
                           prescriptions=prescriptions, appointments=appointments, team=team, staff=staff)


@bp.route("/<int:patient_id>/edit", methods=["GET", "POST"])
@require("patients.register")
def edit(patient_id):
    patient = patient_or_403(patient_id)
    if request.method == "POST":
        try:
            d = _demographics(request.form)
        except v.Invalid as exc:
            return render_template("patients/form.html", patient=patient, form=request.form,
                                   genders=GENDERS, error=str(exc)), 400
        db = get_db()
        db.execute("UPDATE patients SET full_name=?, dob=?, gender=?, phone=?, address_enc=?, updated_at=? WHERE id=?",
                   (d["full_name"], d["dob"], d["gender"], d["phone"], cipher().encrypt(d["address"]),
                    time.time(), patient_id))
        db.commit()
        audit.log("patient.update", patient_id=patient_id, detail={"section": "demographics"})
        sessions.flash("Patient details updated.", "ok")
        return redirect(url_for("patients.detail", patient_id=patient_id))
    form = dict(patient)
    form["address"] = cipher().decrypt(patient["address_enc"])
    audit.log("patient.view", patient_id=patient_id, detail={"scope": ["contact"], "page": "edit"})
    return render_template("patients/form.html", patient=patient, form=form, genders=GENDERS)


@bp.route("/<int:patient_id>/clinical", methods=["POST"])
@require("clinical.update")
def clinical(patient_id):
    patient_or_403(patient_id)
    try:
        allergies = v.text(request.form, "allergies", "Allergies", 500, required=False, multiline=True)
        diagnosis = v.text(request.form, "diagnosis", "Diagnosis", 1000, required=False, multiline=True)
        history = v.text(request.form, "history", "Medical history", 4000, required=False, multiline=True)
    except v.Invalid as exc:
        sessions.flash(str(exc), "error")
        return redirect(url_for("patients.detail", patient_id=patient_id))
    db, c = get_db(), cipher()
    db.execute("UPDATE patients SET allergies_enc=?, diagnosis_enc=?, history_enc=?, updated_at=? WHERE id=?",
               (c.encrypt(allergies), c.encrypt(diagnosis), c.encrypt(history), time.time(), patient_id))
    db.commit()
    audit.log("clinical.update", patient_id=patient_id)
    sessions.flash("Clinical record updated.", "ok")
    return redirect(url_for("patients.detail", patient_id=patient_id))


@bp.route("/<int:patient_id>/vitals", methods=["POST"])
@require("vitals.record")
def vitals(patient_id):
    patient_or_403(patient_id)
    f = request.form
    try:
        values = (v.number(f, "temperature", "Temperature", 30, 45),
                  v.number(f, "pulse", "Pulse", 20, 250, kind=int),
                  v.number(f, "bp_sys", "Systolic BP", 50, 260, kind=int),
                  v.number(f, "bp_dia", "Diastolic BP", 30, 160, kind=int),
                  v.number(f, "spo2", "SpO2", 50, 100, kind=int))
        notes = v.text(f, "notes", "Observations", 500, required=False, multiline=True)
        if all(x is None for x in values) and not notes:
            raise v.Invalid("Enter at least one vital sign or an observation.")
    except v.Invalid as exc:
        sessions.flash(str(exc), "error")
        return redirect(url_for("patients.detail", patient_id=patient_id))
    db = get_db()
    db.execute("INSERT INTO vitals (patient_id,recorded_by,recorded_at,temperature,pulse,bp_sys,bp_dia,spo2,notes_enc)"
               " VALUES (?,?,?,?,?,?,?,?,?)", (patient_id, g.user["id"], time.time(), *values, cipher().encrypt(notes)))
    db.commit()
    audit.log("vitals.record", patient_id=patient_id)
    sessions.flash("Vitals recorded.", "ok")
    return redirect(url_for("patients.detail", patient_id=patient_id))


@bp.route("/<int:patient_id>/prescriptions", methods=["POST"])
@require("prescriptions.add")
def prescribe(patient_id):
    patient_or_403(patient_id)
    try:
        body = {"drug": v.text(request.form, "drug", "Medicine", 100),
                "dosage": v.text(request.form, "dosage", "Dosage", 100),
                "instructions": v.text(request.form, "instructions", "Instructions", 300, required=False, multiline=True)}
    except v.Invalid as exc:
        sessions.flash(str(exc), "error")
        return redirect(url_for("patients.detail", patient_id=patient_id))
    db = get_db()
    db.execute("INSERT INTO prescriptions (patient_id,doctor_id,created_at,body_enc) VALUES (?,?,?,?)",
               (patient_id, g.user["id"], time.time(), cipher().encrypt(json.dumps(body))))
    db.commit()
    audit.log("prescription.add", patient_id=patient_id)
    sessions.flash("Prescription added.", "ok")
    return redirect(url_for("patients.detail", patient_id=patient_id))


@bp.route("/<int:patient_id>/team", methods=["POST"])
@require("care_team.manage")
def team(patient_id):
    patient_or_403(patient_id)
    db = get_db()
    try:
        staff_id = v.number(request.form, "user_id", "Staff member", 1, 10**9, required=True, kind=int)
        action = v.choice(request.form, "action", "Action", ("assign", "remove"))
    except v.Invalid as exc:
        sessions.flash(str(exc), "error")
        return redirect(url_for("patients.detail", patient_id=patient_id))
    staff = db.execute("SELECT id FROM users WHERE id=? AND role IN ('doctor','nurse') AND is_active=1",
                       (staff_id,)).fetchone()
    if staff is None:
        sessions.flash("Choose an active doctor or nurse.", "error")
    elif action == "assign":
        db.execute("INSERT OR IGNORE INTO assignments (patient_id,user_id) VALUES (?,?)", (patient_id, staff_id))
        db.commit()
        audit.log("care_team.assign", patient_id=patient_id, detail={"staff_id": staff_id})
    else:
        db.execute("DELETE FROM assignments WHERE patient_id=? AND user_id=?", (patient_id, staff_id))
        db.commit()
        audit.log("care_team.remove", patient_id=patient_id, detail={"staff_id": staff_id})
    return redirect(url_for("patients.detail", patient_id=patient_id))
