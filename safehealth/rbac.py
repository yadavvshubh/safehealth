"""SR4: role-based access control, enforced on the server for every request, default deny.

Every view must declare a policy with one of the decorators below. A view without a policy is
refused, so forgetting to protect a new page fails closed. The table mirrors section 9.3 of the proposal.
"""
from flask import abort, current_app, g, redirect, request, url_for

from . import audit
from .db import get_db

PERMISSIONS = {
    "admin": {"users.manage", "security.view"},
    "doctor": {"patients.list", "patient.view", "clinical.update", "prescriptions.add",
               "vitals.record", "appointments.view"},
    "nurse": {"patients.list", "patient.view", "vitals.record"},
    "receptionist": {"patients.list", "patient.view", "patients.register", "care_team.manage",
                     "appointments.view", "appointments.manage"},
}

# What each role may see inside a patient record (field-level, applied before decryption).
RECORD_SCOPE = {
    "doctor": {"contact", "allergies", "diagnosis", "history", "vitals", "prescriptions"},
    "nurse": {"contact", "allergies", "diagnosis", "vitals"},          # "Assigned (limited)"
    "receptionist": {"contact", "appointments", "care_team"},
}


def _policy(kind, permission=None):
    def decorator(view):
        view._policy = (kind, permission)
        return view
    return decorator


public = _policy("public")                 # login page only
mfa_stage = _policy("mfa")                 # password verified, second factor pending
authenticated = _policy("auth")            # any fully logged-in user


def require(permission):
    return _policy("perm", permission)


def can(permission):
    user = g.get("user")
    return bool(user) and permission in PERMISSIONS.get(user["role"], ())


def deny(reason, patient_id=None, **extra):
    """Refuse, write the audit entry (which feeds the detection rules), and return 403."""
    detail = {"reason": reason, "method": request.method, "path": request.path}
    detail.update(extra)
    audit.log("access.denied", result="denied", patient_id=patient_id, detail=detail)
    abort(403)


def enforce():
    """before_request hook: the single place where route access is decided."""
    if request.endpoint is None or request.endpoint == "static":
        return None
    view = current_app.view_functions.get(request.endpoint)
    kind, permission = getattr(view, "_policy", (None, None))
    if kind == "public":
        return None
    if kind == "mfa":
        return None if g.pending_user is not None else redirect(url_for("auth.login"))
    if g.user is None:
        return redirect(url_for("auth.login"))
    if kind == "auth":
        return None
    if kind != "perm":
        deny("no_policy")
    if permission not in PERMISSIONS.get(g.user["role"], ()):
        deny("role", required=permission)
    return None


def patient_or_403(patient_id):
    """Object-level check (stops IDOR): clinical staff only reach patients assigned to them."""
    db = get_db()
    role = g.user["role"]
    if role in ("doctor", "nurse"):
        assigned = db.execute(
            "SELECT 1 FROM assignments WHERE patient_id=? AND user_id=?", (patient_id, g.user["id"])
        ).fetchone()
        if not assigned:      # same answer whether the patient exists or not
            deny("assignment", patient_id=patient_id)
    elif role != "receptionist":
        deny("role", patient_id=patient_id)
    patient = db.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if patient is None:
        abort(404)
    return patient
