"""
PHAROS Web - Main Application
-----------------------------
Clean, multi-client Flask web application.
Provides:
- User registration & authentication against user_database/pharos_users.db
- Drag-and-drop document upload (.docx, .docm, .doc)
- Asynchronous multi-threaded scan processing
- Mesmerizing organic animation view during analysis
- Threat intelligence report with LLM explanation placeholder
- Secure binary download of sanitized & reconstructed documents
"""

from __future__ import annotations

import functools
import json
import os
from pathlib import Path

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

import web.db as db
from web.scan_service import get_job_status, submit_scan

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)

app.secret_key = os.environ.get("PHAROS_SECRET_KEY", "pharos-cdr-secret-key-prod-2026")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max file upload


def login_required(view):
    """Decorator ensuring routes require an active user session."""

    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get("user"):
            flash("Please authenticate to access the CDR dashboard.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        ok, msg = db.create_user(username, email, password)
        if ok:
            flash("Registration successful. Please sign in.", "success")
            return redirect(url_for("login"))
        else:
            flash(msg, "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user = db.authenticate_user(username, password)
        if user:
            session["user"] = user
            flash(f"Welcome back, {user['username']}.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please verify username and password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = session["user"]
    recent_scans = db.get_user_scans(user["id"], limit=10)
    return render_template("dashboard.html", recent_scans=recent_scans)


# History page – shows full scan history for the logged‑in user
@app.route("/history")
@login_required
def history():
    user = session["user"]
    # Retrieve up to 50 entries; can be extended later with pagination params
    scans = db.get_user_scans(user["id"], limit=50)
    return render_template("history.html", scans=scans)

# Profile page – view/edit user profile
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = session["user"]
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        ok, msg = db.update_user(user["id"], username=username, email=email, password=password)
        if ok:
            # Refresh session data
            updated_user = db.get_user_by_id(user["id"])
            if updated_user:
                session["user"] = updated_user
            flash(msg, "success")
            return redirect(url_for("profile"))
        else:
            flash(msg, "error")
    # GET – render form with current user info
    user_details = db.get_user_by_id(user["id"])
    return render_template("profile.html", user=user_details)

# CSV export of the user's scan history
@app.route("/history/export")
@login_required
def export_history():
    import csv
    from io import StringIO
    user = session["user"]
    scans = db.get_user_scans(user["id"], limit=1000)
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow([
        "scan_id",
        "file_name",
        "verdict",
        "risk_score",
        "created_at",
    ])
    for row in scans:
        cw.writerow([
            row["scan_id"],
            row["file_name"],
            row["verdict"],
            row["risk_score"],
            row["created_at"],
        ])
    output = si.getvalue()
    return (
        output,
        200,
        {
            "Content-Type": "text/csv",
            "Content-Disposition": f"attachment; filename=pharos_history_{user['username']}.csv",
        },
    )
@login_required
def dashboard():
    user = session["user"]
    recent_scans = db.get_user_scans(user["id"], limit=10)
    return render_template("dashboard.html", recent_scans=recent_scans)


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    """Handle document upload and launch asynchronous scan."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in upload request."}), 400

    uploaded = request.files["file"]
    if not uploaded or uploaded.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    filename = uploaded.filename
    ext = Path(filename).suffix.lower()
    if ext not in [".docx", ".docm", ".doc"]:
        return (
            jsonify(
                {
                    "error": "Only .docx, .docm, and .doc documents are supported in Phase 1."
                }
            ),
            400,
        )

    file_bytes = uploaded.read()
    if len(file_bytes) == 0:
        return jsonify({"error": "Uploaded file is empty (0 bytes)."}), 400

    user_id = session["user"]["id"]
    scan_id = submit_scan(file_bytes, filename, user_id=user_id)

    return jsonify({"scan_id": scan_id, "status": "processing"})


@app.route("/api/scan/<scan_id>/status")
@login_required
def api_scan_status(scan_id: str):
    """Endpoint polled by dashboard JS for real-time progress."""
    status = get_job_status(scan_id)
    return jsonify(status)


@app.route("/report/<scan_id>")
@login_required
def report_view(scan_id: str):
    """View detailed security intelligence report for a completed scan."""
    status = get_job_status(scan_id)
    if status.get("status") != "completed":
        flash("Scan is still in progress or not found.", "error")
        return redirect(url_for("dashboard"))

    result = status.get("result", {})
    from src.pipeline.report import build_report

    report_obj = build_report(result)

    sanitized_available = bool(
        status.get("sanitized_file_path")
        and Path(status["sanitized_file_path"]).exists()
    )

    return render_template(
        "report.html",
        scan_id=scan_id,
        report=report_obj,
        sanitized_download_available=sanitized_available,
    )


@app.route("/download/<scan_id>")
@login_required
def download_sanitized(scan_id: str):
    """Download the sanitized, reconstructed .docx deliverable."""
    status = get_job_status(scan_id)
    file_path = status.get("sanitized_file_path")

    if not file_path or not Path(file_path).exists():
        flash(
            "Sanitized document not available or reconstruction was not required.",
            "error",
        )
        return redirect(url_for("report_view", scan_id=scan_id))

    path_obj = Path(file_path)
    return send_file(
        path_obj,
        as_attachment=True,
        download_name=path_obj.name,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
