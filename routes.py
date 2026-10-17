"""Presentation layer: Flask routes (thin - logic lives in services/, SQL in repository.py)."""
import csv
import io
import os
import uuid
from datetime import datetime

from flask import Response, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

import repository as repo
from auth import login_required
from services import analytics, detection
from services.parser import parse_file

ALERT_STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]


def register_routes(app):
    cfg = app.config

    def sid_arg():
        return request.values.get("source_id", type=int) or None

    # ------------------------------------------------------------------ auth
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user = repo.get_user_by_name(request.form.get("username", "").strip())
            if user and user["role"] == "admin" and check_password_hash(user["password_hash"], request.form.get("password", "")):
                session.clear()
                session.update(user_id=user["user_id"], username=user["username"], role=user["role"])
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------- incident dashboard (+ queue)
    @app.route("/")
    @login_required
    def dashboard():
        return render_template("dashboard.html", sources=repo.list_sources(), statuses=ALERT_STATUSES)

    @app.route("/api/dashboard")
    @login_required
    def api_dashboard():
        sid = sid_arg()
        d = analytics.descriptive(repo.fetch_logs_df(sid))
        summ = repo.alert_summary(sid)
        d["alerts"] = summ
        d["kpis"]["open_alerts"] = summ["status"].get("Open", 0)
        d["kpis"]["critical"] = summ["severity"].get("Critical", 0)
        return jsonify(d)

    @app.route("/api/alerts")
    @login_required
    def api_alerts():
        rows = repo.list_alerts(request.args.get("status") or None, request.args.get("severity") or None, sid_arg(), limit=200)
        return jsonify(rows=rows)

    @app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
    @login_required
    def api_alert_status(alert_id):
        status = (request.get_json(silent=True) or {}).get("status")
        if status not in ALERT_STATUSES:
            return jsonify(error="Invalid status"), 400
        repo.update_alert_status(alert_id, status)
        return jsonify(ok=True, status=status)

    # ----------------------------------------------- master data management
    @app.route("/sources", methods=["GET", "POST"])
    @login_required
    def sources():
        if request.method == "POST":
            name, server = request.form.get("source_name", "").strip(), request.form.get("server_name", "").strip()
            if not name or not server:
                flash("Source name and server name are required.", "error")
            else:
                try:
                    repo.create_source(name, server, request.form.get("source_type", "auth"))
                    flash("Log source added.", "success")
                except Exception:
                    flash("A source with that name already exists.", "error")
            return redirect(url_for("sources"))
        return render_template("sources.html", sources=repo.list_sources())

    @app.route("/sources/<int:sid>/edit", methods=["POST"])
    @login_required
    def source_edit(sid):
        try:
            repo.update_source(sid, request.form["source_name"].strip(), request.form["server_name"].strip(),
                               request.form.get("source_type", "auth"))
            flash("Log source updated.", "success")
        except Exception:
            flash("Could not update source (duplicate name?).", "error")
        return redirect(url_for("sources"))

    @app.route("/sources/<int:sid>/delete", methods=["POST"])
    @login_required
    def source_delete(sid):
        repo.delete_source(sid)
        flash("Log source and its logs were deleted.", "success")
        return redirect(url_for("sources"))

    # ----------------------------------------------------- data entry / upload
    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "POST":
            sid, f = request.form.get("source_id", type=int), request.files.get("logfile")
            if not sid or not repo.get_source(sid):
                flash("Select a valid log source.", "error")
                return redirect(url_for("upload"))
            name = secure_filename(f.filename) if f and f.filename else ""
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext not in cfg["ALLOWED_EXTENSIONS"]:
                flash("Only .csv, .txt and .log files are allowed.", "error")
                return redirect(url_for("upload"))
            path = os.path.join(cfg["UPLOAD_FOLDER"], f"{uuid.uuid4().hex[:10]}_{name}")
            f.save(path)
            try:
                df, stats = parse_file(path, ext)
            except ValueError as exc:
                os.remove(path)
                flash(str(exc), "error")
                return redirect(url_for("upload"))
            n = repo.insert_logs(df, sid)
            flash(f"Imported {n} records from {name} ({stats['skipped']} lines skipped).", "success")
            return redirect(url_for("analytics_page", source_id=sid))
        return render_template("upload.html", sources=repo.list_sources())

    # ------------------------------------------------------------- analytics
    @app.route("/analytics")
    @login_required
    def analytics_page():
        return render_template("analytics.html", sources=repo.list_sources(), selected=sid_arg())

    @app.route("/api/analytics")
    @login_required
    def api_analytics():
        df = repo.fetch_logs_df(sid_arg())
        saved = detection.load_saved(cfg["MODEL_FOLDER"])
        return jsonify(descriptive=analytics.descriptive(df), diagnostic=analytics.diagnostic(df, cfg),
                       classification=saved["metrics"] if saved else None,
                       regression=analytics.regression(df), clustering=analytics.clustering(df, cfg),
                       forecast=analytics.forecast(df))

    # ------------------------------------------------------------ prediction
    @app.route("/prediction", methods=["GET", "POST"])
    @login_required
    def prediction():
        if request.method == "POST":
            df = repo.fetch_logs_df(sid_arg())
            if df.empty:
                flash("No logs available. Upload a log file first.", "error")
                return redirect(url_for("upload"))
            result = detection.run_detection(df, cfg, cfg["MODEL_FOLDER"])
            created = repo.insert_alerts(result["flagged"])
            flash(f"Detection complete. Best model: {result['best']}. {created} new alert(s) stored.", "success")
            return redirect(url_for("prediction"))
        return render_template("prediction.html", sources=repo.list_sources(),
                               saved=detection.load_saved(cfg["MODEL_FOLDER"]))

    # --------------------------------------------------------------- history
    @app.route("/history")
    @login_required
    def history():
        return render_template("history.html", alerts=repo.list_alerts(by_time=True, limit=300),
                               saved=detection.load_saved(cfg["MODEL_FOLDER"]))

    # --------------------------------------------------------------- reports
    @app.route("/reports")
    @login_required
    def reports():
        return render_template("reports.html")

    def csv_response(rows, filename):
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.route("/reports/alerts.csv")
    @login_required
    def report_alerts():
        return csv_response(repo.list_alerts(by_time=True, limit=100000), f"alerts_{datetime.now():%Y%m%d_%H%M}.csv")

    @app.route("/reports/logs.csv")
    @login_required
    def report_logs():
        return csv_response(repo.export_logs(), f"security_logs_{datetime.now():%Y%m%d_%H%M}.csv")
