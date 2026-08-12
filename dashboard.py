"""
dashboard.py
-------------
A small Flask web app so the analyzer can be used as an "app" instead
of just a CLI: upload a .pcap in the browser, see the alert dashboard
and download the report.

Run:
    pip install -r requirements.txt
    python3 dashboard.py
    -> open http://127.0.0.1:5000

Requires: flask, scapy
"""
import os
import sys
import uuid

from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import capture              # noqa: E402
from engine import run_all_detectors   # noqa: E402
import report as report_mod            # noqa: E402

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

ALLOWED_EXT = {".pcap", ".pcapng", ".cap"}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload cap


def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXT


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("pcap_file")
    if not file or file.filename == "":
        flash("Please choose a .pcap file to upload.")
        return redirect(url_for("index"))
    if not allowed_file(file.filename):
        flash("Unsupported file type. Please upload a .pcap, .pcapng, or .cap file.")
        return redirect(url_for("index"))

    job_id = uuid.uuid4().hex[:10]
    saved_path = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")
    file.save(saved_path)

    try:
        packets = capture.load_pcap(saved_path)
    except Exception as e:
        flash(f"Failed to parse pcap: {e}")
        return redirect(url_for("index"))

    alerts = run_all_detectors(packets)
    summary = report_mod.build_summary(packets, alerts)

    html_report = report_mod.to_html(packets, alerts, title=f"Report for {file.filename}")
    report_path = os.path.join(REPORT_DIR, f"{job_id}.html")
    with open(report_path, "w") as f:
        f.write(html_report)

    sorted_alerts = sorted(alerts, key=lambda a: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(a.severity, 9))

    return render_template(
        "results.html",
        filename=file.filename,
        summary=summary,
        alerts=[a.to_dict() for a in sorted_alerts],
        job_id=job_id,
    )


@app.route("/download/<job_id>")
def download_report(job_id):
    return send_from_directory(REPORT_DIR, f"{job_id}.html", as_attachment=True,
                                download_name=f"network_report_{job_id}.html")


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
