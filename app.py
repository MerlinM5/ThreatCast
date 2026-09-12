import os
import ssl
from flask import Flask, render_template, jsonify, request, send_file
from core.detection_engine import DetectionEngine
from core.saii_engine import SAIIEngine
from datetime import datetime
import json
import csv
from io import BytesIO, StringIO
import threading
import uuid

# Initialize App
app = Flask(__name__)
engine = DetectionEngine()
saii_engine = SAIIEngine()

# =========================
# ✅ SOC WORK AREA (In-Memory) + Investigation Fields
# =========================
SOC_ALERTS = {}  # alert_id -> dict
SOC_LOCK = threading.Lock()


def _now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _packet_to_soc_alert(packet: dict) -> dict:
    """
    Converts a Sentinel packet into a SOC alert object (case-like structure).
    Includes investigation fields:
    - assignee, status, priority, case_summary, notes
    """
    log = packet.get("detection_log", {}) or {}
    sev_raw = (packet.get("severity") or "LOW").lower()

    if sev_raw == "critical":
        severity = "critical"
    elif sev_raw == "high":
        severity = "high"
    elif sev_raw == "medium":
        severity = "medium"
    else:
        severity = "low"

    alert_id = str(uuid.uuid4())

    return {
        "id": alert_id,
        "created_at": _now_iso(),
        "title": f"{packet.get('type', 'Alert')} ({packet.get('protocol', 'N/A')})",
        "summary": log.get("reason") or packet.get("info") or "Suspicious activity detected.",
        "source": log.get("source") or "sentinel",
        "severity": severity,

        # ✅ Investigation fields
        "status": "new",
        "assignee": None,
        "priority": "p3",
        "case_summary": "",

        "hybrid_threat_score": packet.get("ml_score"),
        "asset": packet.get("destination"),
        "ip": packet.get("source"),
        "tags": [str(packet.get("protocol", "")).lower(), str(packet.get("type", "")).lower()],
        "notes": [],

        # keep raw packet for drilldown
        "raw_packet": packet
    }


def _seed_soc_if_empty():
    """
    Seeds demo alerts only if SOC is empty.
    """
    with SOC_LOCK:
        if SOC_ALERTS:
            return

        demo_packets = [
            {
                "severity": "HIGH",
                "type": "Credential Phishing",
                "protocol": "HTTPS",
                "source": "192.168.1.22",
                "destination": "10.0.0.5",
                "ml_score": 0.86,
                "info": "HTTPS REQUEST TO http://secure-login.example/verify",
                "detection_log": {"source": "SAII", "reason": "Semantic patterns suggest credential theft."}
            },
            {
                "severity": "CRITICAL",
                "type": "SQL Injection",
                "protocol": "HTTP",
                "source": "10.0.0.14",
                "destination": "10.0.0.5",
                "ml_score": 0.93,
                "info": "HTTP GET /api/v1/query_db?q=' OR 1=1 --",
                "detection_log": {"source": "Rule-Engine", "reason": "Matched SQLi payload signature."}
            },
            {
                "severity": "MEDIUM",
                "type": "Reconnaissance",
                "protocol": "TCP",
                "source": "172.16.0.9",
                "destination": "192.168.1.1",
                "ml_score": 0.61,
                "info": "Port sweep-like behavior detected.",
                "detection_log": {"source": "Heuristic", "reason": "High connection attempts across ports."}
            },
        ]

        for p in demo_packets:
            a = _packet_to_soc_alert(p)
            SOC_ALERTS[a["id"]] = a


# =========================
# --- Application Routes ---
# =========================

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/monitor")
def monitor():
    return render_template("monitor.html")


@app.route("/processor")
def processor():
    return render_template("processor.html")


@app.route("/semantic")
def semantic():
    return render_template("semantic.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ✅ NEW: SOC Work Area UI
@app.route("/soc")
def soc():
    _seed_soc_if_empty()
    return render_template("soc.html")


# =========================
# --- API Routes ---
# =========================

@app.route("/api/control", methods=["POST"])
def control_traffic():
    action = request.json.get("action")
    if action == "start":
        engine.start_generator()
        return jsonify({"status": "started", "message": f"Traffic Generator Active (Hybrid Detection System) with {len(engine.threads)} threads."})
    elif action == "stop":
        engine.stop_generator()
        return jsonify({"status": "stopped", "message": "Traffic Generator Halted"}), 202
    elif action == "clear":
        engine.clear_packets()
        return jsonify({"status": "cleared", "message": "Buffer Cleared"}), 202
    return jsonify({"error": "Invalid action"}), 400


@app.route("/api/packets")
def get_packets():
    return jsonify(engine.get_packets())


@app.route("/api/analyze_intent", methods=["POST"])
def analyze_intent():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL parameter is missing."}), 400

    result = saii_engine.analyze_url(url)

    if result.get("error"):
        return jsonify(result), 400

    return jsonify(result)


@app.route("/api/process_ip_range", methods=["POST"])
def process_ip_range():
    data = request.json
    start_ip = data.get("start_ip")
    end_ip = data.get("end_ip")

    if not start_ip or not end_ip:
        return jsonify({"error": "Start IP and End IP are required."}), 400

    status, packets = engine.generate_simulated_ipdr_data(start_ip, end_ip)

    if status.get("error"):
        return jsonify(status), 400

    with engine.lock:
        for packet in packets:
            engine.packet_buffer.append(packet)
        if len(engine.packet_buffer) > 10000:
            engine.packet_buffer = engine.packet_buffer[-10000:]

    return jsonify({
        "status": "success",
        "message": status.get("message"),
        "results": packets,
        "count": len(packets),
        "total_generated": status.get("total_generated", len(packets)),
        "filtered_count": status.get("filtered_count", len(packets))
    })


@app.route("/api/export_packets", methods=["GET"])
def export_packets():
    packets = engine.get_packets()
    if not packets:
        return jsonify({"message": "No packets in buffer to export."}), 404

    data_to_export = json.dumps(packets, indent=4)
    buffer = BytesIO()
    buffer.write(data_to_export.encode("utf-8"))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'sentinel-export-{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
        mimetype="application/json",
    )


@app.route("/api/export_packets_csv", methods=["GET"])
def export_packets_csv():
    packets = engine.get_packets()
    if not packets:
        return jsonify({"message": "No packets in buffer to export."}), 404

    fieldnames = [
        "id", "timestamp", "source", "destination", "protocol", "port", "length",
        "severity", "type", "is_successful", "rule_hit", "ml_score", "info",
        "prevention_action", "detection_log_source", "detection_log_reason", "detection_log_score_basis"
    ]

    packets_for_csv = []
    for p in packets:
        flat_p = p.copy()
        if 'detection_log' in p:
            flat_p['detection_log_source'] = p['detection_log'].get('source', 'N/A')
            flat_p['detection_log_reason'] = p['detection_log'].get('reason', 'N/A')
            flat_p['detection_log_score_basis'] = p['detection_log'].get('score_basis', 'N/A')
        packets_for_csv.append(flat_p)

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(packets_for_csv)

    buffer = BytesIO(output.getvalue().encode("utf-8"))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'sentinel-export-{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
        mimetype="text/csv",
    )


@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.json
    ip_address = data.get("ip_address")
    duration = data.get("duration", "1 hour")
    packet_data = data.get("packet_data", {})
    reason = packet_data.get('detection_log', {}).get('reason', 'Manual Block')
    action = data.get('action', 'BLOCK_IP')

    if not ip_address:
        return jsonify({"error": "IP address is required for blocking."}), 400

    engine.add_blocked_ip_log(ip_address, packet_data, reason, action)
    print(f"[PREVENTION] CRITICAL: IP {ip_address} BLOCKED for {duration} at the WAF perimeter. Reason: {reason}")

    return jsonify({
        "status": "blocked",
        "ip": ip_address,
        "message": f"IP {ip_address} successfully blocked at the WAF perimeter (Action: {action}). Rule active for {duration}."
    }), 200


@app.route("/api/blocked_ips", methods=["GET"])
def get_blocked_ips():
    return jsonify(engine.get_blocked_ips())


@app.route("/api/ingest_threat_feed", methods=["POST"])
def ingest_threat_feed():
    data = request.json
    ip_list = data.get("ip_addresses")

    if not ip_list or not isinstance(ip_list, list):
        return jsonify({"error": "Invalid input. Expected 'ip_addresses' as a list."}), 400

    count = engine.update_threat_intelligence(ip_list)

    return jsonify({
        "status": "success",
        "message": f"Successfully ingested {len(ip_list)} IPs. Added {count} new unique Indicators of Compromise.",
        "new_ioc_count": count,
    }), 200


@app.route("/api/soar_forensic_sweep", methods=["POST"])
def soar_forensic_sweep():
    data = request.json
    ip_address = data.get("ip_address")

    if not ip_address:
        return jsonify({"error": "IP address is required."}), 400

    print(f"[SOAR] AUTOMATED ACTION: Initiating historical forensic sweep for blocked IP: {ip_address}")

    return jsonify({
        "status": "triggered",
        "message": f"SOAR playbook executed: Historical IPDR query initiated for {ip_address}. Check audit logs in 30 seconds."
    }), 202


# =========================
# ✅ SOC API
# =========================

@app.route("/api/soc/alerts", methods=["GET"])
def soc_list_alerts():
    _seed_soc_if_empty()

    status = request.args.get("status", "all").lower()
    severity = request.args.get("severity", "all").lower()
    q = request.args.get("q", "").strip().lower()

    with SOC_LOCK:
        alerts = list(SOC_ALERTS.values())

    if status != "all":
        alerts = [a for a in alerts if a.get("status") == status]

    if severity != "all":
        alerts = [a for a in alerts if a.get("severity") == severity]

    if q:
        def match(a):
            blob = " ".join([
                str(a.get("title", "")),
                str(a.get("summary", "")),
                str(a.get("source", "")),
                str(a.get("asset", "")),
                str(a.get("ip", "")),
                str(a.get("assignee", "")),
                str(a.get("case_summary", "")),
                " ".join(a.get("tags", []))
            ]).lower()
            return q in blob

        alerts = [a for a in alerts if match(a)]

    alerts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/api/soc/ingest_from_packets", methods=["POST"])
def soc_ingest_from_packets():
    """
    Takes latest malicious packets and creates SOC alerts.
    Body JSON: { "max": 50, "only_successful": false }
    """
    data = request.get_json(force=True, silent=True) or {}
    max_n = int(data.get("max", 50))
    only_successful = bool(data.get("only_successful", False))

    packets = engine.get_packets()
    threats = [p for p in packets if (p.get("severity") not in ["Low", "LOW"])]

    if only_successful:
        threats = [p for p in threats if p.get("is_successful") is True]

    threats = threats[-max_n:]

    created = 0
    with SOC_LOCK:
        for p in threats:
            alert = _packet_to_soc_alert(p)
            SOC_ALERTS[alert["id"]] = alert
            created += 1

    return jsonify({"status": "ok", "created": created})


@app.route("/api/soc/alerts/<alert_id>", methods=["PATCH"])
def soc_update_alert(alert_id):
    data = request.get_json(force=True, silent=True) or {}

    with SOC_LOCK:
        if alert_id not in SOC_ALERTS:
            return jsonify({"error": "alert not found"}), 404

        a = SOC_ALERTS[alert_id]

        if "status" in data:
            st = str(data["status"]).lower()
            if st not in ["new", "triaged", "in_progress", "resolved", "false_positive"]:
                return jsonify({"error": "invalid status"}), 400
            a["status"] = st

        if "assignee" in data:
            a["assignee"] = (data["assignee"] or None)

        # ✅ NEW: priority
        if "priority" in data:
            pr = str(data["priority"]).lower()
            if pr not in ["p1", "p2", "p3", "p4"]:
                return jsonify({"error": "invalid priority"}), 400
            a["priority"] = pr

        # ✅ NEW: case summary
        if "case_summary" in data:
            a["case_summary"] = str(data["case_summary"])[:2000]

        if "tags" in data and isinstance(data["tags"], list):
            a["tags"] = data["tags"]

        SOC_ALERTS[alert_id] = a
        return jsonify(a)


@app.route("/api/soc/alerts/<alert_id>/notes", methods=["POST"])
def soc_add_note(alert_id):
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    author = (data.get("author") or "analyst").strip()

    if len(text) < 2:
        return jsonify({"error": "note too short"}), 400

    with SOC_LOCK:
        if alert_id not in SOC_ALERTS:
            return jsonify({"error": "alert not found"}), 404

        note = {"id": str(uuid.uuid4()), "ts": _now_iso(), "author": author, "text": text}
        SOC_ALERTS[alert_id]["notes"].insert(0, note)
        return jsonify({"note": note, "notes": SOC_ALERTS[alert_id]["notes"]}), 201


@app.route("/api/soc/alerts/<alert_id>", methods=["DELETE"])
def soc_delete_alert(alert_id):
    with SOC_LOCK:
        if alert_id not in SOC_ALERTS:
            return jsonify({"error": "alert not found"}), 404
        SOC_ALERTS.pop(alert_id, None)
    return jsonify({"ok": True})


if __name__ == "__main__":
    cert_path = "certs/cert.pem"
    key_path = "certs/key.pem"
    context = None

    if os.path.exists(cert_path) and os.path.exists(key_path):
        context = (cert_path, key_path)
        print("[+] SSL certificates found. Running with HTTPS.")
    else:
        print("[!] SSL certificates not found. Running without HTTPS (HTTP only).")
        print("[!] To enable HTTPS, run: python gen_certs.py")

    engine.start_generator()

    print("\n[+] Sentinel-X Platform Running...")
    if engine.threads:
        print(f"[+] Hybrid Detection System running: {engine.threads[0].is_alive()}")
    else:
        print("[!] Hybrid Detection System not running: Generator threads failed to start.")

    try:
        if context:
            app.run(host="0.0.0.0", port=5000, ssl_context=context, debug=False)
        else:
            app.run(host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        print(f"Error starting server: {e}")
        engine.stop_generator()
