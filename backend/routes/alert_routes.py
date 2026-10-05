"""
Alert and Incident Management API Routes
"""

import json
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from backend.models.database import get_db_connection

alert_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")

VALID_STATUSES = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


@alert_bp.route("", methods=["GET"])
def get_alerts():
    """Retrieve security alerts with optional severity and status filtering."""
    limit = min(500, int(request.args.get("limit", 50)))
    offset = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    status = request.args.get("status")

    query = """
        SELECT a.*, f.source_ip, f.destination_ip, f.protocol, f.source_port, f.destination_port
        FROM alerts a
        JOIN network_flows f ON a.flow_id = f.flow_id
        WHERE 1=1
    """
    params = []

    if severity:
        query += " AND a.severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND a.status = ?"
        params.append(status.upper())

    query += " ORDER BY a.created_at DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])

    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute(query, params)
    alerts = []
    for r in cursor.fetchall():
        d = dict(r)
        if "recommended_steps" in d and d["recommended_steps"]:
            try:
                d["recommended_steps"] = json.loads(d["recommended_steps"])
            except Exception:
                pass
        alerts.append(d)
    conn.close()

    return jsonify({"count": len(alerts), "alerts": alerts}), 200


@alert_bp.route("/<alert_id>", methods=["GET"])
def get_alert_by_id(alert_id):
    """Retrieve in-depth alert context, associated flow telemetry, and analyst notes."""
    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?;", (alert_id,))
    alert_row = cursor.fetchone()
    if not alert_row:
        conn.close()
        return jsonify({"error": "Alert not found", "alert_id": alert_id}), 404

    alert_data = dict(alert_row)
    if alert_data.get("recommended_steps"):
        try:
            alert_data["recommended_steps"] = json.loads(alert_data["recommended_steps"])
        except Exception:
            pass

    # Associated flow record
    cursor.execute("SELECT * FROM network_flows WHERE flow_id = ?;", (alert_data["flow_id"],))
    flow_row = cursor.fetchone()
    alert_data["flow"] = dict(flow_row) if flow_row else None

    # Analyst notes timeline
    cursor.execute("SELECT * FROM incident_notes WHERE alert_id = ? ORDER BY created_at ASC;", (alert_id,))
    alert_data["notes"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return jsonify(alert_data), 200


@alert_bp.route("/<alert_id>/status", methods=["PUT"])
def update_alert_status(alert_id):
    """Updates the lifecycle status of an alert (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415

    payload = request.get_json()
    new_status = payload.get("status", "").upper()
    resolution_note = payload.get("note", "").strip()

    if new_status not in VALID_STATUSES:
        return jsonify({
            "error": "Invalid status",
            "allowed": list(VALID_STATUSES),
        }), 400

    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?;", (alert_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Alert not found", "alert_id": alert_id}), 404

    cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?;", (new_status, alert_id))

    if resolution_note:
        cursor.execute(
            """
            INSERT INTO incident_notes (alert_id, author, note, created_at)
            VALUES (?, ?, ?, ?);
            """,
            (
                alert_id,
                payload.get("author", "SOC Analyst"),
                f"Status updated to {new_status}: {resolution_note}",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "alert_id": alert_id, "new_status": new_status}), 200


@alert_bp.route("/<alert_id>/notes", methods=["POST"])
def add_analyst_note(alert_id):
    """Add a documented investigative note to the alert incident timeline."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415

    payload = request.get_json()
    note_text = payload.get("note", "").strip()
    author = payload.get("author", "SOC Analyst").strip()

    if not note_text:
        return jsonify({"error": "Field 'note' cannot be empty"}), 400

    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?;", (alert_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Alert not found", "alert_id": alert_id}), 404

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        """
        INSERT INTO incident_notes (alert_id, author, note, created_at)
        VALUES (?, ?, ?, ?);
        """,
        (alert_id, author, note_text, created_at),
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "alert_id": alert_id,
        "author": author,
        "note": note_text,
        "created_at": created_at,
    }), 201
