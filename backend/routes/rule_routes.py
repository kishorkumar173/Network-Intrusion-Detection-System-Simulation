"""
Rules and Dashboard Analytics API Routes
"""

import json
from flask import Blueprint, request, jsonify, current_app
from backend.models.database import get_db_connection, get_dashboard_metrics

rule_bp = Blueprint("rules_dashboard", __name__, url_prefix="/api")


@rule_bp.route("/rules", methods=["GET"])
def get_rules():
    """Retrieve all signature rules, configurations, and active status."""
    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rules ORDER BY rule_id ASC;")
    rules = []
    for r in cursor.fetchall():
        d = dict(r)
        d["threshold"] = json.loads(d["threshold_json"]) if d.get("threshold_json") else {}
        d["enabled"] = bool(d["enabled"])
        rules.append(d)
    conn.close()
    return jsonify({"rules": rules}), 200


@rule_bp.route("/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id):
    """Update rule thresholds or toggle active/inactive state."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json()
    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM rules WHERE rule_id = ?;", (rule_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Rule not found", "rule_id": rule_id}), 404

    enabled = int(payload.get("enabled", existing["enabled"]))
    threshold = payload.get("threshold")
    threshold_json = json.dumps(threshold) if threshold is not None else existing["threshold_json"]
    severity = payload.get("severity", existing["severity"]).upper()

    cursor.execute(
        """
        UPDATE rules SET enabled = ?, threshold_json = ?, severity = ?
        WHERE rule_id = ?;
        """,
        (enabled, threshold_json, severity, rule_id),
    )
    conn.commit()
    conn.close()

    # Also update in-memory rule engine inside IDS_SERVICE
    ids_service = current_app.config["IDS_SERVICE"]
    ids_service.rule_engine.update_rule(
        rule_id,
        {"enabled": bool(enabled), "severity": severity, "threshold": json.loads(threshold_json)},
    )

    return jsonify({"status": "success", "rule_id": rule_id, "updated": True}), 200


@rule_bp.route("/dashboard/stats", methods=["GET"])
def get_stats():
    """Aggregated statistics for dashboard metrics cards."""
    metrics = get_dashboard_metrics(current_app.config["DATABASE_PATH"])
    return jsonify(metrics), 200


@rule_bp.route("/dashboard/traffic", methods=["GET"])
def get_dashboard_traffic():
    """Returns recent traffic timeline data points for interactive Chart.js graphs."""
    limit = min(200, int(request.args.get("limit", 60)))
    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT timestamp, packet_count, byte_count, duration, risk_score, classification, protocol
        FROM network_flows
        ORDER BY timestamp DESC LIMIT ?;
        """,
        (limit,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Reverse to return ascending chronological order for timeline graphs
    rows.reverse()
    return jsonify({"timeline": rows}), 200


@rule_bp.route("/dashboard/alerts", methods=["GET"])
def get_dashboard_alerts():
    """Returns top recent alerts for dashboard live triage table."""
    limit = min(50, int(request.args.get("limit", 15)))
    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT a.alert_id, a.flow_id, a.rule_id, a.alert_type, a.severity,
               a.description, a.risk_score, a.status, a.created_at,
               f.source_ip, f.destination_ip, f.protocol, f.source_port, f.destination_port
        FROM alerts a
        JOIN network_flows f ON a.flow_id = f.flow_id
        ORDER BY a.created_at DESC LIMIT ?;
        """,
        (limit,),
    )
    alerts = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"alerts": alerts}), 200
