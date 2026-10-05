"""
Flow Ingestion and Query API Routes
"""

from flask import Blueprint, request, jsonify, current_app
from backend.utils.validators import validate_flow_payload
from backend.models.database import get_db_connection

flow_bp = Blueprint("flows", __name__, url_prefix="/api/flows")


@flow_bp.route("", methods=["POST"])
def ingest_flow():
    """
    Ingests and analyzes a raw network flow event.
    Returns calculated risk score, classification, and triggered alert if any.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json()
    is_valid, err_msg = validate_flow_payload(payload)
    if not is_valid:
        return jsonify({"error": "Validation Error", "details": err_msg}), 400

    ids_service = current_app.config["IDS_SERVICE"]
    flow_rec, alert_rec, success, err = ids_service.process_flow(payload)

    if not success:
        return jsonify({"error": "Processing Error", "details": err}), 422

    response_data = {
        "status": "success",
        "flow_id": flow_rec["flow_id"],
        "classification": flow_rec["classification"],
        "risk_score": flow_rec["risk_score"],
        "anomaly_score": flow_rec["anomaly_score"],
        "ml_probability": flow_rec["ml_probability"],
        "rules_triggered": len(flow_rec["triggered_rules"]),
        "alert": alert_rec,
    }
    return jsonify(response_data), 201


@flow_bp.route("", methods=["GET"])
def get_flows():
    """Retrieve list of historical network flows with optional filters."""
    limit = min(500, int(request.args.get("limit", 50)))
    offset = int(request.args.get("offset", 0))
    classification = request.args.get("classification")
    protocol = request.args.get("protocol")

    query = "SELECT * FROM network_flows WHERE 1=1"
    params = []

    if classification:
        query += " AND classification = ?"
        params.append(classification.upper())
    if protocol:
        query += " AND protocol = ?"
        params.append(protocol.upper())

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])

    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"count": len(rows), "flows": rows}), 200


@flow_bp.route("/<flow_id>", methods=["GET"])
def get_flow_by_id(flow_id):
    """Retrieve complete metadata for a specific flow ID."""
    conn = get_db_connection(current_app.config["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_flows WHERE flow_id = ?;", (flow_id,))
    flow = cursor.fetchone()

    if not flow:
        conn.close()
        return jsonify({"error": "Flow not found", "flow_id": flow_id}), 404

    # Fetch any associated alert
    cursor.execute("SELECT * FROM alerts WHERE flow_id = ?;", (flow_id,))
    alert = cursor.fetchone()

    # Fetch ML result if present
    cursor.execute("SELECT * FROM model_results WHERE flow_id = ?;", (flow_id,))
    ml = cursor.fetchone()
    conn.close()

    result = dict(flow)
    result["associated_alert"] = dict(alert) if alert else None
    result["ml_result"] = dict(ml) if ml else None
    return jsonify(result), 200
