"""
Flask Backend Application Factory
Initializes database, registers API routes, serves SOC dashboard templates,
and provides on-demand scenario generation for lab simulations.
"""

import os
import sys
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models.database import init_database, DEFAULT_DB_PATH
from backend.services.ids_service import IDSService
from backend.routes.flow_routes import flow_bp
from backend.routes.alert_routes import alert_bp
from backend.routes.rule_routes import rule_bp
from simulator.generate_dataset import generate_single_record


def create_app(test_config=None) -> Flask:
    """Application factory for Flask Network IDS."""
    template_dir = os.path.join(PROJECT_ROOT, "frontend", "templates")
    static_dir = os.path.join(PROJECT_ROOT, "frontend", "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
    )

    db_path = os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
    if test_config:
        app.config.update(test_config)
    else:
        app.config["DATABASE_PATH"] = db_path
        app.config["ENABLE_ML"] = os.environ.get("ENABLE_ML", "true").lower() == "true"
        app.config["MODEL_PATH"] = os.path.join(PROJECT_ROOT, "models", "random_forest_ids.joblib")
        app.config["BASELINE_PATH"] = os.path.join(PROJECT_ROOT, "models", "baseline_stats.json")

    # Initialize SQLite database schema
    init_database(app.config["DATABASE_PATH"])

    # Instantiate central IDS pipeline service
    ids_service = IDSService(
        db_path=app.config["DATABASE_PATH"],
        enable_ml=app.config.get("ENABLE_ML", True),
        model_path=app.config.get("MODEL_PATH"),
        baseline_path=app.config.get("BASELINE_PATH"),
    )
    app.config["IDS_SERVICE"] = ids_service

    # Register API blueprints
    app.register_blueprint(flow_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(rule_bp)

    # Web Dashboard Views
    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/investigation")
    def investigation():
        alert_id = request.args.get("alert_id", "")
        return render_template("investigation.html", alert_id=alert_id)

    @app.route("/incidents")
    def incidents():
        return render_template("incident_mgmt.html")

    # Simulation On-Demand Trigger Endpoint
    @app.route("/api/simulation/trigger", methods=["POST"])
    def trigger_sample():
        """Generates and processes a synthetic scenario on-demand."""
        payload = request.get_json() or {}
        scenario = payload.get("scenario", "NORMAL_WEB")
        flow_record = generate_single_record(scenario, datetime.now())

        flow_rec, alert_rec, success, err = ids_service.process_flow(flow_record)
        if not success:
            return jsonify({"error": err}), 400

        return jsonify({
            "status": "success",
            "scenario": scenario,
            "flow": flow_rec,
            "alert": alert_rec,
        }), 201

    # Global Error Handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("FLASK_PORT", 5000))
    print(f"[*] Starting Defensive Network IDS Application on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
