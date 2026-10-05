"""
Seed Database with Initial Flow Records
Loads historical synthetic data from data/network_traffic.csv and processes it
through the IDS service with high-performance SQLite transaction caching.
"""

import os
import sys
import json
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models.database import init_database, get_db_connection, DEFAULT_DB_PATH
from backend.services.ids_service import IDSService


def seed_db(data_path: str = "data/network_traffic.csv", db_path: str = DEFAULT_DB_PATH, count: int = 200):
    """Ingests flow records in bulk with a single database commit."""
    print(f"[*] Initializing database at {db_path}...")
    init_database(db_path)

    if not os.path.exists(data_path):
        print(f"[!] Dataset not found at {data_path}. Run simulator/generate_dataset.py first.")
        return

    print(f"[*] Seeding {count} records into database...")
    df = pd.read_csv(data_path)
    sample_df = df.head(count)

    # Instantiate pipeline with model
    model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "random_forest_ids.joblib")
    baseline_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "baseline_stats.json")
    service = IDSService(db_path=db_path, enable_ml=True, model_path=model_path, baseline_path=baseline_path)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA synchronous = OFF;")
    cursor.execute("PRAGMA journal_mode = MEMORY;")

    alerts_count = 0
    for idx, row in sample_df.iterrows():
        raw_dict = row.to_dict()
        # Extract features and calculate scores
        features, ok, _ = service.ids_service_features = service.rule_engine, None, None
        feats, is_valid, _ = service.rule_engine, True, ""
        from ids.feature_extractor import extract_network_features
        features, is_valid, _ = extract_network_features(raw_dict)
        if not is_valid:
            continue

        triggered = service.rule_engine.analyze_flow(features)
        anomaly_score, _ = service.anomaly_detector.calculate_anomaly_score(features)
        ml_pred, ml_prob = service.ml_predictor.predict_flow(features) if service.ml_predictor and service.ml_predictor.is_loaded else (0, 0.0)
        risk_score, classification, severity = service.risk_engine.calculate_risk_score(triggered, anomaly_score, ml_prob)

        flow_id = raw_dict.get("flow_id", f"fl-{idx}")
        ts = raw_dict.get("timestamp")

        cursor.execute(
            """
            INSERT OR REPLACE INTO network_flows (
                flow_id, timestamp, source_ip, destination_ip, source_port, destination_port,
                protocol, packet_count, byte_count, duration, risk_score, classification, scenario_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                flow_id, ts, features["source_ip"], features["destination_ip"],
                features["source_port"], features["destination_port"], features["protocol"],
                features["packet_count"], features["byte_count"], features["duration"],
                risk_score, classification, raw_dict.get("scenario_type", "UNKNOWN"),
            ),
        )

        alert = service.alert_engine.generate_alert(raw_dict, features, triggered, risk_score, severity)
        if alert:
            alerts_count += 1
            rec_steps = json.dumps(alert.get("recommended_steps", []))
            cursor.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, flow_id, rule_id, alert_type, severity, description,
                    risk_score, status, recommended_steps, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    alert["alert_id"], alert["flow_id"], alert["rule_id"],
                    alert["alert_type"], alert["severity"], alert["description"],
                    alert["risk_score"], alert["status"], rec_steps, alert["created_at"],
                ),
            )

    conn.commit()
    conn.close()
    print(f"[+] Bulk seeding complete! Ingested {len(sample_df)} flows, generated {alerts_count} initial alerts.")


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
    csv_file = os.path.join(project_root, "data", "network_traffic.csv")
    db_file = os.path.join(project_root, "data", "network_ids.db")
    seed_db(csv_file, db_file, count=250)
