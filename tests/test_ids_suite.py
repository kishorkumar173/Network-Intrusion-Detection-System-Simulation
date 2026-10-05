"""
Automated Pytest Test Suite for Network Intrusion Detection System (IDS)
Includes 30 comprehensive, industry-grade test cases matching Section 26 specifications.
"""

import os
import sys
import tempfile
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ids.feature_extractor import extract_network_features, validate_ip_address, validate_port
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelator, correlate_alerts
from ml.predict import MLPredictor
from backend.models.database import (
    init_database,
    save_flow_and_alert,
    get_dashboard_metrics,
    get_db_connection,
)
from backend.app import create_app


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database file for isolated testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_database(path)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except PermissionError:
        pass


@pytest.fixture
def test_client(temp_db):
    """Create Flask test client bound to temp database."""
    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": temp_db,
        "ENABLE_ML": False,  # Test without ML dependency initially for speed
    })
    with app.test_client() as client:
        yield client


# ==========================================
# 1. Normal TCP Flow
# ==========================================
def test_01_normal_tcp_flow():
    raw = {
        "source_ip": "192.0.2.10", "destination_ip": "198.51.100.15",
        "source_port": 50000, "destination_port": 80, "protocol": "TCP",
        "packet_count": 20, "byte_count": 10000, "duration_seconds": 1.5,
        "connection_count": 2, "failed_connection_count": 0, "syn_count": 2, "rst_count": 0
    }
    feats, ok, err = extract_network_features(raw)
    assert ok is True
    engine = RuleEngine()
    triggered = engine.analyze_flow(feats)
    assert len(triggered) == 0


# ==========================================
# 2. Normal UDP Flow
# ==========================================
def test_02_normal_udp_flow():
    raw = {
        "source_ip": "192.0.2.11", "destination_ip": "198.51.100.22",
        "source_port": 50001, "destination_port": 123, "protocol": "UDP",
        "packet_count": 4, "byte_count": 400, "duration_seconds": 0.1,
        "connection_count": 1, "failed_connection_count": 0, "syn_count": 0, "rst_count": 0
    }
    feats, ok, err = extract_network_features(raw)
    assert ok is True
    assert feats["protocol"] == "UDP"


# ==========================================
# 3. Normal DNS Flow
# ==========================================
def test_03_normal_dns_flow():
    raw = {
        "source_ip": "192.0.2.12", "destination_ip": "198.51.100.53",
        "source_port": 51234, "destination_port": 53, "protocol": "UDP",
        "packet_count": 2, "byte_count": 180, "duration_seconds": 0.05,
        "connection_count": 1, "failed_connection_count": 0, "syn_count": 0, "rst_count": 0
    }
    feats, ok, _ = extract_network_features(raw)
    assert ok is True
    assert feats["destination_port"] == 53


# ==========================================
# 4. Normal HTTPS Flow
# ==========================================
def test_04_normal_https_flow():
    raw = {
        "source_ip": "192.0.2.14", "destination_ip": "198.51.100.44",
        "source_port": 52000, "destination_port": 443, "protocol": "TCP",
        "packet_count": 45, "byte_count": 32000, "duration_seconds": 2.2,
        "connection_count": 2, "failed_connection_count": 0, "syn_count": 2, "rst_count": 0
    }
    feats, ok, _ = extract_network_features(raw)
    assert ok is True
    assert feats["destination_port"] == 443


# ==========================================
# 5. High Connection Rate Trigger
# ==========================================
def test_05_high_connection_rate_rule():
    raw = {
        "source_ip": "192.0.2.20", "destination_ip": "198.51.100.10",
        "source_port": 53000, "destination_port": 80, "protocol": "TCP",
        "packet_count": 500, "byte_count": 50000, "duration_seconds": 1.0,
        "connection_count": 100, "failed_connection_count": 5, "syn_count": 80, "rst_count": 2
    }
    feats, ok, _ = extract_network_features(raw)
    engine = RuleEngine()
    triggered = engine.analyze_flow(feats)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "IDS-001" in rule_ids


# ==========================================
# 6. Repeated Failed Connections (Brute Force)
# ==========================================
def test_06_repeated_failed_connections_rule():
    raw = {
        "source_ip": "192.0.2.21", "destination_ip": "198.51.100.22",
        "source_port": 54000, "destination_port": 22, "protocol": "TCP",
        "packet_count": 120, "byte_count": 12000, "duration_seconds": 5.0,
        "connection_count": 50, "failed_connection_count": 45, "syn_count": 50, "rst_count": 40
    }
    feats, ok, _ = extract_network_features(raw)
    engine = RuleEngine()
    triggered = engine.analyze_flow(feats)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "IDS-002" in rule_ids


# ==========================================
# 7. Multi-Port Probing Pattern
# ==========================================
def test_07_multi_port_probing_pattern_rule():
    raw = {
        "source_ip": "192.0.2.22", "destination_ip": "198.51.100.80",
        "source_port": 55000, "destination_port": 135, "protocol": "TCP",
        "packet_count": 60, "byte_count": 3600, "duration_seconds": 1.2,
        "connection_count": 40, "failed_connection_count": 35, "syn_count": 40, "rst_count": 30,
        "unique_destination_ports": 12
    }
    feats, ok, _ = extract_network_features(raw)
    engine = RuleEngine()
    triggered = engine.analyze_flow(feats)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "IDS-003" in rule_ids


# ==========================================
# 8. SYN-Heavy Pattern
# ==========================================
def test_08_syn_heavy_pattern_rule():
    raw = {
        "source_ip": "192.0.2.23", "destination_ip": "198.51.100.44",
        "source_port": 56000, "destination_port": 443, "protocol": "TCP",
        "packet_count": 1000, "byte_count": 60000, "duration_seconds": 2.0,
        "connection_count": 200, "failed_connection_count": 150, "syn_count": 920, "rst_count": 20
    }
    feats, ok, _ = extract_network_features(raw)
    engine = RuleEngine()
    triggered = engine.analyze_flow(feats)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "IDS-004" in rule_ids


# ==========================================
# 9. High Traffic Volume Surge
# ==========================================
def test_09_high_traffic_volume_rule():
    raw = {
        "source_ip": "192.0.2.24", "destination_ip": "198.51.100.50",
        "source_port": 57000, "destination_port": 80, "protocol": "TCP",
        "packet_count": 6000, "byte_count": 8_500_000, "duration_seconds": 10.0,
        "connection_count": 10, "failed_connection_count": 0, "syn_count": 10, "rst_count": 0
    }
    feats, ok, _ = extract_network_features(raw)
    engine = RuleEngine()
    triggered = engine.analyze_flow(feats)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "IDS-006" in rule_ids


# ==========================================
# 10. Invalid Source IP Validation
# ==========================================
def test_10_invalid_source_ip():
    raw = {
        "source_ip": "999.999.999.999", "destination_ip": "198.51.100.1",
        "source_port": 50000, "destination_port": 80, "protocol": "TCP"
    }
    _, ok, err = extract_network_features(raw)
    assert ok is False
    assert "Invalid source IP" in err


# ==========================================
# 11. Invalid Destination IP Validation
# ==========================================
def test_11_invalid_destination_ip():
    raw = {
        "source_ip": "192.0.2.1", "destination_ip": "not_an_ip",
        "source_port": 50000, "destination_port": 80, "protocol": "TCP"
    }
    _, ok, err = extract_network_features(raw)
    assert ok is False
    assert "Invalid destination IP" in err


# ==========================================
# 12. Invalid Source Port Validation
# ==========================================
def test_12_invalid_source_port():
    raw = {
        "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
        "source_port": 70000, "destination_port": 80, "protocol": "TCP"
    }
    _, ok, err = extract_network_features(raw)
    assert ok is False
    assert "Invalid source port" in err


# ==========================================
# 13. Invalid Destination Port Validation
# ==========================================
def test_13_invalid_destination_port():
    raw = {
        "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
        "source_port": 50000, "destination_port": -5, "protocol": "TCP"
    }
    _, ok, err = extract_network_features(raw)
    assert ok is False
    assert "Invalid destination port" in err


# ==========================================
# 14. Unsupported Protocol Validation
# ==========================================
def test_14_unsupported_protocol():
    raw = {
        "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
        "source_port": 50000, "destination_port": 80, "protocol": "SCTP_UNKNOWN"
    }
    _, ok, err = extract_network_features(raw)
    assert ok is False
    assert "Unsupported protocol" in err


# ==========================================
# 15. Missing Packet Count Handling
# ==========================================
def test_15_missing_packet_count_defaults():
    raw = {
        "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
        "source_port": 50000, "destination_port": 80, "protocol": "TCP",
        "byte_count": 1000
    }
    feats, ok, _ = extract_network_features(raw)
    assert ok is True
    assert feats["packet_count"] == 0
    assert feats["average_packet_size"] == 0.0


# ==========================================
# 16. Zero Duration Division Safety
# ==========================================
def test_16_zero_duration_division_safety():
    raw = {
        "source_ip": "192.0.2.1", "destination_ip": "198.51.100.1",
        "source_port": 50000, "destination_port": 80, "protocol": "TCP",
        "packet_count": 100, "byte_count": 10000, "duration_seconds": 0.0
    }
    feats, ok, _ = extract_network_features(raw)
    assert ok is True
    assert feats["duration"] > 0
    assert feats["packets_per_second"] > 0


# ==========================================
# 17. Feature Extraction Precision
# ==========================================
def test_17_feature_extraction_derived_metrics():
    raw = {
        "source_ip": "192.0.2.10", "destination_ip": "198.51.100.20",
        "source_port": 50000, "destination_port": 443, "protocol": "TCP",
        "packet_count": 50, "byte_count": 25000, "duration_seconds": 2.5,
        "connection_count": 5, "failed_connection_count": 2, "syn_count": 5, "rst_count": 1
    }
    feats, ok, _ = extract_network_features(raw)
    assert ok is True
    assert feats["average_packet_size"] == 500.0
    assert feats["failure_ratio"] == 0.4
    assert feats["syn_ratio"] == 0.1
    assert feats["connection_rate"] == 2.0


# ==========================================
# 18. Rule Engine Enable/Disable Toggle
# ==========================================
def test_18_rule_engine_toggle():
    engine = RuleEngine()
    assert engine.update_rule("IDS-001", {"enabled": False}) is True
    r1 = engine.rules["IDS-001"]
    assert r1["enabled"] is False

    feats = {"connection_rate": 100.0, "connection_count": 50, "destination_port": 80}
    triggered = engine.analyze_flow(feats)
    assert "IDS-001" not in [r["rule_id"] for r in triggered]


# ==========================================
# 19. Anomaly Score Calculation
# ==========================================
def test_19_anomaly_score_bounds():
    detector = AnomalyDetector()
    # High deviation input
    abnormal_feats = {
        "failure_ratio": 0.9, "syn_ratio": 0.95, "connection_rate": 80.0,
        "packets_per_second": 500.0, "bytes_per_second": 800000.0
    }
    score, z_scores = detector.calculate_anomaly_score(abnormal_feats)
    assert 0.0 <= score <= 100.0
    assert score > 50.0  # Must flag abnormal values significantly


# ==========================================
# 20. Risk Score Weighting & Classification
# ==========================================
def test_20_risk_score_weighted_logic():
    risk_engine = RiskEngine(enable_ml=False)
    triggered = [{"rule_id": "IDS-001", "rule_risk_score": 80, "severity": "HIGH"}]
    score, classification, severity = risk_engine.calculate_risk_score(triggered, anomaly_score=60.0, ml_probability=0.0)
    assert score >= 65
    assert classification in ["HIGH RISK", "CRITICAL INVESTIGATION"]
    assert severity in ["HIGH", "CRITICAL"]


# ==========================================
# 21. Alert Generation Engine
# ==========================================
def test_21_alert_creation_structure():
    alert_engine = AlertEngine(alert_threshold_score=40)
    flow = {"flow_id": "flow-test-1", "timestamp": "2026-10-05 12:00:00"}
    feats = {"source_ip": "192.0.2.1", "destination_ip": "198.51.100.1", "source_port": 50000, "destination_port": 443, "protocol": "TCP"}
    triggered = [{"rule_id": "IDS-001", "name": "High Connection Rate", "reason": "Rate exceeded"}]

    alert = alert_engine.generate_alert(flow, feats, triggered, risk_score=75, severity="HIGH")
    assert alert is not None
    assert alert["alert_id"].startswith("ALT-")
    assert alert["severity"] == "HIGH"
    assert len(alert["recommended_steps"]) > 0


# ==========================================
# 22. Alert Correlation & Grouping
# ==========================================
def test_22_alert_correlation_grouping():
    correlator = AlertCorrelator(window_seconds=60)
    a1 = {
        "alert_id": "ALT-001", "timestamp": "2026-10-05 12:00:01",
        "source_ip": "192.0.2.50", "alert_type": "High Connection Rate", "severity": "HIGH", "risk_score": 75
    }
    a2 = {
        "alert_id": "ALT-002", "timestamp": "2026-10-05 12:00:10",
        "source_ip": "192.0.2.50", "alert_type": "High Connection Rate", "severity": "HIGH", "risk_score": 80
    }
    c1 = correlator.correlate_alert(a1)
    c2 = correlator.correlate_alert(a2)

    assert c1["incident_id"] == c2["incident_id"]
    assert c2["correlated_count"] == 2
    assert c2["is_aggregated"] is True


# ==========================================
# 23. Alert Status Transition
# ==========================================
def test_23_alert_status_transition(test_client, temp_db):
    # Seed alert into database
    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO network_flows (flow_id, timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, byte_count, duration, risk_score, classification)
        VALUES ('fl-1', '2026-10-05 10:00:00', '192.0.2.1', '198.51.100.1', 50000, 80, 'TCP', 10, 1000, 1.0, 70, 'HIGH RISK');
    """)
    cursor.execute("""
        INSERT INTO alerts (alert_id, flow_id, rule_id, alert_type, severity, description, risk_score, status, created_at)
        VALUES ('ALT-STATUS-1', 'fl-1', 'IDS-001', 'High Connection Rate', 'HIGH', 'Rate surge', 70, 'NEW', '2026-10-05 10:00:00');
    """)
    conn.commit()
    conn.close()

    resp = test_client.put("/api/alerts/ALT-STATUS-1/status", json={"status": "INVESTIGATING", "author": "Alice"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["new_status"] == "INVESTIGATING"


# ==========================================
# 24. Analyst Note Documentation
# ==========================================
def test_24_analyst_note_documentation(test_client, temp_db):
    # Seed alert
    conn = get_db_connection(temp_db)
    conn.execute("""
        INSERT OR IGNORE INTO network_flows (flow_id, timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, byte_count, duration, risk_score, classification)
        VALUES ('fl-note', '2026-10-05 10:00:00', '192.0.2.1', '198.51.100.1', 50000, 80, 'TCP', 10, 1000, 1.0, 70, 'HIGH RISK');
    """)
    conn.execute("""
        INSERT OR IGNORE INTO alerts (alert_id, flow_id, rule_id, alert_type, severity, description, risk_score, status, created_at)
        VALUES ('ALT-NOTE-1', 'fl-note', 'IDS-001', 'Test Alert', 'HIGH', 'Description', 70, 'NEW', '2026-10-05 10:00:00');
    """)
    conn.commit()
    conn.close()

    resp = test_client.post("/api/alerts/ALT-NOTE-1/notes", json={
        "author": "Analyst Bob",
        "note": "Verified with network engineering: authorized load test."
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "success"
    assert "Bob" in data["author"]


# ==========================================
# 25. Database Storage & Persistence
# ==========================================
def test_25_database_storage_persistence(temp_db):
    flow = {
        "flow_id": "flow-persist-1", "timestamp": "2026-10-05 11:00:00",
        "source_ip": "192.0.2.77", "destination_ip": "198.51.100.88",
        "source_port": 50000, "destination_port": 443, "protocol": "TCP",
        "packet_count": 30, "byte_count": 15000, "duration": 1.2,
        "risk_score": 15, "classification": "NORMAL"
    }
    saved = save_flow_and_alert(flow, alert_dict=None, db_path=temp_db)
    assert saved is True

    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_flows WHERE flow_id = 'flow-persist-1';")
    row = cursor.fetchone()
    assert row is not None
    assert row["source_ip"] == "192.0.2.77"
    conn.close()


# ==========================================
# 26. Dashboard Statistics Retrieval
# ==========================================
def test_26_dashboard_statistics(temp_db):
    metrics = get_dashboard_metrics(temp_db)
    assert "total_flows" in metrics
    assert "normal_flows" in metrics
    assert "suspicious_flows" in metrics
    assert "open_alerts" in metrics
    assert isinstance(metrics["average_risk_score"], float)


# ==========================================
# 27. ML Prediction Graceful Fallback
# ==========================================
def test_27_ml_prediction_fallback():
    predictor = MLPredictor(model_path="non_existent_model.joblib")
    assert predictor.is_loaded is False
    pred, prob = predictor.predict_flow({"packet_count": 10})
    assert pred == 0
    assert prob == 0.0


# ==========================================
# 28. API Ingestion Validation Error Handling
# ==========================================
def test_28_api_ingestion_validation(test_client):
    # Malformed payload missing required destination port
    invalid_payload = {
        "source_ip": "192.0.2.10", "destination_ip": "198.51.100.20",
        "source_port": 50000, "protocol": "TCP"
    }
    resp = test_client.post("/api/flows", json=invalid_payload)
    assert resp.status_code == 400
    data = resp.get_json()
    assert "Validation Error" in data["error"]


# ==========================================
# 29. Empty Dataset Anomaly Fitting
# ==========================================
def test_29_empty_dataset_detector():
    import pandas as pd
    detector = AnomalyDetector()
    empty_df = pd.DataFrame(columns=["label", "packet_count", "byte_count", "duration_seconds", "connection_count", "failed_connection_count", "syn_count"])
    # Should not crash on empty df
    baseline = detector.fit_baseline_from_df(empty_df)
    assert isinstance(baseline, dict)


# ==========================================
# 30. Duplicate Event Idempotent Handling
# ==========================================
def test_30_duplicate_flow_storage(temp_db):
    flow = {
        "flow_id": "dup-flow-1", "timestamp": "2026-10-05 12:00:00",
        "source_ip": "192.0.2.99", "destination_ip": "198.51.100.99",
        "source_port": 50000, "destination_port": 80, "protocol": "TCP",
        "packet_count": 25, "byte_count": 5000, "duration": 1.0,
        "risk_score": 10, "classification": "NORMAL"
    }
    assert save_flow_and_alert(flow, None, db_path=temp_db) is True
    # Inserting identical flow_id should update/replace idempotently without crash
    assert save_flow_and_alert(flow, None, db_path=temp_db) is True
