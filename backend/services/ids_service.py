"""
IDS Core Service
Orchestrates the end-to-end detection pipeline:
Flow Ingestion -> Feature Extraction -> Rules Engine -> Anomaly Detector ->
ML Predictor -> Risk Engine -> Alert Generation -> Correlation -> Database Storage.
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any, Tuple, Optional

from ids.feature_extractor import extract_network_features
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelator
from ml.predict import MLPredictor
from backend.models.database import save_flow_and_alert, DEFAULT_DB_PATH


class IDSService:
    """Central orchestration service for the Network IDS."""

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        enable_ml: bool = True,
        model_path: str = "models/random_forest_ids.joblib",
        baseline_path: str = "models/baseline_stats.json",
        correlation_window: int = 60,
    ):
        self.db_path = db_path
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector(baseline_path=baseline_path)
        self.ml_predictor = MLPredictor(model_path=model_path) if enable_ml else None
        self.risk_engine = RiskEngine(enable_ml=enable_ml)
        self.alert_engine = AlertEngine()
        self.correlator = AlertCorrelator(window_seconds=correlation_window)

    def process_flow(self, raw_flow: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], bool, str]:
        """
        Executes complete defensive inspection pipeline on a raw network flow.

        :param raw_flow: Flow dictionary
        :return: (flow_record, alert_record, success, error_message)
        """
        # Step 1: Feature Extraction & Validation
        features, is_valid, err_msg = extract_network_features(raw_flow)
        if not is_valid:
            return {}, None, False, err_msg

        flow_id = raw_flow.get("flow_id") or f"flow-{uuid.uuid4().hex[:10]}"
        timestamp = raw_flow.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Step 2: Signature / Rule-based Detection
        triggered_rules = self.rule_engine.analyze_flow(features)

        # Step 3: Anomaly-based Statistical Detection
        anomaly_score, z_scores = self.anomaly_detector.calculate_anomaly_score(features)

        # Step 4: Machine Learning Inference (optional)
        if self.ml_predictor and self.ml_predictor.is_loaded:
            ml_pred, ml_prob = self.ml_predictor.predict_flow(features)
        else:
            ml_pred, ml_prob = 0, 0.0

        # Step 5: Hybrid Risk Scoring
        risk_score, classification, severity = self.risk_engine.calculate_risk_score(
            triggered_rules=triggered_rules,
            anomaly_score=anomaly_score,
            ml_probability=ml_prob,
        )

        # Construct enriched flow record
        flow_record = {
            "flow_id": flow_id,
            "timestamp": timestamp,
            "source_ip": features["source_ip"],
            "destination_ip": features["destination_ip"],
            "source_port": features["source_port"],
            "destination_port": features["destination_port"],
            "protocol": features["protocol"],
            "packet_count": features["packet_count"],
            "byte_count": features["byte_count"],
            "duration": features["duration"],
            "risk_score": risk_score,
            "classification": classification,
            "scenario_type": raw_flow.get("scenario_type", "UNKNOWN"),
            "features": features,
            "anomaly_score": anomaly_score,
            "ml_probability": ml_prob,
            "triggered_rules": triggered_rules,
        }

        # Step 6: Alert Generation
        alert_record = self.alert_engine.generate_alert(
            flow_record=flow_record,
            features=features,
            triggered_rules=triggered_rules,
            risk_score=risk_score,
            severity=severity,
        )

        # Step 7: Alert Correlation
        correlation_info = None
        if alert_record:
            correlation_info = self.correlator.correlate_alert(alert_record)
            alert_record["correlation"] = correlation_info

        # Step 8: Database Persistence
        ml_payload = {
            "flow_id": flow_id,
            "model_name": "RandomForest",
            "prediction": ml_pred,
            "score": ml_prob,
        } if self.ml_predictor and self.ml_predictor.is_loaded else None

        save_flow_and_alert(
            flow_dict=flow_record,
            alert_dict=alert_record,
            ml_result=ml_payload,
            db_path=self.db_path,
        )

        return flow_record, alert_record, True, ""
