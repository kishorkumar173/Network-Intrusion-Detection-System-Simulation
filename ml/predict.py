"""
Machine Learning Inference Engine
Loads trained model and generates real-time predictions and malicious probabilities.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple


class MLPredictor:
    """Wrapper for real-time model inference."""

    def __init__(self, model_path: str = "models/random_forest_ids.joblib"):
        self.model_path = model_path
        self.model = None
        self.feature_names = []
        self.is_loaded = False
        self.load_model(model_path)

    def load_model(self, model_path: str):
        """Loads serialized model artifact."""
        if os.path.exists(model_path):
            try:
                payload = joblib.load(model_path)
                self.model = payload["model"]
                self.feature_names = payload["feature_names"]
                self.is_loaded = True
            except Exception as e:
                print(f"[!] Warning: Failed to load ML model from {model_path}: {e}")
                self.is_loaded = False
        else:
            self.is_loaded = False

    def predict_flow(self, features: Dict[str, Any]) -> Tuple[int, float]:
        """
        Predict whether a flow is suspicious.
        :param features: Dict of extracted network features
        :return: (prediction (0=NORMAL, 1=SUSPICIOUS), malicious_probability (0.0 to 1.0))
        """
        if not self.is_loaded or self.model is None:
            # Fallback when ML is disabled or model artifact not found
            return 0, 0.0

        # Construct vector matching FEATURE_COLUMNS
        row = {
            "packet_count": features.get("packet_count", 0),
            "byte_count": features.get("byte_count", 0),
            "duration_seconds": features.get("duration", 0.001),
            "bytes_per_second": features.get("bytes_per_second", 0.0),
            "packets_per_second": features.get("packets_per_second", 0.0),
            "connection_count": features.get("connection_count", 1),
            "failed_connection_count": features.get("failed_connection_count", 0),
            "syn_count": features.get("syn_count", 0),
            "rst_count": features.get("rst_count", 0),
            "average_packet_size": features.get("average_packet_size", 0.0),
        }

        df_input = pd.DataFrame([row])[self.feature_names]

        try:
            pred = int(self.model.predict(df_input)[0])
            if hasattr(self.model, "predict_proba"):
                prob = float(self.model.predict_proba(df_input)[0][1])
            else:
                prob = 1.0 if pred == 1 else 0.0
            return pred, round(prob, 4)
        except Exception as e:
            print(f"[!] Prediction error: {e}")
            return 0, 0.0
