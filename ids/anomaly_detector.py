"""
Statistical Anomaly Detection Engine
Computes normal operational baselines using mean, standard deviation, and IQR.
Evaluates observed flows against baseline distributions via modified Z-score
to output an anomaly score between 0 and 100.
"""

import json
import math
import os
from typing import Dict, Any, Tuple
import pandas as pd


# Default enterprise baseline parameters (used as fallback or pre-calibrated baseline)
DEFAULT_BASELINE = {
    "packets_per_second": {"mean": 25.0, "std": 18.0, "q25": 10.0, "q75": 35.0},
    "bytes_per_second": {"mean": 12000.0, "std": 9500.0, "q25": 4000.0, "q75": 18000.0},
    "connection_rate": {"mean": 2.5, "std": 2.0, "q25": 0.8, "q75": 3.5},
    "failure_ratio": {"mean": 0.01, "std": 0.04, "q25": 0.0, "q75": 0.0},
    "syn_ratio": {"mean": 0.08, "std": 0.10, "q25": 0.02, "q75": 0.12},
}


class AnomalyDetector:
    """Statistical anomaly detector based on multi-metric deviation."""

    def __init__(self, baseline_path: str = None):
        self.baseline_path = baseline_path
        self.baseline = DEFAULT_BASELINE.copy()
        if baseline_path and os.path.exists(baseline_path):
            self.load_baseline(baseline_path)

    def fit_baseline_from_df(self, df: pd.DataFrame, save_path: str = None) -> Dict[str, Any]:
        """
        Calibrate normal baselines using only 'NORMAL' labeled historical traffic.
        """
        normal_df = df[df["label"] == "NORMAL"] if "label" in df.columns else df
        metrics = ["packets_per_second", "bytes_per_second", "connection_rate", "failure_ratio", "syn_ratio"]

        # Ensure derived metrics exist
        working_df = normal_df.copy()
        if "packets_per_second" not in working_df.columns:
            dur = working_df["duration_seconds"].replace(0, 0.001)
            working_df["packets_per_second"] = working_df["packet_count"] / dur
            working_df["bytes_per_second"] = working_df["byte_count"] / dur
            working_df["connection_rate"] = working_df["connection_count"] / dur
            working_df["failure_ratio"] = working_df["failed_connection_count"] / working_df["connection_count"].replace(0, 1)
            working_df["syn_ratio"] = working_df["syn_count"] / working_df["packet_count"].replace(0, 1)

        new_baseline = {}
        for m in metrics:
            if m in working_df.columns:
                series = working_df[m].astype(float)
                mean_val = float(series.mean())
                std_val = float(series.std()) if float(series.std()) > 0.0001 else 1.0
                q25_val = float(series.quantile(0.25))
                q75_val = float(series.quantile(0.75))
                new_baseline[m] = {
                    "mean": round(mean_val, 4),
                    "std": round(std_val, 4),
                    "q25": round(q25_val, 4),
                    "q75": round(q75_val, 4),
                }

        self.baseline = new_baseline
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, "w") as f:
                json.dump(self.baseline, f, indent=2)
            self.baseline_path = save_path

        return self.baseline

    def load_baseline(self, path: str):
        """Load pre-calibrated baseline from JSON file."""
        with open(path, "r") as f:
            self.baseline = json.load(f)

    def calculate_anomaly_score(self, features: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
        """
        Calculates an anomaly score (0-100) based on weighted Z-score deviations.

        :param features: Extracted flow features
        :return: (anomaly_score, metric_z_scores)
        """
        metric_weights = {
            "failure_ratio": 0.25,
            "syn_ratio": 0.25,
            "connection_rate": 0.25,
            "packets_per_second": 0.15,
            "bytes_per_second": 0.10,
        }

        z_scores = {}
        total_deviation = 0.0

        for metric, weight in metric_weights.items():
            base = self.baseline.get(metric, {"mean": 0.0, "std": 1.0})
            mean = base["mean"]
            std = base["std"] if base["std"] > 0 else 1.0
            val = float(features.get(metric, 0.0))

            # One-sided or absolute deviation depending on metric
            diff = max(0.0, val - mean)
            z = diff / std
            z_scores[metric] = round(z, 2)

            # Cap each metric's individual Z contribution to prevent extreme single-feature skew
            effective_z = min(10.0, z)
            total_deviation += effective_z * weight

        # Map combined deviation to 0-100 scale using sigmoid-like curve
        # z=0 -> ~0%, z=2 -> ~35%, z=3.5 -> ~65%, z=6 -> ~90%
        # formula: 100 * (1 - exp(-0.35 * total_deviation))
        raw_score = 100.0 * (1.0 - math.exp(-0.38 * total_deviation))
        anomaly_score = round(max(0.0, min(100.0, raw_score)), 1)

        return anomaly_score, z_scores
