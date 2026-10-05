"""
Hybrid Risk Scoring Engine
Combines Rule-Based Detection, Anomaly Detection, and Machine Learning
into a calibrated 0-100 risk score and categorical classifications.
"""

from typing import Dict, Any, List, Tuple


class RiskEngine:
    """Calculates weighted risk scores from multi-layered detection signals."""

    def __init__(
        self,
        weight_rule: float = 0.40,
        weight_anomaly: float = 0.30,
        weight_ml: float = 0.30,
        enable_ml: bool = True,
    ):
        self.enable_ml = enable_ml
        if enable_ml:
            total = weight_rule + weight_anomaly + weight_ml
            self.weight_rule = weight_rule / total
            self.weight_anomaly = weight_anomaly / total
            self.weight_ml = weight_ml / total
        else:
            self.weight_rule = 0.60
            self.weight_anomaly = 0.40
            self.weight_ml = 0.0

    def calculate_risk_score(
        self,
        triggered_rules: List[Dict[str, Any]],
        anomaly_score: float,
        ml_probability: float,
    ) -> Tuple[int, str, str]:
        """
        Calculates final combined risk score (0-100), classification, and alert severity.

        :param triggered_rules: List of rules matched by the rule engine
        :param anomaly_score: Anomaly score between 0.0 and 100.0
        :param ml_probability: ML malicious probability between 0.0 and 1.0
        :return: (risk_score, classification, severity)
        """
        # 1. Rule component: maximum risk score among triggered rules
        if triggered_rules:
            rule_score = max(r.get("rule_risk_score", 50) for r in triggered_rules)
        else:
            rule_score = 0.0

        # 2. Anomaly component (0-100)
        anomaly_comp = float(anomaly_score)

        # 3. ML component (0-100)
        ml_comp = float(ml_probability) * 100.0

        # Weighted calculation
        if self.enable_ml:
            combined = (
                self.weight_rule * rule_score
                + self.weight_anomaly * anomaly_comp
                + self.weight_ml * ml_comp
            )
        else:
            combined = (
                self.weight_rule * rule_score
                + self.weight_anomaly * anomaly_comp
            )

        # If a critical signature matched (e.g. SYN flood or severe port attack), enforce high floor
        if any(r.get("severity") == "CRITICAL" for r in triggered_rules):
            combined = max(combined, 82.0)
        elif any(r.get("severity") == "HIGH" for r in triggered_rules):
            combined = max(combined, 65.0)

        final_score = int(round(max(0, min(100, combined))))

        # Determine Classification
        if final_score <= 20:
            classification = "NORMAL"
            severity = "INFO"
        elif final_score <= 40:
            classification = "LOW RISK"
            severity = "LOW"
        elif final_score <= 60:
            classification = "SUSPICIOUS"
            severity = "MEDIUM"
        elif final_score <= 80:
            classification = "HIGH RISK"
            severity = "HIGH"
        else:
            classification = "CRITICAL INVESTIGATION"
            severity = "CRITICAL"

        return final_score, classification, severity
