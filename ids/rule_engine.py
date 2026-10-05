"""
Rule-Based Intrusion Detection Engine
Implements deterministic, signature-like detection rules with configurable thresholds.
"""

from typing import Dict, Any, List, Optional


DEFAULT_RULES = {
    "IDS-001": {
        "rule_id": "IDS-001",
        "name": "High Connection Rate",
        "severity": "HIGH",
        "description": "Connection rate per second exceeded configured baseline threshold.",
        "enabled": True,
        "threshold": {"connection_rate": 35.0, "min_connections": 20},
    },
    "IDS-002": {
        "rule_id": "IDS-002",
        "name": "Repeated Failed Connections",
        "severity": "HIGH",
        "description": "Abnormal volume of failed authentication or handshake attempts detected.",
        "enabled": True,
        "threshold": {"failed_connections": 15, "failure_ratio": 0.65},
    },
    "IDS-003": {
        "rule_id": "IDS-003",
        "name": "Multi-Port Probing Pattern",
        "severity": "MEDIUM",
        "description": "Sequential or broad port sweep indicators matching reconnaissance activity.",
        "enabled": True,
        "threshold": {"min_connections": 25, "rst_count": 15},
    },
    "IDS-004": {
        "rule_id": "IDS-004",
        "name": "SYN-Heavy Connection Behavior",
        "severity": "CRITICAL",
        "description": "High proportion of SYN packets relative to data flow, characteristic of SYN flooding.",
        "enabled": True,
        "threshold": {"syn_ratio": 0.75, "min_syn_count": 50},
    },
    "IDS-005": {
        "rule_id": "IDS-005",
        "name": "Unusual Service Port Activity",
        "severity": "HIGH",
        "description": "Traffic targeting suspicious or non-standard administrative/backdoor service ports.",
        "enabled": True,
        "threshold": {"unusual_ports": [4444, 5555, 6667, 31337, 1337, 8888, 9999]},
    },
    "IDS-006": {
        "rule_id": "IDS-006",
        "name": "Abnormally High Traffic Volume",
        "severity": "MEDIUM",
        "description": "Byte count or byte transfer rate exceeds typical operational profile.",
        "enabled": True,
        "threshold": {"byte_count": 2_000_000, "bytes_per_second": 300_000},
    },
}


class RuleEngine:
    """Manages detection signatures and evaluates flow feature records."""

    def __init__(self, rules: Optional[Dict[str, Dict[str, Any]]] = None):
        self.rules = rules or DEFAULT_RULES.copy()

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update configurable thresholds or toggle enable state."""
        if rule_id in self.rules:
            self.rules[rule_id].update(updates)
            return True
        return False

    def get_rules(self) -> List[Dict[str, Any]]:
        """Return list of all configured rules."""
        return list(self.rules.values())

    def analyze_flow(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate extracted features against all enabled detection signatures.

        :param features: Cleaned numerical and metadata features
        :return: List of triggered rule dictionaries
        """
        triggered_rules = []

        # RULE 1: High Connection Rate (IDS-001)
        r1 = self.rules.get("IDS-001")
        if r1 and r1.get("enabled", True):
            t_rate = r1["threshold"].get("connection_rate", 35.0)
            t_conn = r1["threshold"].get("min_connections", 20)
            if features.get("connection_rate", 0) > t_rate and features.get("connection_count", 0) >= t_conn:
                triggered_rules.append({
                    "rule_id": r1["rule_id"],
                    "name": r1["name"],
                    "severity": r1["severity"],
                    "reason": (
                        f"Connection rate {features['connection_rate']:.1f}/s exceeded baseline "
                        f"threshold of {t_rate}/s (Total conns: {features['connection_count']})"
                    ),
                    "rule_risk_score": 75,
                })

        # RULE 2: Repeated Failed Connections (IDS-002)
        r2 = self.rules.get("IDS-002")
        if r2 and r2.get("enabled", True):
            t_failed = r2["threshold"].get("failed_connections", 15)
            t_ratio = r2["threshold"].get("failure_ratio", 0.65)
            if features.get("failed_connection_count", 0) >= t_failed and features.get("failure_ratio", 0) >= t_ratio:
                triggered_rules.append({
                    "rule_id": r2["rule_id"],
                    "name": r2["name"],
                    "severity": r2["severity"],
                    "reason": (
                        f"Detected {features['failed_connection_count']} failed connections with "
                        f"{features['failure_ratio']*100:.1f}% failure ratio on port {features.get('destination_port')}"
                    ),
                    "rule_risk_score": 80,
                })

        # RULE 3: Multi-Port Probing Pattern (IDS-003)
        r3 = self.rules.get("IDS-003")
        if r3 and r3.get("enabled", True):
            t_min_conns = r3["threshold"].get("min_connections", 25)
            t_rst = r3["threshold"].get("rst_count", 15)
            # Either high unique ports or high connection count with elevated RST returns
            if (features.get("unique_destination_ports", 1) >= 5 or 
                (features.get("connection_count", 0) >= t_min_conns and features.get("rst_count", 0) >= t_rst)):
                triggered_rules.append({
                    "rule_id": r3["rule_id"],
                    "name": r3["name"],
                    "severity": r3["severity"],
                    "reason": (
                        f"Reconnaissance pattern: {features.get('connection_count')} connections with "
                        f"{features.get('rst_count')} TCP RST rejections across port {features.get('destination_port')}"
                    ),
                    "rule_risk_score": 65,
                })

        # RULE 4: SYN-Heavy Connection Behavior (IDS-004)
        r4 = self.rules.get("IDS-004")
        if r4 and r4.get("enabled", True):
            t_syn_ratio = r4["threshold"].get("syn_ratio", 0.75)
            t_syn_count = r4["threshold"].get("min_syn_count", 50)
            if features.get("syn_ratio", 0) >= t_syn_ratio and features.get("syn_count", 0) >= t_syn_count:
                triggered_rules.append({
                    "rule_id": r4["rule_id"],
                    "name": r4["name"],
                    "severity": r4["severity"],
                    "reason": (
                        f"SYN packet dominance: {features['syn_count']} SYN packets accounting for "
                        f"{features['syn_ratio']*100:.1f}% of total flow packets"
                    ),
                    "rule_risk_score": 90,
                })

        # RULE 5: Unusual Service Port Activity (IDS-005)
        r5 = self.rules.get("IDS-005")
        if r5 and r5.get("enabled", True):
            suspicious_ports = r5["threshold"].get("unusual_ports", [4444, 5555, 6667, 31337, 1337, 8888, 9999])
            if features.get("destination_port") in suspicious_ports:
                triggered_rules.append({
                    "rule_id": r5["rule_id"],
                    "name": r5["name"],
                    "severity": r5["severity"],
                    "reason": (
                        f"Access attempt to known suspicious/unassigned service port: {features.get('destination_port')} "
                        f"({features.get('protocol')})"
                    ),
                    "rule_risk_score": 70,
                })

        # RULE 6: Abnormally High Traffic Volume (IDS-006)
        r6 = self.rules.get("IDS-006")
        if r6 and r6.get("enabled", True):
            t_bytes = r6["threshold"].get("byte_count", 2_000_000)
            t_rate = r6["threshold"].get("bytes_per_second", 300_000)
            if features.get("byte_count", 0) >= t_bytes or features.get("bytes_per_second", 0) >= t_rate:
                triggered_rules.append({
                    "rule_id": r6["rule_id"],
                    "name": r6["name"],
                    "severity": r6["severity"],
                    "reason": (
                        f"Volumetric surge: {features.get('byte_count'):,} bytes transferred at "
                        f"{features.get('bytes_per_second'):,.0f} B/s"
                    ),
                    "rule_risk_score": 60,
                })

        return triggered_rules
