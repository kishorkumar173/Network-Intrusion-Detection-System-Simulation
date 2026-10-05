"""
Alert Generation Engine
Generates structured security alerts for SOC triage with enriched context,
severity rankings, and recommended defensive investigation playbooks.
"""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional


ALERT_PLAYBOOKS = {
    "High Connection Rate": [
        "Check source host IP reputation against internal asset inventory.",
        "Review host authentication and service logs for rapid session spawning.",
        "Verify whether source IP belongs to an authorized automated load tester or proxy.",
        "Apply rate limiting or temporary connection throttling at network gateway if unapproved.",
    ],
    "Repeated Failed Connections": [
        "Inspect target host authentication logs (e.g., auth.log, Windows Security Event ID 4625).",
        "Identify targeted usernames and determine if credential stuffing or brute force is underway.",
        "Verify if account lockouts have triggered on target directory services.",
        "Enforce IP blocklist or multifactor authentication (MFA) enforcement policies.",
    ],
    "Multi-Port Probing Pattern": [
        "Analyze TCP flags and sequence numbers across probed destination ports.",
        "Check firewall drop logs to confirm perimeter defenses dropped probing packets.",
        "Review whether an internal vulnerability scanner (e.g., Tenable, Qualys) was scheduled.",
        "Isolate source host in quarantine VLAN if scanning is unsanctioned.",
    ],
    "SYN-Heavy Connection Behavior": [
        "Inspect TCP backlog queue and SYN-cookie activation metrics on destination servers.",
        "Verify if volumetric denial of service or half-open connection exhaustion is occurring.",
        "Enable SYN proxying or upstream DDoS mitigation scrubbers.",
        "Coordinate with network engineering to throttle offending ingress subnet.",
    ],
    "Unusual Service Port Activity": [
        "Investigate target service process binding (e.g. netstat/lsof on destination endpoint).",
        "Check endpoint detection and response (EDR) telemetry for unauthorized listener binaries.",
        "Determine if traffic is associated with command-and-control (C2) or remote access trojans.",
        "Quarantine endpoint and capture volatile memory dump for forensic analysis.",
    ],
    "Abnormally High Traffic Volume": [
        "Analyze NetFlow/IPFIX payload volume metrics and protocol distribution.",
        "Determine if data exfiltration or massive unauthorized file backup is in progress.",
        "Review Cloud Access Security Broker (CASB) and proxy logs for cloud upload activity.",
        "Review authorized data migration schedules with data engineering teams.",
    ],
}

DEFAULT_PLAYBOOK = [
    "Review correlated network flow records for associated source and destination IP.",
    "Cross-reference source IP against internal DHCP and asset management database.",
    "Examine historical baseline for this specific communication pair.",
    "Engage Tier 2 incident response if behavioral anomaly is sustained.",
]


class AlertEngine:
    """Manages security alert creation and contextual enrichment."""

    def __init__(self, alert_threshold_score: int = 40):
        self.alert_threshold_score = alert_threshold_score

    def generate_alert(
        self,
        flow_record: Dict[str, Any],
        features: Dict[str, Any],
        triggered_rules: List[Dict[str, Any]],
        risk_score: int,
        severity: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Generates an alert object if risk score exceeds threshold or a critical rule triggered.

        :param flow_record: Original raw flow dictionary
        :param features: Extracted flow features
        :param triggered_rules: Matched rules
        :param risk_score: Final calculated risk score (0-100)
        :param severity: Severity string (INFO, LOW, MEDIUM, HIGH, CRITICAL)
        :return: Alert dictionary or None
        """
        # Alerts are generated when risk >= 40 or at least one rule triggered
        if risk_score < self.alert_threshold_score and not triggered_rules:
            return None

        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        timestamp = flow_record.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Determine dominant alert type and rule ID
        if triggered_rules:
            primary_rule = triggered_rules[0]
            rule_id = primary_rule.get("rule_id", "ANOMALY-001")
            alert_type = primary_rule.get("name", "Behavioral Anomaly")
            description = primary_rule.get("reason", "Suspicious traffic pattern matched detection rule.")
        else:
            rule_id = "ANOMALY-001"
            alert_type = "Statistical Anomaly"
            description = f"Flow exhibited multi-metric statistical deviation with risk score of {risk_score}/100."

        # Fetch recommended investigation playbook
        playbook = ALERT_PLAYBOOKS.get(alert_type, DEFAULT_PLAYBOOK)

        alert = {
            "alert_id": alert_id,
            "flow_id": flow_record.get("flow_id", f"flow-{uuid.uuid4().hex[:6]}"),
            "timestamp": timestamp,
            "source_ip": features.get("source_ip"),
            "destination_ip": features.get("destination_ip"),
            "source_port": features.get("source_port"),
            "destination_port": features.get("destination_port"),
            "protocol": features.get("protocol"),
            "rule_id": rule_id,
            "alert_type": alert_type,
            "severity": severity,
            "risk_score": risk_score,
            "description": description,
            "status": "NEW",
            "recommended_steps": playbook,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        return alert
