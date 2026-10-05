"""
Alert Correlation Engine
Groups repeated and related security alerts across time windows, source IP,
and alert types to minimize alert fatigue and escalate to Security Incidents.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List


class AlertCorrelator:
    """Correlates alerts into grouped incident clusters."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # In-memory correlation buffer: key = (source_ip, alert_type) -> list of alerts
        self.active_groups: Dict[tuple, List[Dict[str, Any]]] = {}

    def correlate_alert(self, new_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a newly generated alert, checks for existing correlation cluster,
        and returns enriched incident metadata.
        """
        src_ip = new_alert.get("source_ip")
        alert_type = new_alert.get("alert_type")
        key = (src_ip, alert_type)

        try:
            alert_time = datetime.strptime(new_alert.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            alert_time = datetime.now()

        # Prune old alerts outside window
        cutoff = alert_time - timedelta(seconds=self.window_seconds)
        if key in self.active_groups:
            self.active_groups[key] = [
                a for a in self.active_groups[key]
                if datetime.strptime(a.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")), "%Y-%m-%d %H:%M:%S") >= cutoff
            ]

        if key not in self.active_groups or len(self.active_groups[key]) == 0:
            self.active_groups[key] = [new_alert]
            incident_id = f"INC-{new_alert['alert_id'].replace('ALT-', '')}"
            group_count = 1
        else:
            self.active_groups[key].append(new_alert)
            group_count = len(self.active_groups[key])
            incident_id = f"INC-{self.active_groups[key][0]['alert_id'].replace('ALT-', '')}"

        correlation_info = {
            "incident_id": incident_id,
            "correlation_key": f"{src_ip}:{alert_type}",
            "correlated_count": group_count,
            "is_aggregated": group_count > 1,
            "window_seconds": self.window_seconds,
        }

        return correlation_info


def correlate_alerts(alert_list: List[Dict[str, Any]], window_seconds: int = 60) -> List[Dict[str, Any]]:
    """
    Batch helper to group an arbitrary list of alerts into incident clusters.
    """
    correlator = AlertCorrelator(window_seconds=window_seconds)
    incidents = {}

    for alert in alert_list:
        info = correlator.correlate_alert(alert)
        inc_id = info["incident_id"]
        if inc_id not in incidents:
            incidents[inc_id] = {
                "incident_id": inc_id,
                "source_ip": alert["source_ip"],
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "max_risk_score": alert["risk_score"],
                "alerts": [alert],
                "first_seen": alert["timestamp"],
                "last_seen": alert["timestamp"],
            }
        else:
            inc = incidents[inc_id]
            inc["alerts"].append(alert)
            inc["last_seen"] = alert["timestamp"]
            inc["max_risk_score"] = max(inc["max_risk_score"], alert["risk_score"])
            # Escalate severity if repeated occurrences
            if len(inc["alerts"]) >= 5 and inc["severity"] != "CRITICAL":
                inc["severity"] = "HIGH"
            if len(inc["alerts"]) >= 10:
                inc["severity"] = "CRITICAL"

    return list(incidents.values())
