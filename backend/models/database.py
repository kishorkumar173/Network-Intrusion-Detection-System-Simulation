"""
Database Architecture and Data Access Layer
Implements SQLite persistent schema for Flows, Alerts, Rules, Incident Notes, and ML Results.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional


DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "network_ids.db",
)


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Creates a thread-safe connection to the SQLite database with dictionary rows."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_database(db_path: str = DEFAULT_DB_PATH):
    """Initializes tables, indexes, and default signature rules."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. NETWORK_FLOWS table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_flows (
            flow_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            destination_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL,
            duration REAL NOT NULL,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            scenario_type TEXT DEFAULT 'UNKNOWN'
        );
    """)

    # 2. ALERTS table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            flow_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            recommended_steps TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE
        );
    """)

    # 3. RULES table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            threshold_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        );
    """)

    # 4. INCIDENT_NOTES table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT 'SOC Analyst',
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
        );
    """)

    # 5. MODEL_RESULTS table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id TEXT NOT NULL,
            model_name TEXT NOT NULL,
            prediction INTEGER NOT NULL,
            score REAL NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE
        );
    """)

    # Performance and query optimization indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_source_ip ON network_flows(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts(flow_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_notes_alert_id ON incident_notes(alert_id);")

    # Seed Default Rules if empty
    cursor.execute("SELECT COUNT(*) FROM rules;")
    if cursor.fetchone()[0] == 0:
        from ids.rule_engine import DEFAULT_RULES
        for r_id, r in DEFAULT_RULES.items():
            cursor.execute(
                """
                INSERT INTO rules (rule_id, rule_name, description, severity, threshold_json, enabled)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    r["rule_id"],
                    r["name"],
                    r["description"],
                    r["severity"],
                    json.dumps(r["threshold"]),
                    1 if r.get("enabled", True) else 0,
                ),
            )

    conn.commit()
    conn.close()


def save_flow_and_alert(
    flow_dict: Dict[str, Any],
    alert_dict: Optional[Dict[str, Any]],
    ml_result: Optional[Dict[str, Any]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    """Atomic transaction to save flow event, associated alert, and ML outcome."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT OR REPLACE INTO network_flows (
                flow_id, timestamp, source_ip, destination_ip, source_port, destination_port,
                protocol, packet_count, byte_count, duration, risk_score, classification, scenario_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                flow_dict["flow_id"],
                flow_dict["timestamp"],
                flow_dict["source_ip"],
                flow_dict["destination_ip"],
                flow_dict["source_port"],
                flow_dict["destination_port"],
                flow_dict["protocol"],
                flow_dict["packet_count"],
                flow_dict["byte_count"],
                flow_dict["duration"],
                flow_dict["risk_score"],
                flow_dict["classification"],
                flow_dict.get("scenario_type", "UNKNOWN"),
            ),
        )

        if alert_dict:
            rec_steps = json.dumps(alert_dict.get("recommended_steps", []))
            cursor.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, flow_id, rule_id, alert_type, severity, description,
                    risk_score, status, recommended_steps, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    alert_dict["alert_id"],
                    alert_dict["flow_id"],
                    alert_dict["rule_id"],
                    alert_dict["alert_type"],
                    alert_dict["severity"],
                    alert_dict["description"],
                    alert_dict["risk_score"],
                    alert_dict.get("status", "NEW"),
                    rec_steps,
                    alert_dict["created_at"],
                ),
            )

        if ml_result:
            cursor.execute(
                """
                INSERT INTO model_results (flow_id, model_name, prediction, score, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    ml_result["flow_id"],
                    ml_result.get("model_name", "RandomForest"),
                    ml_result["prediction"],
                    ml_result["score"],
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"[!] Database transaction error: {e}")
        return False
    finally:
        conn.close()


def get_dashboard_metrics(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Retrieves top-card aggregate metrics and distributions for SOC Dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM network_flows;")
    total_flows = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM network_flows WHERE classification = 'NORMAL';")
    normal_flows = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM network_flows WHERE classification != 'NORMAL';")
    suspicious_flows = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'INVESTIGATING');")
    open_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status != 'RESOLVED';")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM network_flows;")
    avg_risk = cursor.fetchone()[0]
    avg_risk = round(avg_risk, 1) if avg_risk is not None else 0.0

    # Severity distribution
    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity;")
    sev_counts = dict(cursor.fetchall())

    # Top Alert Types
    cursor.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type ORDER BY cnt DESC LIMIT 5;")
    top_alert_types = [dict(row) for row in cursor.fetchall()]

    # Protocol distribution
    cursor.execute("SELECT protocol, COUNT(*) as cnt FROM network_flows GROUP BY protocol;")
    proto_dist = [dict(row) for row in cursor.fetchall()]

    # Top Source IPs by Alerts
    cursor.execute("""
        SELECT f.source_ip, COUNT(*) as cnt
        FROM alerts a
        JOIN network_flows f ON a.flow_id = f.flow_id
        GROUP BY f.source_ip ORDER BY cnt DESC LIMIT 5;
    """)
    top_sources = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "total_flows": total_flows,
        "normal_flows": normal_flows,
        "suspicious_flows": suspicious_flows,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "average_risk_score": avg_risk,
        "severity_distribution": sev_counts,
        "top_alert_types": top_alert_types,
        "protocol_distribution": proto_dist,
        "top_sources": top_sources,
    }
