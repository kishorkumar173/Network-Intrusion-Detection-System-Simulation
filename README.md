# Network Intrusion Detection System (IDS) Simulation

![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)
![Framework](https://img.shields.io/badge/framework-Flask%203.1-black.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-30%20passed-brightgreen.svg)
![SOC Type](https://img.shields.io/badge/architecture-Defensive%20Hybrid%20NIDS-red.svg)

> **DEFENSIVE CYBERSECURITY STATEMENT:** This project is designed exclusively for defensive cybersecurity education and SOC analyst training. All suspicious network behavior is represented using synthetic data records adhering strictly to RFC 5737 reserved documentation IP blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). It does not send raw network packets, flood networks, or probe external systems.

---

## Table of Contents
1. [Overview & Objectives](#overview--objectives)
2. [Cybersecurity & Industry Relevance](#cybersecurity--industry-relevance)
3. [Core IDS Concepts](#core-ids-concepts)
4. [System Architecture](#system-architecture)
5. [Technology Stack](#technology-stack)
6. [Synthetic Dataset Generator](#synthetic-dataset-generator)
7. [Traffic Simulator](#traffic-simulator)
8. [Feature Engineering & Validation](#feature-engineering--validation)
9. [Detection Engines](#detection-engines)
   - [Rule-Based Signature Engine](#rule-based-signature-engine)
   - [Statistical Anomaly Detector](#statistical-anomaly-detector)
   - [Machine Learning Classifiers](#machine-learning-classifiers)
   - [Hybrid Risk Scoring](#hybrid-risk-scoring)
10. [Alert Management & Correlation](#alert-management--correlation)
11. [SOC Dashboard & Investigation Console](#soc-dashboard--investigation-console)
12. [REST API Documentation](#rest-api-documentation)
13. [Installation & Quickstart](#installation--quickstart)
14. [Automated Testing Strategy](#automated-testing-strategy)
15. [False Positives vs False Negatives](#false-positives-vs-false-negatives)
16. [Future Scope](#future-scope)
17. [License & Ethical Disclaimer](#license--ethical-disclaimer)

---

## Overview & Objectives

Modern enterprise Security Operations Centers (SOCs) rely on Intrusion Detection Systems (IDS) such as Suricata, Snort, and Zeek coupled with security analytics platforms to identify unauthorized network activity, reconnaissance, and protocol abuse.

This project delivers a **Defensive Network Intrusion Detection System (IDS) Simulation** that implements:
- Synthetic network flow generation using safe documentation IP ranges.
- Multi-tier hybrid detection fusing deterministic signature rules, statistical Z-score baseline deviations, and supervised machine learning (Random Forest).
- Calibrated 0–100 risk scoring with categorical classifications (`NORMAL`, `LOW RISK`, `SUSPICIOUS`, `HIGH RISK`, `CRITICAL INVESTIGATION`).
- Structured security alert generation with severity ratings and tailored defensive SOC investigation playbooks.
- Rolling time-window alert correlation to eliminate alert fatigue.
- Full-featured, responsive dark-theme SOC Dashboard with live metrics, 5 interactive charts, event triage, and incident lifecycle management (`NEW` &rarr; `INVESTIGATING` &rarr; `RESOLVED` / `FALSE_POSITIVE`).

---

## Cybersecurity & Industry Relevance

### How IDS Technology is Deployed:
- **SOCs & MSSPs:** Continuous 24/7 monitoring of network ingress/egress to detect scanning, credential abuse, and command-and-control (C2) beaconing.
- **Financial Institutions & Banks:** Segmentation monitoring to identify lateral movement between sensitive payment zones and general workstation subnets.
- **Cloud & Data Center Providers:** High-throughput flow monitoring to spot volumetric surges and Distributed Denial-of-Service (DDoS) precursors.
- **Critical Infrastructure & Government:** Rigorous protocol inspection to detect anomalies in industrial and administrative control systems.

### Relevant Cybersecurity Job Roles:
- **SOC Analyst (Tier 1 / Tier 2):** Triages incoming security alerts, analyzes packet flow statistics, executes investigation playbooks, and documents root causes.
- **Network Security Engineer:** Configures intrusion detection sensors, tunes signature thresholds, and manages perimeter firewalls.
- **Cybersecurity Detection Engineer:** Designs custom detection rules, feature engineering pipelines, and anomaly detection models.
- **Incident Response Analyst:** Formulates remediation strategies and containment actions based on correlated security incidents.

---

## Core IDS Concepts

| Concept | Explanation |
| :--- | :--- |
| **Network Traffic** | The aggregate volume of data packets moving across a computer network at any given time. |
| **Network Flow** | An unidirectional or bidirectional sequence of packets sharing 5 core attributes (Source IP, Destination IP, Source Port, Destination Port, Protocol) within a given timeframe. |
| **Packet** | The fundamental discrete unit of data formatted for transmission over a packet-switched network. |
| **Security Event** | Any observable occurrence in a system or network (e.g., connection established, TCP SYN received). |
| **Security Alert** | A high-priority notification produced when a security event or series of events triggers an analytic rule or anomaly threshold. |
| **Security Incident** | An event or collection of correlated alerts that adversely affects or threatens the confidentiality, integrity, or availability of organizational systems. |
| **IDS vs. IPS** | An **IDS** inspects traffic out-of-band and alerts defenders without disrupting communication. An **IPS** sits in-line and can actively drop packets, reset connections, or blacklist IPs automatically. |
| **NIDS vs. HIDS** | **NIDS** monitors network flow points and choke points for subnet-wide visibility. **HIDS** (e.g., OSSEC, Wazuh agent) monitors individual host operating system logs, file integrity, and process trees. |
| **Signature vs. Anomaly** | **Signature Detection** matches known strings, ports, or byte thresholds (fast, explainable, low false-positive rate, but blind to zero-days). **Anomaly Detection** flags deviations from learned historical baselines (detects novel attacks, but produces higher false positives). |

---

## System Architecture

```
        ┌────────────────────────────────────────────────────────┐
        │  Synthetic Network Flow Stream / Pre-generated Dataset │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │              REST API Flow Ingestion Gateway           │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │               Feature Extraction Engine                │
        │  - IPv4 & Port Bounds Sanitization                     │
        │  - Division-by-Zero Safety                             │
        │  - Rate Calculation (B/s, Pkts/s, Failure Ratio)      │
        └───────────────────────────┬────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
│  Signature Engine    │ │  Anomaly Detector    │ │  Machine Learning    │
│  - IDS-001 Conn Rate │ │  - Baseline Mean/Std │ │  - Random Forest     │
│  - IDS-002 Failures  │ │  - Z-Score Deviation │ │  - Logistic Reg      │
│  - IDS-003 Port Sweep│ │  - IQR Multi-Metric  │ │  - Isolation Forest  │
│  - IDS-004 SYN Flood │ │  - Anomaly (0-100)   │ │  - Malicious Prob    │
│  - IDS-005 Ports     │ │                      │ │                      │
│  - IDS-006 Volume    │ │                      │ │                      │
└──────────┬───────────┘ └──────────┬───────────┘ └──────────┬───────────┘
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │              Hybrid Risk Scoring Engine                │
        │  Risk = (0.40 * Rules) + (0.30 * Anomaly) + (0.30 * ML)│
        │  Mapped to 0-100 & Severity (INFO -> CRITICAL)         │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │                 Alert Generation Engine                │
        │  - Contextual Triage Metadata                          │
        │  - Defensive Playbooks & Action Recommendations        │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │                Alert Correlation Engine                │
        │  - Grouping by (Source IP, Type, 60s Rolling Window)   │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │            SQLite Relational Database Storage          │
        │  - Indexed Queries (timestamp, source_ip, status)      │
        └───────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │            SOC Live Web Dashboard & Triage Console     │
        │  - 5 Interactive Charts (Chart.js)                     │
        │  - 6 Real-Time Metric Top Cards                        │
        │  - Alert Investigation & Analyst Notes Timeline        │
        └────────────────────────────────────────────────────────┘
```

---

## Technology Stack

- **Backend:** Python 3.13, Flask 3.1
- **Machine Learning & Analytics:** Scikit-Learn 1.7, Pandas 2.3, NumPy 2.2, Joblib 1.5
- **Data Storage:** SQLite 3 (Foreign key enforced, PRAGMA synchronous tuned)
- **Frontend Dashboard:** HTML5, CSS3, JavaScript (ES6+), Bootstrap 5.3, Chart.js 4.4, FontAwesome 6
- **Test Automation:** Pytest 8.4

---

## Synthetic Dataset Generator

Located at `simulator/generate_dataset.py`, this script generates 6,000 realistic network flow records without generating raw traffic packets.

To run:
```bash
python simulator/generate_dataset.py
```

### Dataset Schema:
| Column | Type | Description |
| :--- | :--- | :--- |
| `flow_id` | String | Unique UUID for the flow record |
| `timestamp` | String | Format: `YYYY-MM-DD HH:MM:SS` |
| `source_ip` | String | RFC 5737 TEST-NET address (`192.0.2.0/24`) |
| `destination_ip` | String | RFC 5737 TEST-NET address (`198.51.100.0/24` or `203.0.113.0/24`) |
| `source_port` | Integer | Ephemeral source port (49152–65535) |
| `destination_port` | Integer | Service port (e.g. 80, 443, 22, 53, 4444) |
| `protocol` | String | `TCP`, `UDP`, or `ICMP` |
| `packet_count` | Integer | Total packets transmitted |
| `byte_count` | Integer | Total bytes transferred |
| `duration_seconds` | Float | Session duration in seconds |
| `connection_count` | Integer | Connection attempts in sampling period |
| `failed_connection_count` | Integer | Failed handshakes or authentication rejections |
| `syn_count` | Integer | Number of TCP SYN flags observed |
| `rst_count` | Integer | Number of TCP RST flags observed |
| `average_packet_size` | Float | Calculated `byte_count / packet_count` |
| `label` | String | `NORMAL` or `SUSPICIOUS` |
| `scenario_type` | String | Detailed scenario name |

---

## Traffic Simulator

Located at `simulator/traffic_simulator.py`, the simulator can stream continuous flow telemetry directly into the IDS REST API or output to console.

```bash
# Stream mixed traffic at fast pace to local backend
python simulator/traffic_simulator.py --mode mixed --speed fast --target-url http://127.0.0.1:5000/api/flows

# Stream only benign traffic slowly
python simulator/traffic_simulator.py --mode normal --speed slow
```

---

## Detection Engines

### Rule-Based Signature Engine
Configured in `ids/rule_engine.py`:
- **IDS-001 (High Connection Rate):** `connection_rate > 35.0/sec` and `connection_count >= 20`
- **IDS-002 (Repeated Failed Connections):** `failed_connections >= 15` and `failure_ratio >= 0.65`
- **IDS-003 (Multi-Port Probing Pattern):** `connection_count >= 25` and `rst_count >= 15` (or `unique_ports >= 5`)
- **IDS-004 (SYN-Heavy Flood):** `syn_ratio >= 0.75` and `syn_count >= 50`
- **IDS-005 (Unusual Service Port Activity):** `destination_port in [4444, 5555, 6667, 31337, 1337, 8888, 9999]`
- **IDS-006 (Abnormally High Traffic Volume):** `byte_count >= 2,000,000` or `bytes_per_second >= 300,000`

### Statistical Anomaly Detector
Configured in `ids/anomaly_detector.py`:
Computes historical means and standard deviations from known normal flows across:
- `packets_per_second`
- `bytes_per_second`
- `connection_rate`
- `failure_ratio`
- `syn_ratio`

Computes modified Z-scores:
$$Z = \frac{\text{Observed} - \mu}{\sigma}$$
Yields an anomaly score from 0 to 100 via an exponential saturation curve.

### Machine Learning Benchmark Results
Evaluated on an 80/20 train/test split of 6,000 genuine flow records:
```
======================================================================
      NETWORK IDS MACHINE LEARNING MODEL BENCHMARK REPORT      
======================================================================
Model Name               | Accuracy   | Precision  | Recall     | F1-Score  
----------------------------------------------------------------------
Random Forest            |   100.00%  |   100.00%  |   100.00%  |   100.00%
Logistic Regression      |    98.75%  |   100.00%  |    95.83%  |    97.87%
Isolation Forest         |    80.50%  |    60.61%  |   100.00%  |    75.47%
======================================================================

CONFUSION MATRICES:

[Random Forest]
  True Negative  (TN): 840   | False Positive (FP): 0    
  False Negative (FN): 0     | True Positive  (TP): 360  

[Logistic Regression]
  True Negative  (TN): 840   | False Positive (FP): 0    
  False Negative (FN): 15    | True Positive  (TP): 345  

[Isolation Forest]
  True Negative  (TN): 606   | False Positive (FP): 234  
  False Negative (FN): 0     | True Positive  (TP): 360  
```

### Hybrid Risk Scoring
Combines all three detection paradigms:
$$\text{Risk Score} = (0.40 \times \text{RuleScore}) + (0.30 \times \text{AnomalyScore}) + (0.30 \times \text{MLProbability} \times 100)$$

Risk brackets:
- `0–20:` **NORMAL** (`INFO`)
- `21–40:` **LOW RISK** (`LOW`)
- `41–60:` **SUSPICIOUS** (`MEDIUM`)
- `61–80:` **HIGH RISK** (`HIGH`)
- `81–100:` **CRITICAL INVESTIGATION** (`CRITICAL`)

---

## SOC Dashboard & Investigation Console

The web UI provides a full SOC operations center:
1. **Top Cards:** Total Flows, Normal Flows, Suspicious Flows, Open Alerts, Critical Alerts, Average Risk Score.
2. **Scenario Injector Bar:** Injects simulated attacks with a single click (`Normal HTTPS`, `High Conn Rate`, `Failed Conns`, `Multi-Port Sweep`, `SYN Flood`, `Volumetric Surge`).
3. **Five Real-Time Charts:**
   - Traffic Over Time (Packets & Risk timeline)
   - Normal vs. Suspicious Donut
   - Alerts by Severity Bar
   - Top Alert Types Horizontal Bar
   - Protocol Distribution Pie
4. **Alerts Triage Queue:** Filterable by severity and status.
5. **Event Investigation Page (`/investigation`):** Complete flow telemetry breakdown, multi-layer score display, defensive playbook recommendations, status toggling, and analyst notes timeline.
6. **Incident Management Page (`/incidents`):** Correlated security clusters grouped by source IP and detection type.

---

## REST API Documentation

| Method | Endpoint | Description | Status Code |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/flows` | Ingests and inspects raw network flow | `201 Created` |
| `GET` | `/api/flows` | Lists flows with limit, protocol, and classification filters | `200 OK` |
| `GET` | `/api/flows/<id>` | Retrieves flow metadata and associated alert/ML score | `200 OK` |
| `GET` | `/api/alerts` | Lists alerts filtered by severity and status | `200 OK` |
| `GET` | `/api/alerts/<id>` | Retrieves complete alert, telemetry, and notes timeline | `200 OK` |
| `PUT` | `/api/alerts/<id>/status`| Updates alert status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) | `200 OK` |
| `POST`| `/api/alerts/<id>/notes` | Appends documented analyst note to incident | `201 Created` |
| `GET` | `/api/rules` | Retrieves active signature rules and thresholds | `200 OK` |
| `PUT` | `/api/rules/<id>` | Updates rule threshold or enables/disables rule | `200 OK` |
| `GET` | `/api/dashboard/stats`| Aggregated metrics for SOC top cards | `200 OK` |
| `GET` | `/api/dashboard/traffic`| Time-series data points for charts | `200 OK` |
| `GET` | `/api/dashboard/alerts` | Top recent alerts for dashboard triage table | `200 OK` |
| `POST`| `/api/simulation/trigger` | Injects on-demand synthetic scenario | `201 Created` |

---

## Installation & Quickstart

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Git

### Step-by-Step Execution:
```bash
# 1. Clone repository
git clone https://github.com/<your-username>/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate synthetic training dataset (6,000 records)
python simulator/generate_dataset.py

# 4. Train ML models and calibrate statistical baselines
python ml/train_model.py

# 5. Seed the database with initial telemetry
python simulator/seed_database.py

# 6. Run the automated test suite (30 tests)
pytest tests/test_ids_suite.py -v

# 7. Start the Flask SOC Dashboard
python backend/app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

To stream live traffic in another terminal:
```bash
python simulator/traffic_simulator.py --mode mixed --speed fast --target-url http://127.0.0.1:5000/api/flows
```

---

## Automated Testing Strategy

The test suite in `tests/test_ids_suite.py` executes 30 automated test cases:
1. `test_01_normal_tcp_flow` &bull; PASSED
2. `test_02_normal_udp_flow` &bull; PASSED
3. `test_03_normal_dns_flow` &bull; PASSED
4. `test_04_normal_https_flow` &bull; PASSED
5. `test_05_high_connection_rate_rule` &bull; PASSED
6. `test_06_repeated_failed_connections_rule` &bull; PASSED
7. `test_07_multi_port_probing_pattern_rule` &bull; PASSED
8. `test_08_syn_heavy_pattern_rule` &bull; PASSED
9. `test_09_high_traffic_volume_rule` &bull; PASSED
10. `test_10_invalid_source_ip` &bull; PASSED
11. `test_11_invalid_destination_ip` &bull; PASSED
12. `test_12_invalid_source_port` &bull; PASSED
13. `test_13_invalid_destination_port` &bull; PASSED
14. `test_14_unsupported_protocol` &bull; PASSED
15. `test_15_missing_packet_count_defaults` &bull; PASSED
16. `test_16_zero_duration_division_safety` &bull; PASSED
17. `test_17_feature_extraction_derived_metrics` &bull; PASSED
18. `test_18_rule_engine_toggle` &bull; PASSED
19. `test_19_anomaly_score_bounds` &bull; PASSED
20. `test_20_risk_score_weighted_logic` &bull; PASSED
21. `test_21_alert_creation_structure` &bull; PASSED
22. `test_22_alert_correlation_grouping` &bull; PASSED
23. `test_23_alert_status_transition` &bull; PASSED
24. `test_24_analyst_note_documentation` &bull; PASSED
25. `test_25_database_storage_persistence` &bull; PASSED
26. `test_26_dashboard_statistics` &bull; PASSED
27. `test_27_ml_prediction_fallback` &bull; PASSED
28. `test_28_api_ingestion_validation` &bull; PASSED
29. `test_29_empty_dataset_detector` &bull; PASSED
30. `test_30_duplicate_flow_storage` &bull; PASSED

**Result:** `30 passed in 7.80s (100% pass rate)`.

---

## False Positives vs False Negatives

- **False Positive (FP):** Legitimate activity incorrectly flagged as an intrusion (e.g., scheduled database backup creating a volumetric surge). High FP rates cause alert fatigue, analyst burnout, and missed critical threats.
- **False Negative (FN):** An actual malicious intrusion classified as benign. FNs allow attackers to remain undetected in a network.
- **Mitigation:** The hybrid architecture ensures no single engine acts as a single point of failure. Rules provide explainable bounds, ML identifies complex relationships, and statistical Z-scores surface novel deviations.

---

## Ethical Disclaimer

This software simulation is designed exclusively for educational, defensive, and academic research purposes. It must not be deployed against unapproved networks or used for offensive cyber actions. The authors disclaim liability for improper usage outside controlled lab environments.
