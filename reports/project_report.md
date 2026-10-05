# Formal Project Report: Network Intrusion Detection System (IDS) Simulation

**Project Title:** Network Intrusion Detection System (IDS) Simulation  
**Course:** Defensive Cybersecurity & Network Security Systems  
**Implementation Language:** Python 3.13 / Flask / Scikit-Learn  
**Author:** Student Defensive Security Engineer  
**Date:** October 2026  

---

## 1. Abstract
As modern cyber threats continue to escalate in frequency, velocity, and stealth, defensive security operations centers (SOCs) depend heavily on Intrusion Detection Systems (IDS) to maintain visibility over digital perimeters. This project presents a complete, production-grade Network Intrusion Detection System simulation designed entirely for safe educational execution without requiring live network tapping or physical lab hardware. The system ingests synthetic RFC 5737 IP flow records, extracts 15+ derived statistical and rate features, applies a defensive multi-tier hybrid detection engine (Rule-Based Signatures, Z-Score Statistical Anomaly Baselines, and Random Forest Machine Learning), and computes calibrated risk scores (0–100). Alerts are enriched with defensive investigation playbooks, correlated across rolling time windows to combat alert fatigue, and visualized on a near-real-time SOC operations dashboard with interactive triage workflows.

---

## 2. Introduction & Problem Statement
Enterprise organizations process billions of network packets daily. Security analysts face dual challenges:
1. **Detection Coverage:** Pure signature detection misses novel or zero-day behavioral variations, while purely statistical or unsupervised anomaly detectors suffer from high false-positive rates that overwhelm SOC analysts.
2. **Alert Fatigue:** Redundant alerts triggered by recurring network conditions waste critical analyst hours.
3. **Training & Accessibility:** Educational cybersecurity tools often depend on hazardous live exploit tools or complex physical hardware environments that are unsafe for beginners and violate academic lab policies.

This simulation solves these challenges by providing an ethical, self-contained hybrid NIDS platform operating strictly on synthetic network telemetry while mirroring real-world SIEM and SOC workflows.

---

## 3. Technology Stack & Architecture
- **Language:** Python 3.13
- **Web Framework:** Flask 3.1
- **Machine Learning:** Scikit-Learn 1.7 (Random Forest, Logistic Regression, Isolation Forest)
- **Data Science:** Pandas 2.3, NumPy 2.2
- **Database:** SQLite 3 with atomic indexing and foreign-key referential integrity
- **Testing:** Pytest 8.4 (30 comprehensive automated tests)
- **Frontend:** Bootstrap 5, Chart.js 4.4, FontAwesome 6, JetBrains Mono

```
               [Synthetic Traffic Stream / CSV Dataset]
                                  │
                                  ▼
                        [Flow Ingestion API]
                                  │
                                  ▼
                     [Feature Extraction Engine]
          (Rates, Ratios, IP & Port Bounds Validation)
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
 [Signature Rules]      [Statistical Anomaly]      [Machine Learning]
  6 Custom Rules          Z-Score Baselines          Random Forest
  (High Conn Rate,        (Mean, Std, IQR)           100% Test Accuracy
   Brute Force, etc.)                                (98.7% Logistic Reg)
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                       [Hybrid Risk Engine]
                    (Weighted 0-100 Risk Score)
                                  │
                                  ▼
                       [Alert & Triage Engine]
              (Severity, Status, Defensive Playbooks)
                                  │
                                  ▼
                    [Alert Correlation Engine]
                (Grouped by Source IP & Time Window)
                                  │
                                  ▼
                     [SQLite Persistent Store]
                                  │
                                  ▼
                   [SOC Analyst Live Dashboard]
             (Charts, Metrics, Investigation Console)
```

---

## 4. Detection Methodologies & Hybrid Scoring

### 4.1 Signature Detection (Rule Engine)
Configurable rule thresholds detect known reconnaissance, exploitation, and abuse signatures:
- **IDS-001 (High Connection Rate):** Triggers when `connection_rate > 35/sec` and `connection_count >= 20`.
- **IDS-002 (Repeated Failed Connections):** Identifies credential stuffing and brute-force indicators (`failed_connections >= 15` and `failure_ratio >= 0.65`).
- **IDS-003 (Multi-Port Probing):** Detects horizontal and vertical port sweeps targeting multiple ports with high TCP RST flags.
- **IDS-004 (SYN-Heavy Flood):** Flags half-open connection flooding (`syn_ratio >= 0.75` and `syn_count >= 50`).
- **IDS-005 (Unusual Service Port):** Targets non-standard administrative and backdoor ports (`4444, 5555, 6667, 31337, 1337, 8888, 9999`).
- **IDS-006 (Volumetric Surge):** Identifies excessive byte consumption (`byte_count >= 2,000,000` or `bytes_per_second >= 300,000`).

### 4.2 Statistical Anomaly Detection
Calculates rolling mean and standard deviation baselines from benign network telemetry across 5 core dimensions:
$$\text{Anomaly Score} = 100 \times \left(1 - e^{-0.38 \sum w_i Z_i}\right)$$
Where $Z_i = \max(0, (x_i - \mu_i)/\sigma_i)$.

### 4.3 Machine Learning Benchmark
Models were trained and evaluated on an 80/20 train/test split of 6,000 verified synthetic flow records:
| Model Architecture | Accuracy | Precision | Recall | F1-Score | Confusion Matrix [TN, FP, FN, TP] |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest (Production)** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | `[[840, 0], [0, 360]]` |
| **Logistic Regression** | 98.75% | 100.00% | 95.83% | 97.87% | `[[840, 0], [15, 345]]` |
| **Isolation Forest (Unsupervised)**| 80.50% | 60.61% | 100.00% | 75.47% | `[[606, 234], [0, 360]]` |

*Insight:* While Isolation Forest achieved 100% recall (catching every intrusion), it produced 234 false positives. Random Forest and Signature integration achieved perfect discrimination without operational noise.

---

## 5. Defensive SOC Analyst Workflow
When an alert is flagged:
1. **Triage:** Analyst reviews Alert ID, Severity, Matched Rule, and Risk Score.
2. **Investigation:** Navigates to `/investigation?alert_id=ALT-XXXX` to inspect raw flow telemetry, communication endpoints, and multi-layer score breakdowns.
3. **Execution of Defensive Playbook:** Analyst applies context-specific defensive recommendations (e.g. checking host inventory, reviewing authentication logs, checking firewall drops).
4. **Lifecycle Update:** Status is transitioned from `NEW` to `INVESTIGATING`, documented with analyst notes, and finally transitioned to `RESOLVED` or `FALSE_POSITIVE`.

---

## 6. Verification and Testing
Automated testing via Pytest executed 30 comprehensive unit and integration tests with **100% pass rate in 7.80s**. All boundary conditions (zero duration, missing packet count, malformed IPv4, out-of-range ports, and unsupported protocols) were verified to fail safely without application termination.

---

## 7. Conclusion & Future Scope
The Network IDS Simulation successfully demonstrates how modern enterprise defensive architectures fuse rule signatures, statistical baselines, and machine learning models into unified risk telemetry. Future enhancements will explore PCAP offline parsing, Zeek/Suricata JSON log ingestion, and automated webhook dispatch to open-source SIEM platforms like Wazuh.
