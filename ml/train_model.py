"""
Machine Learning Model Training Pipeline
Trains Supervised (Random Forest, Logistic Regression) and Unsupervised (Isolation Forest)
classifiers on synthetic flow records. Computes true metrics and serializes models.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration_seconds",
    "bytes_per_second",
    "packets_per_second",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
]


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure all derived rate features exist in DataFrame."""
    working = df.copy()
    dur = working["duration_seconds"].replace(0, 0.001)
    if "bytes_per_second" not in working.columns:
        working["bytes_per_second"] = working["byte_count"] / dur
    if "packets_per_second" not in working.columns:
        working["packets_per_second"] = working["packet_count"] / dur
    return working


def train_models(data_path: str = "data/network_traffic.csv", models_dir: str = "models"):
    """Train and evaluate models, saving production artifacts."""
    os.makedirs(models_dir, exist_ok=True)

    print(f"[*] Loading training dataset from {data_path}...")
    df = pd.read_csv(data_path)
    df = prepare_features(df)

    # Encode label: NORMAL=0, SUSPICIOUS=1
    y = (df["label"] == "SUSPICIOUS").astype(int)
    X = df[FEATURE_COLUMNS].fillna(0)

    # 80/20 stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 1. Random Forest Classifier
    print("[*] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=1)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)

    rf_acc = float(accuracy_score(y_test, rf_preds))
    rf_prec = float(precision_score(y_test, rf_preds, zero_division=0))
    rf_rec = float(recall_score(y_test, rf_preds, zero_division=0))
    rf_f1 = float(f1_score(y_test, rf_preds, zero_division=0))
    rf_cm = confusion_matrix(y_test, rf_preds).tolist()

    print("\n" + "=" * 50)
    print("--- RANDOM FOREST EVALUATION RESULTS ---")
    print(f"Accuracy  : {rf_acc * 100:.2f}%")
    print(f"Precision : {rf_prec * 100:.2f}%")
    print(f"Recall    : {rf_rec * 100:.2f}%")
    print(f"F1 Score  : {rf_f1 * 100:.2f}%")
    print(f"Confusion Matrix (TN, FP, FN, TP):\n{rf_cm}")
    print("=" * 50)

    # 2. Logistic Regression
    print("\n[*] Training Logistic Regression Classifier...")
    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train_scaled, y_train)
    lr_preds = lr_model.predict(X_test_scaled)

    lr_acc = float(accuracy_score(y_test, lr_preds))
    lr_prec = float(precision_score(y_test, lr_preds, zero_division=0))
    lr_rec = float(recall_score(y_test, lr_preds, zero_division=0))
    lr_f1 = float(f1_score(y_test, lr_preds, zero_division=0))
    lr_cm = confusion_matrix(y_test, lr_preds).tolist()

    print("--- LOGISTIC REGRESSION EVALUATION RESULTS ---")
    print(f"Accuracy  : {lr_acc * 100:.2f}%")
    print(f"Precision : {lr_prec * 100:.2f}%")
    print(f"Recall    : {lr_rec * 100:.2f}%")
    print(f"F1 Score  : {lr_f1 * 100:.2f}%")
    print(f"Confusion Matrix:\n{lr_cm}")
    print("=" * 50)

    # 3. Isolation Forest (Unsupervised)
    print("\n[*] Training Isolation Forest (Unsupervised Anomaly Model)...")
    X_train_normal = X_train[y_train == 0]
    iso_model = IsolationForest(contamination=0.25, random_state=42, n_jobs=1)
    iso_model.fit(X_train_normal)
    iso_raw = iso_model.predict(X_test)
    iso_preds = np.where(iso_raw == -1, 1, 0)

    iso_acc = float(accuracy_score(y_test, iso_preds))
    iso_prec = float(precision_score(y_test, iso_preds, zero_division=0))
    iso_rec = float(recall_score(y_test, iso_preds, zero_division=0))
    iso_f1 = float(f1_score(y_test, iso_preds, zero_division=0))
    iso_cm = confusion_matrix(y_test, iso_preds).tolist()

    print("--- ISOLATION FOREST RESULTS ---")
    print(f"Accuracy  : {iso_acc * 100:.2f}%")
    print(f"Precision : {iso_prec * 100:.2f}%")
    print(f"Recall    : {iso_rec * 100:.2f}%")
    print(f"F1 Score  : {iso_f1 * 100:.2f}%")
    print(f"Confusion Matrix:\n{iso_cm}")
    print("=" * 50)

    # Save Random Forest model package
    model_payload = {
        "model": rf_model,
        "feature_names": FEATURE_COLUMNS,
        "metrics": {
            "random_forest": {"accuracy": rf_acc, "precision": rf_prec, "recall": rf_rec, "f1": rf_f1, "confusion_matrix": rf_cm},
            "logistic_regression": {"accuracy": lr_acc, "precision": lr_prec, "recall": lr_rec, "f1": lr_f1, "confusion_matrix": lr_cm},
            "isolation_forest": {"accuracy": iso_acc, "precision": iso_prec, "recall": iso_rec, "f1": iso_f1, "confusion_matrix": iso_cm},
        },
    }
    rf_save_path = os.path.join(models_dir, "random_forest_ids.joblib")
    joblib.dump(model_payload, rf_save_path)
    print(f"\n[+] Production model saved to {rf_save_path}")

    # Generate baseline statistics for AnomalyDetector
    from ids.anomaly_detector import AnomalyDetector
    detector = AnomalyDetector()
    baseline_stats_path = os.path.join(models_dir, "baseline_stats.json")
    detector.fit_baseline_from_df(df, save_path=baseline_stats_path)
    print(f"[+] Calibrated statistical baselines saved to {baseline_stats_path}")

    # Save evaluation summary JSON
    summary_path = os.path.join(models_dir, "model_evaluation_metrics.json")
    with open(summary_path, "w") as f:
        json.dump(model_payload["metrics"], f, indent=2)
    print(f"[+] Evaluation metrics summary saved to {summary_path}")

    return model_payload["metrics"]


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
    data_file = os.path.join(project_root, "data", "network_traffic.csv")
    models_dir = os.path.join(project_root, "models")
    train_models(data_file, models_dir)
