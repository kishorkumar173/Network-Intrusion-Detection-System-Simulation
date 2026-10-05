"""
Model Evaluation and Metrics Reporting
Loads saved metrics and prints a comprehensive comparison report.
"""

import json
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def print_evaluation_report(metrics_path: str = "models/model_evaluation_metrics.json"):
    """Format and display model benchmark report."""
    if not os.path.exists(metrics_path):
        print(f"[!] Error: Metrics file not found at {metrics_path}. Run ml/train_model.py first.")
        return

    with open(metrics_path, "r") as f:
        metrics = json.load(f)

    print("=" * 70)
    print("      NETWORK IDS MACHINE LEARNING MODEL BENCHMARK REPORT      ")
    print("=" * 70)
    print(f"{'Model Name':<24} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 70)

    for model_name, m in metrics.items():
        clean_name = model_name.replace("_", " ").title()
        print(
            f"{clean_name:<24} | "
            f"{m['accuracy']*100:>7.2f}%  | "
            f"{m['precision']*100:>7.2f}%  | "
            f"{m['recall']*100:>7.2f}%  | "
            f"{m['f1']*100:>7.2f}%"
        )

    print("=" * 70)
    print("\nCONFUSION MATRICES:")
    for model_name, m in metrics.items():
        clean_name = model_name.replace("_", " ").title()
        cm = m.get("confusion_matrix", [[0, 0], [0, 0]])
        print(f"\n[{clean_name}]")
        print(f"  True Negative  (TN): {cm[0][0]:<5} | False Positive (FP): {cm[0][1]:<5}")
        print(f"  False Negative (FN): {cm[1][0]:<5} | True Positive  (TP): {cm[1][1]:<5}")


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
    report_file = os.path.join(project_root, "models", "model_evaluation_metrics.json")
    print_evaluation_report(report_file)
