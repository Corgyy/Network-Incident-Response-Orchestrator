import argparse
import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


FEATURE_COLUMNS = [
    "suspicious_command_count",
    "executable_evidence_count",
    "network_connection_count",
    "hash_evidence_count",
    "http_count",
    "dns_count",
    "smb_count",
    "unique_dest_ip_count",
    "external_connection_count",
    "bytes_out",
    "bytes_in",
    "has_webroot_executable",
    "has_cmd_execution",
    "has_powershell",
    "has_encoded_command",
]


def train_model(training_file, model_file, report_file, contamination):
    if not os.path.exists(training_file):
        raise FileNotFoundError(f"Training file not found: {training_file}")

    df = pd.read_csv(training_file)

    missing_columns = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing feature columns in training data: {missing_columns}")

    X = df[FEATURE_COLUMNS].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42
    )

    model.fit(X_scaled)

    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)

    anomaly_count = int((predictions == -1).sum())
    normal_count = int((predictions == 1).sum())

    os.makedirs(os.path.dirname(model_file), exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "feature_columns": FEATURE_COLUMNS,
            "model_type": "IsolationForest",
            "contamination": contamination,
        },
        model_file
    )

    report = {
        "agent": "ml_classifier",
        "model": "IsolationForest",
        "training_file": training_file,
        "model_file": model_file,
        "total_training_rows": len(df),
        "feature_columns": FEATURE_COLUMNS,
        "contamination": contamination,
        "normal_count": normal_count,
        "anomaly_count": anomaly_count,
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "score_mean": float(scores.mean()),
        "labels_in_training_file": sorted(df["label"].unique().tolist()) if "label" in df.columns else [],
        "note": (
            "IsolationForest is used for anomaly detection on incident feature vectors. "
            "It detects whether an incident looks normal or anomalous. "
            "The final incident type will be assigned later by rule-based labeling based on evidence."
        )
    }

    os.makedirs(os.path.dirname(report_file), exist_ok=True)

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("IsolationForest training completed.")
    print(f"Training file: {training_file}")
    print(f"Model saved to: {model_file}")
    print(f"Training report saved to: {report_file}")
    print(f"Normal samples: {normal_count}")
    print(f"Anomaly samples: {anomaly_count}")


def main():
    parser = argparse.ArgumentParser(description="Train IsolationForest incident anomaly detector.")

    parser.add_argument(
        "--training-file",
        default="./.pi/data/training_incidents.csv",
        help="Path to training CSV file."
    )

    parser.add_argument(
        "--model-file",
        default="./.pi/models/isolation_forest_model.pkl",
        help="Path to save trained IsolationForest model."
    )

    parser.add_argument(
        "--report-file",
        default="./reports/ml_training_report.json",
        help="Path to save training report."
    )

    parser.add_argument(
        "--contamination",
        type=float,
        default=0.25,
        help="Expected anomaly ratio in training data."
    )

    args = parser.parse_args()

    train_model(
        training_file=args.training_file,
        model_file=args.model_file,
        report_file=args.report_file,
        contamination=args.contamination
    )


if __name__ == "__main__":
    main()