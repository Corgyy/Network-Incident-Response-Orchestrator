import argparse
import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


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


def train_model(training_file, model_file, report_file):
    if not os.path.exists(training_file):
        raise FileNotFoundError(f"Training file not found: {training_file}")

    df = pd.read_csv(training_file)

    missing_columns = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing feature columns in training data: {missing_columns}")

    if "label" not in df.columns:
        raise ValueError("Training data must contain a 'label' column.")

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"].fillna("Unknown")

    label_counts = y.value_counts()
    can_stratify = label_counts.min() >= 2

    if can_stratify:
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y,
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.25,
            random_state=42,
        )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    labels = sorted(y.unique().tolist())

    feature_importance = [
        {
            "feature": feature,
            "importance": round(float(importance), 6),
        }
        for feature, importance in zip(FEATURE_COLUMNS, model.feature_importances_)
    ]

    feature_importance = sorted(
        feature_importance,
        key=lambda x: x["importance"],
        reverse=True,
    )

    os.makedirs(os.path.dirname(os.path.abspath(model_file)), exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "model_type": "RandomForestClassifier",
            "labels": labels,
        },
        model_file,
    )

    report = {
        "agent": "ml_classifier",
        "model": "RandomForestClassifier",
        "training_file": training_file,
        "model_file": model_file,
        "total_training_rows": int(len(df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "feature_columns": FEATURE_COLUMNS,
        "labels": labels,
        "label_distribution": {
            label: int(count) for label, count in y.value_counts().items()
        },
        "accuracy": round(float(accuracy), 4),
        "classification_report": classification_report(
            y_test,
            y_pred,
            zero_division=0,
            output_dict=True,
        ),
        "feature_importance": feature_importance,
        "note": (
            "RandomForestClassifier is used to classify incident type from "
            "feature vectors extracted by Log Collector and Network Analyzer. "
            "The input alert is already suspicious; ML is used to classify what "
            "type of incident it is, not to detect whether an alert exists."
        ),
    }

    os.makedirs(os.path.dirname(os.path.abspath(report_file)), exist_ok=True)

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("RandomForest training completed.")
    print(f"Training file: {training_file}")
    print(f"Model saved to: {model_file}")
    print(f"Training report saved to: {report_file}")
    print(f"Accuracy: {accuracy:.4f}")
    print("Labels:")
    for label in labels:
        print(f"  - {label}")


def main():
    parser = argparse.ArgumentParser(
        description="Train RandomForest incident type classifier."
    )

    parser.add_argument(
        "--training-file",
        default="./data/training_incidents.csv",
        help="Path to training CSV file.",
    )

    parser.add_argument(
        "--model-file",
        default="./.pi/models/random_forest_incident_classifier.pkl",
        help="Path to save trained RandomForest model.",
    )

    parser.add_argument(
        "--report-file",
        default="./reports/ml_training_report.json",
        help="Path to save training report.",
    )

    args = parser.parse_args()

    train_model(
        training_file=args.training_file,
        model_file=args.model_file,
        report_file=args.report_file,
    )


if __name__ == "__main__":
    main()