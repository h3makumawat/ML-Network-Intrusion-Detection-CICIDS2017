#!/usr/bin/env python3
"""
ML-Based Network Intrusion Detection System
IBM SkillsBuild Cyber Security Bootcamp 2026 | BharatCares (CSRBOX Group)

Dataset-based defensive cybersecurity demonstration.
This tool trains classifiers on labeled CSV network-flow records; it does not
capture live traffic, block attacks, or guarantee that traffic is safe.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

RANDOM_STATE = 42
LABEL_CANDIDATES = ("label", " Label", " Label ", " Label  ")
TARGET_NAME = "Label"
LOGGER = logging.getLogger("network_intrusion_detection")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names and make duplicate names unique."""
    out = df.copy()
    cleaned = [str(c).replace("\\ufeff", "").strip() for c in out.columns]
    seen: dict[str, int] = {}
    unique = []
    for name in cleaned:
        count = seen.get(name, 0)
        seen[name] = count + 1
        unique.append(name if count == 0 else f"{name}_{count}")
    out.columns = unique
    return out


def find_label_column(df: pd.DataFrame) -> str:
    """Find the label column without relying on capitalization or whitespace."""
    matches = [c for c in df.columns if str(c).strip().lower() == "label"]
    if not matches:
        raise ValueError(
            "Could not find a 'Label' target column. Check that the input CSV "
            "is a labeled CIC-IDS2017-style dataset."
        )
    return matches[0]


def normalize_labels(series: pd.Series) -> pd.Series:
    """Map BENIGN to 0 and known non-benign labels to 1; unknown blanks become NA."""
    values = series.astype("string").str.strip().str.upper()
    values = values.replace({"": pd.NA, "NAN": pd.NA, "NONE": pd.NA, "<NA>": pd.NA})
    mapped = pd.Series(pd.NA, index=series.index, dtype="Int64")
    mapped.loc[values == "BENIGN"] = 0
    mapped.loc[values.notna() & (values != "BENIGN")] = 1
    return mapped


def read_csv_files(paths: list[Path], sample_size: int | None = None) -> pd.DataFrame:
    """Read one or more CSV files; use deterministic sampling when requested."""
    frames = []
    for path in paths:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Dataset file not found: {path}")
        LOGGER.info("Reading dataset: %s", path)
        frame = pd.read_csv(path, low_memory=False)
        frame = clean_column_names(frame)
        if sample_size and len(frame) > sample_size:
            frame = frame.sample(n=sample_size, random_state=RANDOM_STATE)
        frames.append(frame)
    if not frames:
        raise ValueError("Provide at least one CSV dataset file.")
    # Concatenation preserves columns across files and fills absent columns with NaN.
    data = pd.concat(frames, ignore_index=True, sort=False)
    return clean_column_names(data)


def make_demo_data(rows: int = 800) -> pd.DataFrame:
    """Generate clearly synthetic data to verify the pipeline without a dataset."""
    rng = np.random.default_rng(RANDOM_STATE)
    malicious = rng.binomial(1, 0.35, size=rows)
    duration = rng.gamma(shape=2.0, scale=1.5, size=rows) + malicious * rng.uniform(0, 3, rows)
    packet_count = rng.poisson(lam=18 + malicious * 20, size=rows)
    byte_count = rng.lognormal(mean=7.0 + malicious * 0.9, sigma=0.8, size=rows)
    flow_rate = (packet_count / (duration + 0.1)) * (1 + malicious * 0.5)
    return pd.DataFrame({
        "Flow Duration": duration,
        "Total Fwd Packets": packet_count,
        "Total Length of Fwd Packets": byte_count,
        "Flow Packets/s": flow_rate,
        "Active Mean": rng.gamma(1.5, 10, rows),
        "Idle Mean": rng.gamma(2.0, 15, rows),
        "Label": np.where(malicious == 0, "BENIGN", "SYNTHETIC_ATTACK")
    })


def prepare_dataset(data: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, dict[str, Any]]:
    """Clean data and return numeric features, binary target, and preparation summary."""
    data = clean_column_names(data)
    label_col = find_label_column(data)
    target = normalize_labels(data[label_col])
    valid_target = target.notna()
    dropped_target_rows = int((~valid_target).sum())
    data = data.loc[valid_target].copy()
    target = target.loc[valid_target].astype(int)

    feature_frame = data.drop(columns=[label_col]).copy()
    # Convert every feature to numeric; nonnumeric values become missing.
    for col in feature_frame.columns:
        feature_frame[col] = pd.to_numeric(feature_frame[col], errors="coerce")
    feature_frame = feature_frame.replace([np.inf, -np.inf], np.nan)

    # Drop columns with no usable numeric values and exact duplicate columns.
    all_missing = [c for c in feature_frame.columns if feature_frame[c].notna().sum() == 0]
    if all_missing:
        feature_frame = feature_frame.drop(columns=all_missing)
    if feature_frame.empty:
        raise ValueError("No usable numeric feature columns remain after cleaning.")

    duplicate_mask = feature_frame.T.duplicated()
    duplicate_columns = list(feature_frame.columns[duplicate_mask])
    if duplicate_columns:
        feature_frame = feature_frame.drop(columns=duplicate_columns)

    # Remove constant features to reduce noise and simplify inference schema.
    constant_cols = [c for c in feature_frame.columns if feature_frame[c].nunique(dropna=True) <= 1]
    if constant_cols:
        feature_frame = feature_frame.drop(columns=constant_cols)
    if feature_frame.empty:
        raise ValueError("All feature columns were empty, duplicated, or constant.")

    summary = {
        "rows_retained": int(len(feature_frame)),
        "rows_dropped_due_to_missing_label": dropped_target_rows,
        "features_used": int(feature_frame.shape[1]),
        "feature_columns": list(feature_frame.columns),
        "class_counts": {
            "BENIGN": int((target == 0).sum()),
            "MALICIOUS": int((target == 1).sum())
        },
        "dropped_all_missing_columns": all_missing,
        "dropped_duplicate_columns": duplicate_columns,
        "dropped_constant_columns": constant_cols,
        "source_row_count_after_file_read": int(len(data) + dropped_target_rows)
    }
    return feature_frame.astype(float), target, summary


def save_eda(X: pd.DataFrame, y: pd.Series, out_dir: Path) -> None:
    """Save class distribution and feature correlation plots."""
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = pd.Series(
        {"BENIGN": int((y == 0).sum()), "MALICIOUS": int((y == 1).sum())}
    )
    plt.figure(figsize=(7, 5))
    counts.plot(kind="bar")
    plt.title("Network Flow Class Distribution")
    plt.xlabel("Class")
    plt.ylabel("Number of records")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_dir / "class_distribution.png", dpi=160)
    plt.close()

    # Correlation is calculated on at most 12 columns for a readable plot.
    corr_cols = list(X.columns[:12])
    if len(corr_cols) >= 2:
        corr = X[corr_cols].corr(numeric_only=True)
        plt.figure(figsize=(10, 8))
        sns.heatmap(corr, cmap="coolwarm", center=0, square=False)
        plt.title("Feature Correlation (first 12 usable features)")
        plt.tight_layout()
        plt.savefig(out_dir / "feature_correlation.png", dpi=160)
        plt.close()


def build_pipeline(model: Any) -> Pipeline:
    """Build preprocessing + estimator pipeline; fit imputation on training data only."""
    return Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", model),
    ])


def safe_metric_dict(y_true: pd.Series, y_pred: np.ndarray, y_score: np.ndarray | None) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_malicious": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_malicious": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_malicious": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positives": int(((np.asarray(y_true) == 0) & (y_pred == 1)).sum()),
        "false_negatives": int(((np.asarray(y_true) == 1) & (y_pred == 0)).sum()),
    }
    if y_score is not None and len(np.unique(y_true)) == 2:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
        except ValueError:
            metrics["roc_auc"] = None
    else:
        metrics["roc_auc"] = None
    return metrics


def train_project(data: pd.DataFrame, out_dir: Path, test_size: float = 0.2) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    X, y, summary = prepare_dataset(data)
    if len(y) < 10:
        raise ValueError("At least 10 labeled rows are recommended for a meaningful demo.")
    if y.nunique() < 2 or y.value_counts().min() < 2:
        raise ValueError("Training requires at least two classes with at least two rows per class.")

    save_eda(X, y, out_dir)
    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=RANDOM_STATE, stratify=stratify
    )

    models = {
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, class_weight="balanced", random_state=RANDOM_STATE
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=120, max_depth=18, min_samples_leaf=2,
            class_weight="balanced_subsample", n_jobs=-1, random_state=RANDOM_STATE
        ),
    }
    results: dict[str, Any] = {}
    fitted: dict[str, Pipeline] = {}
    predictions: dict[str, np.ndarray] = {}

    for name, estimator in models.items():
        pipeline = build_pipeline(estimator)
        pipeline.fit(X_train, y_train)
        pred = pipeline.predict(X_test)
        score = None
        if hasattr(pipeline, "predict_proba"):
            try:
                score = pipeline.predict_proba(X_test)[:, 1]
            except (ValueError, IndexError):
                score = None
        metrics = safe_metric_dict(y_test, pred, score)
        results[name] = metrics
        fitted[name] = pipeline
        predictions[name] = pred
        LOGGER.info("%s metrics: %s", name, json.dumps(metrics, indent=2))

    # Select by F1 for the malicious class; tie-break with recall.
    selected_name = max(
        results,
        key=lambda name: (results[name]["f1_malicious"], results[name]["recall_malicious"])
    )
    final_model = fitted[selected_name]
    final_pred = predictions[selected_name]
    final_score = None
    if hasattr(final_model, "predict_proba"):
        try:
            final_score = final_model.predict_proba(X_test)[:, 1]
        except (ValueError, IndexError):
            pass

    cm = confusion_matrix(y_test, final_pred, labels=[0, 1])
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["BENIGN", "MALICIOUS"],
        yticklabels=["BENIGN", "MALICIOUS"]
    )
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.title(f"Confusion Matrix — {selected_name}")
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrix.png", dpi=160)
    plt.close()

    comparison = pd.DataFrame(results).T
    comparison[["accuracy", "precision_malicious", "recall_malicious", "f1_malicious"]].plot(
        kind="bar", figsize=(10, 6)
    )
    plt.title("Model Performance Comparison")
    plt.ylabel("Score")
    plt.ylim(0, 1)
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_dir / "model_comparison.png", dpi=160)
    plt.close()

    report = classification_report(
        y_test, final_pred, labels=[0, 1], target_names=["BENIGN", "MALICIOUS"],
        zero_division=0
    )
    (out_dir / "classification_report.txt").write_text(report, encoding="utf-8")

    schema = {
        "project": "ML-Based Network Intrusion Detection System",
        "feature_columns": list(X.columns),
        "label_mapping": {"BENIGN": 0, "MALICIOUS": 1},
        "selected_model": selected_name,
        "random_state": RANDOM_STATE,
        "note": "Dataset-based model; not a live traffic sensor or prevention system."
    }
    joblib.dump(final_model, out_dir / "model.joblib")
    (out_dir / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")
    summary.update({
        "dataset_type": "synthetic_demo" if data.get("Label", pd.Series(dtype=str)).astype(str).str.contains("SYNTHETIC", case=False).any() else "user_provided_csv",
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "selected_model": selected_name,
        "model_metrics": results,
        "selected_model_confusion_matrix": cm.tolist(),
        "selected_model_classification_report": report,
        "random_state": RANDOM_STATE,
        "warning": "Metrics describe this particular dataset split and do not guarantee real-world detection performance."
    })
    (out_dir / "evaluation_metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "run_summary.json").write_text(json.dumps({
        "status": "success",
        "selected_model": selected_name,
        "output_files": [
            "model.joblib", "feature_schema.json", "evaluation_metrics.json",
            "classification_report.txt", "confusion_matrix.png",
            "class_distribution.png", "feature_correlation.png", "model_comparison.png"
        ]
    }, indent=2), encoding="utf-8")
    LOGGER.info("Training complete. Selected model: %s", selected_name)
    LOGGER.info("Artifacts saved to: %s", out_dir.resolve())


def predict_csv(input_path: Path, out_dir: Path, output_path: Path | None = None) -> None:
    model_path = out_dir / "model.joblib"
    schema_path = out_dir / "feature_schema.json"
    if not model_path.exists() or not schema_path.exists():
        raise FileNotFoundError(
            f"Model files were not found in {out_dir}. Run training first."
        )
    model = joblib.load(model_path)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    expected = schema["feature_columns"]
    raw = clean_column_names(pd.read_csv(input_path, low_memory=False))
    # Prediction files may include a Label column; it is never passed to the model.
    label_cols = [c for c in raw.columns if c.strip().lower() == "label"]
    if label_cols:
        raw = raw.drop(columns=label_cols)
    missing = [c for c in expected if c not in raw.columns]
    extra = [c for c in raw.columns if c not in expected]
    if missing:
        raise ValueError(
            "Prediction CSV is missing required feature columns: "
            + ", ".join(missing[:20])
            + ". Use the same feature schema as the training dataset."
        )
    X = raw[expected].copy()
    for col in expected:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    predicted = model.predict(X)
    probabilities = None
    if hasattr(model, "predict_proba"):
        try:
            probabilities = model.predict_proba(X)[:, 1]
        except (ValueError, IndexError):
            probabilities = None
    result = pd.DataFrame({
        "predicted_class": np.where(predicted == 1, "MALICIOUS", "BENIGN"),
        "malicious_probability": probabilities if probabilities is not None else np.nan,
        "prediction_note": "Model estimate only; not a guarantee of safety."
    })
    result_path = output_path or (out_dir / "predictions.csv")
    result.to_csv(result_path, index=False)
    LOGGER.info("Predictions saved to: %s", result_path.resolve())
    if extra:
        LOGGER.info("Ignored extra prediction columns: %s", ", ".join(extra[:20]))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train or use a dataset-based ML network intrusion detection model."
    )
    parser.add_argument(
        "--data", nargs="+", type=Path,
        help="One or more labeled CSV files for training."
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Use generated SYNTHETIC data to test the pipeline; not real dataset evidence."
    )
    parser.add_argument(
        "--sample-size", type=int, default=100000,
        help="Maximum rows sampled from each input CSV (default: 100000; use 0 for all rows)."
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("outputs"),
        help="Directory for model, metrics, plots, and predictions (default: outputs)."
    )
    parser.add_argument(
        "--predict", type=Path,
        help="Predict labels for a separate CSV using an already trained model."
    )
    parser.add_argument(
        "--prediction-output", type=Path,
        help="Optional output path for prediction CSV."
    )
    parser.add_argument(
        "--test-size", type=float, default=0.2,
        help="Fraction held out for testing (default: 0.2)."
    )
    return parser.parse_args()


def main() -> int:
    configure_logging()
    args = parse_args()
    try:
        if not 0.1 <= args.test_size <= 0.5:
            raise ValueError("--test-size must be between 0.1 and 0.5.")
        if args.predict:
            predict_csv(args.predict, args.output_dir, args.prediction_output)
            return 0
        if args.demo and args.data:
            raise ValueError("Choose either --demo or --data, not both.")
        if args.demo:
            LOGGER.warning(
                "DEMO MODE: using synthetic records. Results do not represent CIC-IDS2017 performance."
            )
            data = make_demo_data()
        elif args.data:
            sample_size = None if args.sample_size == 0 else args.sample_size
            if sample_size is not None and sample_size < 10:
                raise ValueError("--sample-size must be 0 or at least 10.")
            data = read_csv_files(args.data, sample_size=sample_size)
        else:
            raise ValueError("Provide --data path/to/file.csv or use --demo.")
        train_project(data, args.output_dir, test_size=args.test_size)
        return 0
    except Exception as exc:
        LOGGER.error("%s", exc)
        LOGGER.info("Run with --help to see command-line options.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
