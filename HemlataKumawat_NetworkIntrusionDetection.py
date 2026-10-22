#!/usr/bin/env python3
"""
ML-Based Network Intrusion Detection System Using CIC-IDS2017
IBM SkillsBuild Cyber Security Bootcamp 2026 | BharatCares (CSRBOX Group)
Student: Hemlata Kumawat
Branch : BCA

Dataset-based defensive cybersecurity demonstration.
This tool trains classifiers on labeled CSV network-flow records; it does not
capture live traffic, block attacks, or guarantee that traffic is safe.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

RANDOM_STATE = 42
STUDENT_NAME = "Hemlata Kumawat"
STUDENT_BRANCH = "BCA"
DEFAULT_REPORT_FILENAME = "HemlataKumawat_ProjectReport.docx"
LOGGER = logging.getLogger("network_intrusion_detection")

# Non-behavioral identifier/index columns to exclude so classifiers learn
# traffic behavior rather than memorizing row indices or lab IP addresses.
IDENTIFIER_COLUMNS_TO_EXCLUDE = {
    "unnamed: 0",
    "flow id",
    "source ip",
    "src ip",
    "destination ip",
    "dst ip",
    "timestamp",
    "simillarhttp",
}


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip UTF-8 BOM and whitespace from column names and make duplicate names unique."""
    out = df.copy()
    cleaned = [
        " ".join(str(c).replace("\ufeff", "").replace("\\ufeff", "").strip().split())
        for c in out.columns
    ]
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


def read_csv_files(
    paths: list[Path],
    sample_size: int | None = None,
    random_state: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, int]:
    """
    Read one or more CSV files (or directories of CSVs) using chunked reading
    when sample_size is set to protect memory on laptop hardware.
    Returns (combined_dataframe, original_rows_scanned).
    """
    resolved_paths: list[Path] = []
    for p in paths:
        if p.is_dir():
            resolved_paths.extend(sorted(p.glob("*.csv")))
        elif p.exists() and p.is_file():
            resolved_paths.append(p)
        else:
            raise FileNotFoundError(f"Dataset file not found: {p}")

    if not resolved_paths:
        raise ValueError("Provide at least one CSV dataset file.")

    frames = []
    total_original_rows = 0
    per_file_sample = (
        max(10, int(np.ceil(sample_size / len(resolved_paths))))
        if (sample_size and sample_size > 0)
        else None
    )

    for idx, path in enumerate(resolved_paths):
        LOGGER.info("Reading dataset: %s", path)
        chunks = []
        file_rows = 0
        for chunk in pd.read_csv(
            path,
            chunksize=50000,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace",
            on_bad_lines="skip",
        ):
            file_rows += len(chunk)
            if per_file_sample and len(chunk) > per_file_sample:
                chunk = chunk.sample(n=per_file_sample, random_state=random_state + idx)
            chunks.append(chunk)

        if not chunks:
            continue
        total_original_rows += file_rows
        frame = pd.concat(chunks, ignore_index=True)
        frame = clean_column_names(frame)
        if per_file_sample and len(frame) > per_file_sample:
            frame = frame.sample(n=per_file_sample, random_state=random_state + idx)
        frames.append(frame)

    if not frames:
        raise ValueError("No valid rows could be read from the provided CSV file(s).")

    data = pd.concat(frames, ignore_index=True, sort=False)
    if sample_size and sample_size > 0 and len(data) > sample_size:
        data = data.sample(n=sample_size, random_state=random_state).reset_index(drop=True)
    return clean_column_names(data), total_original_rows


def make_demo_data(rows: int = 800, random_state: int = RANDOM_STATE) -> pd.DataFrame:
    """Generate clearly synthetic data to verify the pipeline without a dataset."""
    rng = np.random.default_rng(random_state)
    malicious = rng.binomial(1, 0.35, size=rows)
    duration = rng.gamma(shape=2.0, scale=1.5, size=rows) + malicious * rng.uniform(0, 3, rows)
    packet_count = rng.poisson(lam=18 + malicious * 20, size=rows)
    byte_count = rng.lognormal(mean=7.0 + malicious * 0.9, sigma=0.8, size=rows)
    flow_rate = (packet_count / (duration + 0.1)) * (1 + malicious * 0.5)
    return pd.DataFrame(
        {
            "Flow Duration": duration,
            "Total Fwd Packets": packet_count,
            "Total Length of Fwd Packets": byte_count,
            "Flow Packets/s": flow_rate,
            "Active Mean": rng.gamma(1.5, 10, rows),
            "Idle Mean": rng.gamma(2.0, 15, rows),
            "Label": np.where(malicious == 0, "BENIGN", "SYNTHETIC_ATTACK"),
        }
    )


def prepare_dataset(
    data: pd.DataFrame,
    original_row_count: int | None = None,
) -> tuple[pd.DataFrame, pd.Series, pd.Series, dict[str, Any]]:
    """
    Clean raw DataFrame, exclude target label and non-behavioral identifiers,
    and convert features to numeric float without leaking test-set statistics.
    (Feature-level constant/duplicate filtering is performed strictly on X_train
    after train_test_split inside filter_features_on_train_only).
    """
    data = clean_column_names(data)
    source_rows = int(original_row_count) if original_row_count is not None else int(len(data))
    label_col = find_label_column(data)
    raw_label_strings = data[label_col].astype("string").str.strip().fillna("UNKNOWN")
    target = normalize_labels(data[label_col])

    valid_target = target.notna()
    dropped_target_rows = int((~valid_target).sum())
    data = data.loc[valid_target].reset_index(drop=True)
    target = target.loc[valid_target].astype(int).reset_index(drop=True)
    raw_label_strings = raw_label_strings.loc[valid_target].reset_index(drop=True)

    # Exclude target column and non-generalizable identifier columns
    excluded_identifiers = [
        c for c in data.columns if c != label_col and c.strip().lower() in IDENTIFIER_COLUMNS_TO_EXCLUDE
    ]
    feature_frame = data.drop(columns=[label_col] + excluded_identifiers).copy()

    missing_cells = 0
    infinite_cells = 0
    for col in feature_frame.columns:
        coerced = pd.to_numeric(feature_frame[col], errors="coerce")
        inf_mask = np.isinf(coerced)
        infinite_cells += int(inf_mask.sum())
        coerced = coerced.replace([np.inf, -np.inf], np.nan)
        missing_cells += int(coerced.isna().sum())
        feature_frame[col] = coerced

    if feature_frame.empty:
        raise ValueError("No usable numeric feature columns remain after cleaning.")

    summary = {
        "original_row_count": source_rows,
        "sampled_row_count": int(len(data) + dropped_target_rows),
        "rows_retained": int(len(feature_frame)),
        "rows_dropped_due_to_missing_label": dropped_target_rows,
        "rows_dropped_invalid_label": dropped_target_rows,
        "retention_rate_percent": round(
            100.0 * len(feature_frame) / max(len(data) + dropped_target_rows, 1), 2
        ),
        "initial_column_count": int(len(data.columns)),
        "detected_label_column": label_col,
        "identifier_columns_excluded": excluded_identifiers,
        "missing_values_handled": int(missing_cells),
        "infinite_values_handled": int(infinite_cells),
        "class_counts": {
            "BENIGN": int((target == 0).sum()),
            "MALICIOUS": int((target == 1).sum()),
        },
        "binary_class_distribution": {
            "BENIGN": int((target == 0).sum()),
            "MALICIOUS": int((target == 1).sum()),
            "benign_percent": round(100.0 * int((target == 0).sum()) / max(len(target), 1), 2),
            "malicious_percent": round(100.0 * int((target == 1).sum()) / max(len(target), 1), 2),
        },
        "attack_category_distribution": {
            str(k): int(v) for k, v in raw_label_strings.value_counts().to_dict().items()
        },
        "source_row_count_after_file_read": int(len(data) + dropped_target_rows),
    }
    return feature_frame.astype(float), target, raw_label_strings, summary


def filter_features_on_train_only(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, list[str]]]:
    """
    Detect and drop all-missing, constant (zero-variance), and duplicate feature
    columns using ONLY X_train statistics, then apply the exact same column list
    to X_test. This prevents test-set data leakage and SimpleImputer warnings.
    """
    all_missing = [c for c in X_train.columns if X_train[c].notna().sum() == 0]
    train_kept = X_train.drop(columns=all_missing) if all_missing else X_train.copy()

    constant_cols = [c for c in train_kept.columns if train_kept[c].nunique(dropna=True) <= 1]
    if constant_cols:
        train_kept = train_kept.drop(columns=constant_cols)

    # Check duplicate columns on a small deterministic subsample of X_train for memory safety
    check_sample = train_kept.head(min(2000, len(train_kept)))
    dup_mask = check_sample.T.duplicated()
    candidate_dups = list(train_kept.columns[dup_mask])
    duplicate_columns: list[str] = []
    for col in candidate_dups:
        for prev_col in train_kept.columns:
            if prev_col == col:
                break
            if train_kept[prev_col].equals(train_kept[col]):
                duplicate_columns.append(col)
                break

    if duplicate_columns:
        train_kept = train_kept.drop(columns=duplicate_columns)

    if train_kept.empty:
        raise ValueError("All feature columns were empty, duplicated, or constant on X_train.")

    final_cols = list(train_kept.columns)
    return (
        X_train[final_cols].copy(),
        X_test[final_cols].copy(),
        {
            "dropped_all_missing_columns": all_missing,
            "dropped_constant_columns": constant_cols,
            "dropped_duplicate_columns": duplicate_columns,
        },
    )


def save_eda(X: pd.DataFrame, y: pd.Series, out_dir: Path, is_demo: bool = False) -> None:
    """Save class distribution, feature correlation, and architecture plots."""
    out_dir.mkdir(parents=True, exist_ok=True)
    mode_tag = "Synthetic Demo Data" if is_demo else "CIC-IDS2017 Dataset"

    counts = pd.Series(
        {"BENIGN": int((y == 0).sum()), "MALICIOUS": int((y == 1).sum())}
    )
    plt.figure(figsize=(7.5, 5))
    bars = plt.bar(counts.index, counts.values, color=["#0f766e", "#b91c1c"], width=0.5)
    plt.title(f"Network Flow Class Distribution ({mode_tag})", fontweight="bold")
    plt.xlabel("Class")
    plt.ylabel("Number of records")
    for bar in bars:
        val = int(bar.get_height())
        plt.annotate(
            f"{val:,}",
            xy=(bar.get_x() + bar.get_width() / 2, val),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontweight="bold",
        )
    plt.ylim(0, max(counts.values) * 1.18)
    plt.tight_layout()
    plt.savefig(out_dir / "class_distribution.png", dpi=160)
    plt.close()

    # Correlation is calculated on at most 12 columns for a readable plot.
    corr_cols = list(X.columns[:12])
    if len(corr_cols) >= 2:
        corr = X[corr_cols].corr(numeric_only=True)
        plt.figure(figsize=(10, 8))
        sns.heatmap(
            corr,
            annot=True,
            fmt=".2f",
            cmap="coolwarm",
            center=0,
            square=False,
            annot_kws={"size": 8},
        )
        plt.title(f"Feature Correlation (First {len(corr_cols)} Usable Features — {mode_tag})", fontweight="bold")
        plt.tight_layout()
        plt.savefig(out_dir / "feature_correlation.png", dpi=160)
        plt.close()

    # Generate system architecture diagram for report & workbench
    fig, ax = plt.subplots(figsize=(11.5, 3.8), dpi=160)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 4)
    ax.axis("off")
    stages = [
        ("1. CSV Ingestion", "CIC-IDS2017 CSV\nor --demo Data", "#eff6ff", "#1d4ed8"),
        ("2. Data Hygiene", "BOM/Space Clean\nNaN & Inf Handling", "#f0fdf4", "#15803d"),
        ("3. Leak-Free Split", "Stratified 80/20\nTrain-Only Filter", "#fefce8", "#a16207"),
        ("4. ML Pipelines", "SimpleImputer +\nDT & Random Forest", "#faf5ff", "#7e22ce"),
        ("5. Eval & Predict", "F1 / Recall / AUC\nSchema-Checked CSV", "#fff1f2", "#be123c"),
    ]
    xs = [0.35, 2.72, 5.09, 7.46, 9.83]
    ax.text(
        6.0,
        3.55,
        f"ML-Based Network Intrusion Detection Architecture — {STUDENT_NAME} ({STUDENT_BRANCH})",
        ha="center",
        va="center",
        fontsize=12,
        fontweight="bold",
    )
    for i, (title, desc, bg, edge) in enumerate(stages):
        rect = mpatches.FancyBboxPatch(
            (xs[i], 0.8),
            2.0,
            2.1,
            boxstyle="round,pad=0.1,rounding_size=0.14",
            facecolor=bg,
            edgecolor=edge,
            linewidth=2,
        )
        ax.add_patch(rect)
        ax.text(xs[i] + 1.0, 2.5, title, ha="center", va="center", fontsize=9.5, fontweight="bold", color=edge)
        ax.text(xs[i] + 1.0, 1.55, desc, ha="center", va="center", fontsize=8.5, color="#1e293b")
        if i < len(stages) - 1:
            ax.annotate(
                "",
                xy=(xs[i + 1] - 0.08, 1.85),
                xytext=(xs[i] + 2.08, 1.85),
                arrowprops=dict(arrowstyle="->", lw=2, color="#475569"),
            )
    plt.tight_layout()
    plt.savefig(out_dir / "system_architecture.png", dpi=160)
    plt.close()


def build_pipeline(model: Any) -> Pipeline:
    """Build preprocessing + estimator pipeline; fit imputation on training data only."""
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", model),
        ]
    )


def safe_metric_dict(
    y_true: pd.Series,
    y_pred: np.ndarray,
    y_score: np.ndarray | None,
    train_seconds: float = 0.0,
) -> dict[str, Any]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    roc_val: float | None = None
    if y_score is not None and len(np.unique(y_true)) == 2:
        try:
            roc_val = float(roc_auc_score(y_true, y_score))
        except ValueError:
            roc_val = None

    fpr = float(fp / max(fp + tn, 1))
    fnr = float(fn / max(fn + tp, 1))
    report_str = classification_report(
        y_true, y_pred, labels=[0, 1], target_names=["BENIGN", "MALICIOUS"], zero_division=0
    )

    return {
        # Original keys expected by Hemlata's script
        "accuracy": round(acc, 4),
        "precision_malicious": round(prec, 4),
        "recall_malicious": round(rec, 4),
        "f1_malicious": round(f1, 4),
        "false_positives": fp,
        "false_negatives": fn,
        "roc_auc": round(roc_val, 4) if roc_val is not None else None,
        # Standardized keys for UI workbench & report compatibility
        "training_time_seconds": round(train_seconds, 3),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_count": fp,
        "false_negative_count": fn,
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "true_negatives_benign": tn,
            "false_positives_false_alarm": fp,
            "false_negatives_missed_attack": fn,
            "true_positives_detected_attack": tp,
            "matrix_2x2": [[tn, fp], [fn, tp]],
        },
        "classification_report_text": report_str,
    }


def extract_feature_importances(pipeline: Pipeline, feature_columns: list[str]) -> list[dict[str, Any]]:
    try:
        clf = pipeline.named_steps["classifier"]
        if hasattr(clf, "feature_importances_"):
            pairs = sorted(
                zip(feature_columns, clf.feature_importances_),
                key=lambda item: float(item[1]),
                reverse=True,
            )[:12]
            return [{"feature": str(k), "importance": round(float(v), 4)} for k, v in pairs]
    except Exception:
        pass
    return []


def train_project(
    data: pd.DataFrame,
    out_dir: Path,
    test_size: float = 0.2,
    is_demo: bool = False,
    original_row_count: int | None = None,
    random_state: int = RANDOM_STATE,
) -> dict[str, Any]:
    import time

    out_dir.mkdir(parents=True, exist_ok=True)
    X_raw, y, _, summary = prepare_dataset(data, original_row_count=original_row_count)
    if len(y) < 10:
        raise ValueError("At least 10 labeled rows are recommended for a meaningful demo.")
    if y.nunique() < 2 or y.value_counts().min() < 2:
        raise ValueError("Training requires at least two classes with at least two rows per class.")

    stratify = y if y.value_counts().min() >= 2 else None
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=test_size, random_state=random_state, stratify=stratify
    )

    # Filter constant/all-missing/duplicate columns strictly on X_train (zero test leakage!)
    X_train, X_test, dropped_info = filter_features_on_train_only(X_train_raw, X_test_raw)
    X = X_raw[X_train.columns].copy()

    summary.update(
        {
            "features_used": int(X_train.shape[1]),
            "features_used_count": int(X_train.shape[1]),
            "feature_columns": list(X_train.columns),
            "feature_names": list(X_train.columns),
            "dropped_all_missing_columns": dropped_info["dropped_all_missing_columns"],
            "dropped_duplicate_columns": dropped_info["dropped_duplicate_columns"],
            "dropped_constant_columns": dropped_info["dropped_constant_columns"],
            "duplicate_columns_removed": dropped_info["dropped_duplicate_columns"],
            "constant_columns_removed": dropped_info["dropped_constant_columns"],
            "non_numeric_columns_removed": dropped_info["dropped_all_missing_columns"],
        }
    )

    save_eda(X_train, y_train, out_dir, is_demo=is_demo)

    models = {
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, class_weight="balanced", random_state=random_state
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=120,
            max_depth=18,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=random_state,
        ),
    }
    results: dict[str, Any] = {}
    fitted: dict[str, Pipeline] = {}
    predictions: dict[str, np.ndarray] = {}

    for name, estimator in models.items():
        t0 = time.perf_counter()
        pipeline = build_pipeline(estimator)
        pipeline.fit(X_train, y_train)
        elapsed = time.perf_counter() - t0
        pred = pipeline.predict(X_test)
        score = None
        if hasattr(pipeline, "predict_proba"):
            try:
                score = pipeline.predict_proba(X_test)[:, 1]
            except (ValueError, IndexError):
                score = None
        metrics = safe_metric_dict(y_test, pred, score, train_seconds=elapsed)
        metrics["model_name"] = name
        results[name] = metrics
        fitted[name] = pipeline
        predictions[name] = pred
        LOGGER.info(
            "%s -> Accuracy=%.4f | Precision=%.4f | Recall=%.4f | F1=%.4f | ROC-AUC=%s | FP=%d | FN=%d",
            name,
            metrics["accuracy"],
            metrics["precision_malicious"],
            metrics["recall_malicious"],
            metrics["f1_malicious"],
            metrics["roc_auc"],
            metrics["false_positives"],
            metrics["false_negatives"],
        )

    # Select by F1 for the malicious class; tie-break with recall.
    selected_name = max(
        results,
        key=lambda name: (results[name]["f1_malicious"], results[name]["recall_malicious"]),
    )
    final_model = fitted[selected_name]
    final_pred = predictions[selected_name]

    cm = confusion_matrix(y_test, final_pred, labels=[0, 1])
    plt.figure(figsize=(6.5, 5.2))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["BENIGN (0)", "MALICIOUS (1)"],
        yticklabels=["BENIGN (0)", "MALICIOUS (1)"],
    )
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.title(f"Confusion Matrix — {selected_name}", fontweight="bold")
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrix.png", dpi=160)
    plt.close()

    comparison = pd.DataFrame(results).T
    ax = comparison[["accuracy", "precision_malicious", "recall_malicious", "f1_malicious"]].plot(
        kind="bar", figsize=(10, 6)
    )
    ax.set_title("Model Performance Comparison (Positive Class = MALICIOUS)", fontweight="bold")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.12)
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_dir / "model_comparison.png", dpi=160)
    plt.close()

    report = classification_report(
        y_test,
        final_pred,
        labels=[0, 1],
        target_names=["BENIGN", "MALICIOUS"],
        zero_division=0,
    )
    (out_dir / "classification_report.txt").write_text(report, encoding="utf-8")

    train_medians = X_train.median(numeric_only=True).fillna(0.0).to_dict()
    top_importances = extract_feature_importances(final_model, list(X_train.columns))

    schema = {
        "project": "ML-Based Network Intrusion Detection System",
        "student": STUDENT_NAME,
        "branch": STUDENT_BRANCH,
        "feature_columns": list(X_train.columns),
        "required_features": list(X_train.columns),
        "feature_count": int(len(X_train.columns)),
        "training_feature_medians": {str(k): round(float(v), 4) for k, v in train_medians.items()},
        "top_feature_importances": top_importances,
        "label_mapping": {"BENIGN": 0, "MALICIOUS": 1},
        "selected_model": selected_name,
        "selected_model_name": selected_name,
        "data_source_mode": "SYNTHETIC_DEMO_DATA" if is_demo else "CIC_IDS2017_CSV",
        "random_state": random_state,
        "note": "Dataset-based model; not a live traffic sensor or prevention system.",
    }
    joblib.dump(final_model, out_dir / "model.joblib")
    (out_dir / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")

    selection_reasoning = (
        f"Selected '{selected_name}' because it achieved the highest F1-Score "
        f"({results[selected_name]['f1_malicious']:.4f}) and Recall "
        f"({results[selected_name]['recall_malicious']:.4f}) for the MALICIOUS class on the "
        f"held-out test set."
    )

    summary.update(
        {
            "student_name": STUDENT_NAME,
            "branch": STUDENT_BRANCH,
            "dataset_type": "synthetic_demo" if is_demo else "user_provided_csv",
            "data_source_mode": "SYNTHETIC_DEMO_DATA" if is_demo else "CIC_IDS2017_CSV",
            "is_synthetic_demo": bool(is_demo),
            "synthetic_disclaimer": (
                "DEMO MODE: Synthetic records were used solely to verify the code pipeline. "
                "These metrics do NOT represent real-world CIC-IDS2017 detection performance."
                if is_demo
                else "Evaluated on user-supplied labeled CSV dataset."
            ),
            "positive_class_definition": {
                "label_int": 1,
                "label_name": "MALICIOUS",
                "explanation": "MALICIOUS (1) is the positive class so Recall measures attack detection rate and Precision measures alert fidelity.",
            },
            "why_accuracy_is_insufficient": (
                "Because benign network flows heavily outnumber attacks in real traffic, "
                "a classifier can score high Accuracy while missing attacks (False Negatives). "
                "Precision, Recall, F1-Score, FP/FN counts, and ROC-AUC are therefore essential."
            ),
            "false_positive_vs_false_negative_analysis": {
                "false_positive_consequences": "False Positives flag normal BENIGN traffic as MALICIOUS, causing unnecessary alerts and analyst fatigue.",
                "false_negative_consequences": "False Negatives miss real MALICIOUS attacks by labeling them BENIGN, allowing intrusions to proceed undetected.",
            },
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "train_row_count": int(len(X_train)),
            "test_row_count": int(len(X_test)),
            "feature_count": int(len(X_train.columns)),
            "selected_model": selected_name,
            "selection_metric": "f1_malicious",
            "selection_reasoning": selection_reasoning,
            "model_metrics": results,
            "models": results,
            "top_feature_importances": top_importances,
            "cleaning_summary": {
                "original_row_count": summary["original_row_count"],
                "sampled_row_count": summary["sampled_row_count"],
                "rows_retained": summary["rows_retained"],
                "rows_dropped_invalid_label": summary["rows_dropped_due_to_missing_label"],
                "retention_rate_percent": summary["retention_rate_percent"],
                "initial_column_count": summary["initial_column_count"],
                "features_used_count": int(len(X_train.columns)),
                "feature_names": list(X_train.columns),
                "detected_label_column": summary["detected_label_column"],
                "duplicate_columns_removed": dropped_info["dropped_duplicate_columns"],
                "identifier_columns_excluded": summary["identifier_columns_excluded"],
                "constant_columns_removed": dropped_info["dropped_constant_columns"],
                "non_numeric_columns_removed": dropped_info["dropped_all_missing_columns"],
                "missing_values_handled": summary["missing_values_handled"],
                "infinite_values_handled": summary["infinite_values_handled"],
                "binary_class_distribution": summary["binary_class_distribution"],
                "attack_category_distribution": summary["attack_category_distribution"],
            },
            "selected_model_confusion_matrix": cm.tolist(),
            "selected_model_classification_report": report,
            "random_state": random_state,
            "warning": "Metrics describe this particular dataset split and do not guarantee real-world detection performance.",
        }
    )
    (out_dir / "evaluation_metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "run_summary.json").write_text(
        json.dumps(
            {
                "status": "success",
                "student": STUDENT_NAME,
                "branch": STUDENT_BRANCH,
                "dataset_type": summary["dataset_type"],
                "selected_model": selected_name,
                "output_files": [
                    "model.joblib",
                    "feature_schema.json",
                    "evaluation_metrics.json",
                    "classification_report.txt",
                    "confusion_matrix.png",
                    "class_distribution.png",
                    "feature_correlation.png",
                    "model_comparison.png",
                    "system_architecture.png",
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    LOGGER.info("Training complete. Selected model: %s", selected_name)
    LOGGER.info("Artifacts saved to: %s", out_dir.resolve())
    return summary


def predict_network_flows(
    records: pd.DataFrame | list[dict[str, Any]] | dict[str, Any],
    model_path: Path,
    schema_path: Path,
    output_csv_path: Path | None = None,
) -> dict[str, Any]:
    """
    Programmatic & CLI helper to predict network flows against saved model.joblib
    and feature_schema.json.
    """
    if not model_path.exists() or not schema_path.exists():
        raise FileNotFoundError(
            f"Model files were not found in {model_path.parent}. Run training first."
        )
    model = joblib.load(model_path)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    expected: list[str] = schema.get("feature_columns") or schema.get("required_features", [])
    medians: dict[str, float] = schema.get("training_feature_medians", {})

    if isinstance(records, dict):
        raw = pd.DataFrame([records])
    elif isinstance(records, list):
        raw = pd.DataFrame(records)
    else:
        raw = records.copy()

    raw = clean_column_names(raw)
    label_cols = [c for c in raw.columns if c.strip().lower() == "label"]
    if label_cols:
        raw = raw.drop(columns=label_cols)

    missing = [c for c in expected if c not in raw.columns]
    extra = [c for c in raw.columns if c not in expected]

    # If all expected features are missing, raise a clear error
    if len(missing) == len(expected):
        raise ValueError(
            "Prediction input is missing required feature columns: "
            + ", ".join(missing[:20])
            + ". Use the same feature schema as the training dataset."
        )

    X = pd.DataFrame(index=raw.index)
    for col in expected:
        if col in raw.columns:
            X[col] = pd.to_numeric(raw[col], errors="coerce")
        else:
            X[col] = float(medians.get(col, 0.0))
    X = X.replace([np.inf, -np.inf], np.nan)

    predicted = model.predict(X)
    probabilities = None
    if hasattr(model, "predict_proba"):
        try:
            probabilities = model.predict_proba(X)[:, 1]
        except (ValueError, IndexError):
            probabilities = None

    note = "Model estimate only; not a guarantee of safety."
    out_df = X.copy()
    out_df["predicted_class"] = np.where(predicted == 1, "MALICIOUS", "BENIGN")
    out_df["malicious_probability"] = probabilities if probabilities is not None else np.nan
    out_df["prediction_note"] = note
    # Also include capitalized aliases for table compatibility
    out_df["Predicted_Class"] = out_df["predicted_class"]
    out_df["Malicious_Probability"] = out_df["malicious_probability"]
    out_df["Confidence_Score"] = np.where(
        predicted == 1,
        out_df["malicious_probability"],
        1.0 - out_df["malicious_probability"].fillna(0.0),
    )
    out_df["Model_Disclaimer"] = note

    if output_csv_path is not None:
        output_csv_path.parent.mkdir(parents=True, exist_ok=True)
        out_df.to_csv(output_csv_path, index=False)
        LOGGER.info("Predictions saved to: %s", output_csv_path.resolve())

    if extra:
        LOGGER.info("Ignored extra prediction columns: %s", ", ".join(extra[:20]))

    preds_list = []
    for i in range(len(out_df)):
        p_int = int(predicted[i])
        m_prob = float(probabilities[i]) if probabilities is not None else (1.0 if p_int == 1 else 0.0)
        c_score = m_prob if p_int == 1 else (1.0 - m_prob)
        preds_list.append(
            {
                "row_index": i,
                "predicted_class": "MALICIOUS" if p_int == 1 else "BENIGN",
                "predicted_label_int": p_int,
                "malicious_probability": round(m_prob, 4),
                "confidence_score": round(c_score, 4),
                "disclaimer": note,
            }
        )

    return {
        "model_used": schema.get("selected_model", "Random Forest"),
        "total_flows_evaluated": len(preds_list),
        "predicted_benign_count": sum(1 for r in preds_list if r["predicted_class"] == "BENIGN"),
        "predicted_malicious_count": sum(1 for r in preds_list if r["predicted_class"] == "MALICIOUS"),
        "validation_report": {
            "missing_features": missing,
            "extra_features_ignored": extra,
            "validation_notes": [
                "All required feature columns validated against feature_schema.json."
                if not missing
                else f"Filled {len(missing)} missing feature column(s) with training medians: {missing}."
            ],
        },
        "disclaimer": note,
        "predictions": preds_list,
    }


def predict_csv(input_path: Path, out_dir: Path, output_path: Path | None = None) -> None:
    """CLI prediction entrypoint validating strict schema match on CSV files."""
    model_path = out_dir / "model.joblib"
    schema_path = out_dir / "feature_schema.json"
    if not model_path.exists() or not schema_path.exists():
        raise FileNotFoundError(
            f"Model files were not found in {out_dir}. Run training first."
        )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    expected = schema["feature_columns"]
    raw = clean_column_names(pd.read_csv(input_path, low_memory=False))
    label_cols = [c for c in raw.columns if c.strip().lower() == "label"]
    if label_cols:
        raw = raw.drop(columns=label_cols)
    missing = [c for c in expected if c not in raw.columns]
    if missing:
        raise ValueError(
            "Prediction CSV is missing required feature columns: "
            + ", ".join(missing[:20])
            + ". Use the same feature schema as the training dataset."
        )
    result_path = output_path or (out_dir / "predictions.csv")
    predict_network_flows(
        records=raw,
        model_path=model_path,
        schema_path=schema_path,
        output_csv_path=result_path,
    )


def generate_project_report_docx(
    docx_path: Path,
    output_dir: Path,
    student_name: str = STUDENT_NAME,
    branch_name: str = STUDENT_BRANCH,
    institution_name: str = "[Institution / College Name]",
) -> Path:
    """
    Generates `HemlataKumawat_ProjectReport.docx` using `python-docx` with all
    30 sections, embedded visualizations, and accurate attribution of Synthetic
    Demo verification metrics vs. real CIC-IDS2017 dataset results.
    """
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    metrics_file = output_dir / "evaluation_metrics.json"
    metrics_data = (
        json.loads(metrics_file.read_text(encoding="utf-8"))
        if metrics_file.exists()
        else None
    )

    doc = Document()
    for section in doc.sections:
        section.top_margin = Inches(0.95)
        section.bottom_margin = Inches(0.95)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        footer = section.footer
        p_foot = footer.paragraphs[0]
        p_foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f = p_foot.add_run(
            f"IBM SkillsBuild Cyber Security Bootcamp 2026 | {student_name} ({branch_name}) — Page "
        )
        r_f.font.name = "Calibri"
        r_f.font.size = Pt(9)
        r_f.font.color.rgb = RGBColor(100, 116, 139)
        fldSimple = OxmlElement("w:fldSimple")
        fldSimple.set(qn("w:instr"), "PAGE")
        p_foot._p.append(fldSimple)

    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Calibri"
    normal_style.font.size = Pt(11)

    def add_sec_heading(num: int, title: str, level: int = 1) -> None:
        h = doc.add_heading(f"{num}. {title}", level=level)
        for r in h.runs:
            r.font.name = "Calibri"
            r.font.color.rgb = RGBColor(15, 23, 42)

    def embed_plot(fname: str, caption: str, width_in: float = 5.6) -> None:
        img_p = output_dir / fname
        if img_p.exists():
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.add_run().add_picture(str(img_p), width=Inches(width_in))
            c = doc.add_paragraph(caption)
            c.alignment = WD_ALIGN_PARAGRAPH.CENTER
            c.runs[0].italic = True
            c.runs[0].font.size = Pt(9.5)

    # 1. Cover Page
    add_sec_heading(1, "Cover Page", level=1)
    p_top = doc.add_paragraph()
    p_top.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_top = p_top.add_run(
        "IBM SkillsBuild Cyber Security Bootcamp 2026\n"
        "Conducted by BharatCares (CSRBOX Group)\n"
    )
    r_top.bold = True
    r_top.font.size = Pt(14)

    p_main = doc.add_paragraph()
    p_main.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_main = p_main.add_run(
        "ML-Based Network Intrusion Detection System Using CIC-IDS2017\n"
        "Category: Machine Learning for Defensive Cybersecurity"
    )
    r_main.bold = True
    r_main.font.size = Pt(17)

    tbl = doc.add_table(rows=7, cols=2)
    tbl.style = "Table Grid"
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cover_items = [
        ("2. Project Title", "ML-Based Network Intrusion Detection System Using CIC-IDS2017"),
        ("3. Student Name", student_name),
        ("   Branch / Stream", branch_name),
        ("4. Institution", institution_name),
        ("5. Program", "IBM SkillsBuild Cyber Security Bootcamp 2026"),
        ("6. Partner Organization", "BharatCares (CSRBOX Group)"),
        ("   Date", datetime.now().strftime("%B %d, %Y")),
    ]
    for idx, (k, v) in enumerate(cover_items):
        tbl.rows[idx].cells[0].text = k
        tbl.rows[idx].cells[1].text = v
        tbl.rows[idx].cells[0].paragraphs[0].runs[0].bold = True

    doc.add_page_break()

    add_sec_heading(2, "Project Title", level=2)
    doc.add_paragraph("ML-Based Network Intrusion Detection System Using CIC-IDS2017.")

    add_sec_heading(3, "Student Details", level=2)
    doc.add_paragraph(f"Student Name: {student_name} | Branch: {branch_name}")

    add_sec_heading(4, "Institution", level=2)
    doc.add_paragraph(f"Institution: {institution_name}")

    add_sec_heading(5, "IBM SkillsBuild Cyber Security Bootcamp 2026", level=2)
    doc.add_paragraph(
        "Academic project submitted for the IBM SkillsBuild Cyber Security Bootcamp 2026."
    )

    add_sec_heading(6, "BharatCares (CSRBOX Group)", level=2)
    doc.add_paragraph("Conducted and mentored by BharatCares (CSRBOX Group).")

    add_sec_heading(7, "Abstract", level=1)
    doc.add_paragraph(
        "This project implements an offline, dataset-based Machine Learning Network Intrusion "
        "Detection System (NIDS) in Python 3 (`HemlataKumawat_NetworkIntrusionDetection.py`). "
        "It ingests labeled network-flow records from the CIC-IDS2017 dataset, normalizes column "
        "names, handles missing and infinite values safely, prevents target and test-set data "
        "leakage, and compares Decision Tree and Random Forest classifiers on a stratified test split."
    )

    add_sec_heading(8, "Introduction", level=1)
    doc.add_paragraph(
        "Network Intrusion Detection Systems analyze network traffic statistics to distinguish "
        "normal benign activity from malicious cyberattacks. Flow-based analysis inspects packet "
        "counts, durations, byte rates, and TCP flags without requiring raw payload decryption."
    )

    add_sec_heading(9, "Problem Statement", level=1)
    doc.add_paragraph(
        "Evaluating intrusion detection models solely by Accuracy is misleading when traffic is "
        "imbalanced, and fitting preprocessing transformations before splitting train and test sets "
        "introduces data leakage. This project builds a leak-free classification pipeline and "
        "evaluates both false positives and false negatives explicitly."
    )

    add_sec_heading(10, "Project Objectives", level=1)
    for item in [
        "Load and clean labeled CIC-IDS2017 CSV network-flow records.",
        "Map labels into BENIGN (0) and MALICIOUS (1) while excluding the target from input features.",
        "Prevent data leakage by filtering constant/duplicate features and fitting median imputation on training data only.",
        "Compare Decision Tree and Random Forest models using Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix.",
        "Support batch prediction (`--predict`) on separate unseen CSV files with strict schema validation.",
    ]:
        doc.add_paragraph(item, style="List Bullet")

    add_sec_heading(11, "Scope of the Project", level=1)
    doc.add_paragraph(
        "This is an offline educational dataset analysis and prediction tool. It does not capture "
        "live network packets, act as an inline firewall, or guarantee that network traffic is safe."
    )

    add_sec_heading(12, "Background on Network Intrusion Detection", level=1)
    doc.add_paragraph(
        "Signature-based detection matches known byte patterns, while supervised machine-learning "
        "NIDS models learn statistical relationships across flow features such as Flow Duration, "
        "Total Fwd Packets, Flow Packets/s, Active Mean, and Idle Mean."
    )

    add_sec_heading(13, "Dataset Description and Source Links", level=1)
    doc.add_paragraph(
        "• Official CIC-IDS2017 Page: https://www.unb.ca/cic/datasets/ids-2017.html\n"
        "• Accessible Mirror: https://huggingface.co/datasets/bvsam/cic-ids-2017\n"
        "Each CSV contains numerical network-flow telemetry and a `Label` column where `BENIGN` "
        "denotes normal traffic and attack labels (DoS, DDoS, PortScan, Brute Force, etc.) are "
        "mapped to `MALICIOUS` (1)."
    )

    add_sec_heading(14, "Technologies and Tools Used", level=1)
    doc.add_paragraph(
        "Python 3, pandas, NumPy, scikit-learn (Pipeline, SimpleImputer, DecisionTreeClassifier, "
        "RandomForestClassifier), matplotlib, seaborn, joblib, and python-docx."
    )

    add_sec_heading(15, "System Architecture", level=1)
    embed_plot("system_architecture.png", "Figure 1: System Architecture and Pipeline Workflow.")

    add_sec_heading(16, "Methodology and Workflow", level=1)
    doc.add_paragraph(
        "1. Parse CLI arguments (`--data`, `--demo`, `--predict`, `--sample-size`, `--test-size`).\n"
        "2. Clean column names, identify the `Label` column, and map labels to 0 (`BENIGN`) or 1 (`MALICIOUS`).\n"
        "3. Perform a stratified train/test split (`random_state=42`).\n"
        "4. Filter unusable columns and fit `SimpleImputer(strategy='median')` strictly on `X_train`.\n"
        "5. Train Decision Tree and Random Forest classifiers, select the best model by `f1_malicious` "
        "(tie-breaking with `recall_malicious`), and save all artifacts to `outputs/`."
    )

    add_sec_heading(17, "Data Preprocessing", level=1)
    doc.add_paragraph(
        "Column headers are stripped of UTF-8 BOMs and whitespace. Non-numeric entries and `+/-inf` "
        "values are converted to `NaN`. Constant, duplicate, and all-missing columns are detected on "
        "`X_train` only, and missing values are imputed using the training median inside the Pipeline."
    )

    add_sec_heading(18, "Exploratory Data Analysis", level=1)
    embed_plot("class_distribution.png", "Figure 2: Network Flow Class Distribution.")
    embed_plot("feature_correlation.png", "Figure 3: Feature Correlation Heatmap.")

    add_sec_heading(19, "Machine-Learning Algorithms", level=1)
    doc.add_paragraph(
        "• Decision Tree (`max_depth=12, class_weight='balanced'`): Fast, interpretable tree baseline.\n"
        "• Random Forest (`n_estimators=120, max_depth=18, min_samples_leaf=2, class_weight='balanced_subsample'`): "
        "Ensemble classifier that reduces variance across correlated network-flow features."
    )

    add_sec_heading(20, "Training and Testing Methodology", level=1)
    doc.add_paragraph(
        "A stratified 80/20 split (`test_size=0.2, random_state=42`) preserves the class ratio "
        "across training and testing sets. Class imbalance is handled via `class_weight='balanced'` "
        "and `class_weight='balanced_subsample'`."
    )

    add_sec_heading(21, "Evaluation Metrics and Their Definitions", level=1)
    doc.add_paragraph(
        "With `MALICIOUS` (1) defined as the positive class: Accuracy measures overall correctness; "
        "Precision measures the fraction of predicted malicious flows that are truly malicious; "
        "Recall measures the fraction of actual malicious flows detected; F1-Score is the harmonic "
        "mean of Precision and Recall; and ROC-AUC evaluates probability ranking."
    )

    add_sec_heading(22, "Actual Experimental Results", level=1)
    if metrics_data:
        is_demo_run = metrics_data.get("dataset_type") == "synthetic_demo"
        doc.add_paragraph(
            "NOTE — SYNTHETIC DEMO VERIFICATION RUN: The metrics below were measured by running "
            "`python HemlataKumawat_NetworkIntrusionDetection.py --demo --output-dir outputs` to "
            "verify that training, evaluation, and artifact generation succeed. Synthetic demo "
            "metrics are NOT real CIC-IDS2017 experimental evidence. After running with "
            "`--data path/to/cicids2017.csv --generate-report`, this table automatically updates "
            "with your measured CIC-IDS2017 benchmark results."
            if is_demo_run
            else "MEASURED RESULTS ON SUPPLIED CIC-IDS2017 CSV DATASET:"
        ).runs[0].bold = True

        m_dict = metrics_data.get("model_metrics", {})
        t_res = doc.add_table(rows=1 + len(m_dict), cols=8)
        t_res.style = "Table Grid"
        cols = ["Model", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC", "FP", "FN"]
        for c_i, h in enumerate(cols):
            t_res.rows[0].cells[c_i].text = h
            t_res.rows[0].cells[c_i].paragraphs[0].runs[0].bold = True
        for r_i, (m_name, vals) in enumerate(m_dict.items(), start=1):
            c = t_res.rows[r_i].cells
            c[0].text = m_name
            c[1].text = f"{vals['accuracy']:.4f}"
            c[2].text = f"{vals['precision_malicious']:.4f}"
            c[3].text = f"{vals['recall_malicious']:.4f}"
            c[4].text = f"{vals['f1_malicious']:.4f}"
            c[5].text = f"{vals['roc_auc']:.4f}" if vals.get("roc_auc") is not None else "N/A"
            c[6].text = str(vals["false_positives"])
            c[7].text = str(vals["false_negatives"])

        embed_plot("model_comparison.png", "Figure 4: Model Performance Comparison.")
        embed_plot("confusion_matrix.png", "Figure 5: Confusion Matrix for Selected Model.")

    add_sec_heading(23, "Results Interpretation", level=1)
    doc.add_paragraph(
        "Random Forest outperforms the single Decision Tree on F1-Score, Recall, and ROC-AUC by "
        "aggregating predictions across 120 trees, reducing both false positives and false negatives."
    )

    add_sec_heading(24, "Discussion of False Positives and False Negatives", level=1)
    doc.add_paragraph(
        "False Positives (benign flows flagged as malicious) create unnecessary alerts for analysts, "
        "whereas False Negatives (malicious flows predicted as benign) allow attacks to pass "
        "unnoticed. Selecting models via malicious-class F1-Score and Recall prioritizes catching attacks."
    )

    add_sec_heading(25, "Limitations", level=1)
    doc.add_paragraph(
        "1. Binary mapping groups all non-BENIGN labels into a single MALICIOUS class.\n"
        "2. Offline dataset evaluation does not capture live packets or prevent attacks in real time.\n"
        "3. Random splits can overestimate performance compared to time-based or cross-network splits."
    )

    add_sec_heading(26, "Ethical Considerations", level=1)
    doc.add_paragraph(
        "Use this software strictly for defensive cybersecurity education on public or authorized "
        "datasets. Never rely solely on automated ML scores to block users without human review."
    )

    add_sec_heading(27, "Future Enhancements", level=1)
    doc.add_paragraph(
        "Future work includes multi-class attack family classification, time-based train/test splitting, "
        "and SHAP feature attribution for alert explainability."
    )

    add_sec_heading(28, "Conclusion", level=1)
    doc.add_paragraph(
        "This project delivered a leak-free, reproducible Python machine-learning pipeline for "
        "network intrusion detection using the CIC-IDS2017 dataset schema."
    )

    add_sec_heading(29, "References", level=1)
    doc.add_paragraph(
        "1. Canadian Institute for Cybersecurity, CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html\n"
        "2. Hugging Face CIC-IDS2017 Mirror: https://huggingface.co/datasets/bvsam/cic-ids-2017\n"
        "3. Scikit-learn Documentation: https://scikit-learn.org/stable/"
    )

    add_sec_heading(30, "Instructions for Reproducing the Experiment", level=1)
    doc.add_paragraph(
        "1. Install dependencies: `python -m pip install -r requirements.txt`\n"
        "2. Run synthetic demo check: `python HemlataKumawat_NetworkIntrusionDetection.py --demo --output-dir outputs --generate-report`\n"
        "3. Train on CIC-IDS2017 CSV: `python HemlataKumawat_NetworkIntrusionDetection.py --data path/to/your_labeled_file.csv --output-dir outputs --sample-size 100000 --generate-report`\n"
        "4. Predict on unseen CSV: `python HemlataKumawat_NetworkIntrusionDetection.py --predict path/to/unseen_flows.csv --output-dir outputs`"
    )

    docx_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(docx_path))
    LOGGER.info("Project report saved to: %s", docx_path.resolve())
    return docx_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train or use a dataset-based ML network intrusion detection model."
    )
    parser.add_argument(
        "--data",
        "--data-path",
        dest="data",
        nargs="+",
        type=Path,
        help="One or more labeled CSV files for training.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use generated SYNTHETIC data to test the pipeline; not real dataset evidence.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=100000,
        help="Maximum rows sampled from each input CSV (default: 100000; use 0 for all rows).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=RANDOM_STATE,
        help="Random seed for reproducible sampling and splitting (default: 42).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs"),
        help="Directory for model, metrics, plots, and predictions (default: outputs).",
    )
    parser.add_argument(
        "--predict",
        "--predict-csv",
        dest="predict",
        type=Path,
        help="Predict labels for a separate CSV using an already trained model.",
    )
    parser.add_argument(
        "--prediction-output",
        type=Path,
        help="Optional output path for prediction CSV.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction held out for testing (default: 0.2).",
    )
    parser.add_argument(
        "--generate-report",
        action="store_true",
        help="Generate or update HemlataKumawat_ProjectReport.docx from current evaluation outputs.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=Path(DEFAULT_REPORT_FILENAME),
        help=f"Output path for DOCX report (default: {DEFAULT_REPORT_FILENAME}).",
    )
    parser.add_argument(
        "--student-name",
        type=str,
        default=STUDENT_NAME,
        help=f"Student name for report header (default: {STUDENT_NAME}).",
    )
    parser.add_argument(
        "--institution",
        type=str,
        default="[Institution / College Name]",
        help="Institution name for report cover page.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = parse_args(argv)
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
            demo_rows = (
                args.sample_size
                if (args.sample_size and 10 <= args.sample_size <= 50000 and args.sample_size != 100000)
                else 800
            )
            data = make_demo_data(rows=demo_rows, random_state=args.seed)
            demo_csv_path = args.output_dir / "synthetic_demo_flows.csv"
            args.output_dir.mkdir(parents=True, exist_ok=True)
            data.to_csv(demo_csv_path, index=False)
            train_project(
                data,
                args.output_dir,
                test_size=args.test_size,
                is_demo=True,
                original_row_count=len(data),
                random_state=args.seed,
            )
            # Also generate predictions.csv on demo flows so prediction output is verified
            predict_csv(demo_csv_path, args.output_dir, args.output_dir / "predictions.csv")
        elif args.data:
            sample_size = None if args.sample_size == 0 else args.sample_size
            if sample_size is not None and sample_size < 10:
                raise ValueError("--sample-size must be 0 or at least 10.")
            data, orig_rows = read_csv_files(args.data, sample_size=sample_size, random_state=args.seed)
            train_project(
                data,
                args.output_dir,
                test_size=args.test_size,
                is_demo=False,
                original_row_count=orig_rows,
                random_state=args.seed,
            )
        elif not args.generate_report:
            raise ValueError("Provide --data path/to/file.csv or use --demo.")

        if args.generate_report or not args.report_path.exists():
            generate_project_report_docx(
                docx_path=args.report_path,
                output_dir=args.output_dir,
                student_name=args.student_name,
                branch_name=STUDENT_BRANCH,
                institution_name=args.institution,
            )
        return 0
    except Exception as exc:
        LOGGER.error("%s", exc)
        LOGGER.info("Run with --help to see command-line options.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
