#!/usr/bin/env python3
"""
Automated Quality Assurance & Unit Test Suite for
`HemlataKumawat_NetworkIntrusionDetection.py`
"""
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from HemlataKumawat_NetworkIntrusionDetection import (
    clean_column_names,
    filter_features_on_train_only,
    find_label_column,
    generate_project_report_docx,
    make_demo_data,
    normalize_labels,
    predict_network_flows,
    prepare_dataset,
    train_project,
)


class TestHemlataNIDSPipeline(unittest.TestCase):
    def test_clean_column_names_strips_bom_and_whitespace(self) -> None:
        df = pd.DataFrame({
            "\ufeff Destination Port ": [80, 443],
            "Flow   Duration": [100, 200],
            " Label ": ["BENIGN", "DoS Hulk"],
        })
        cleaned = clean_column_names(df)
        self.assertEqual(list(cleaned.columns), ["Destination Port", "Flow Duration", "Label"])

    def test_find_label_column_and_normalize_labels(self) -> None:
        df = pd.DataFrame({"Destination Port": [80], " label ": ["BENIGN"]})
        self.assertEqual(find_label_column(df), " label ")
        series = pd.Series([" BENIGN ", "DoS Hulk", "   ", np.nan])
        mapped = normalize_labels(series)
        self.assertEqual(int(mapped.iloc[0]), 0)
        self.assertEqual(int(mapped.iloc[1]), 1)
        self.assertTrue(pd.isna(mapped.iloc[2]))
        self.assertTrue(pd.isna(mapped.iloc[3]))

    def test_prepare_dataset_excludes_identifiers_and_target(self) -> None:
        raw_df = make_demo_data(rows=200, random_state=42)
        raw_df["Unnamed: 0"] = np.arange(len(raw_df))
        raw_df["Flow ID"] = "192.168.1.1-10.0.0.1-80"
        raw_df["Timestamp"] = "07/07/2017 03:30:00"

        X, y, _, summary = prepare_dataset(raw_df)
        lower_cols = [c.lower() for c in X.columns]
        self.assertNotIn("label", lower_cols)
        self.assertNotIn("unnamed: 0", lower_cols)
        self.assertNotIn("flow id", lower_cols)
        self.assertNotIn("timestamp", lower_cols)
        self.assertIn("Unnamed: 0", summary["identifier_columns_excluded"])
        self.assertFalse(np.isinf(X.to_numpy(na_value=0.0)).any())
        self.assertEqual(len(X), len(y))

    def test_filter_features_on_train_only_prevents_test_leakage(self) -> None:
        # Column 'TestOnlySignal' is constant (0) in train, but varies in test.
        # A leak-free pipeline MUST drop 'TestOnlySignal' based on X_train alone.
        X_train = pd.DataFrame({
            "ValidFeature": [1.0, 2.0, 3.0, 4.0],
            "TestOnlySignal": [0.0, 0.0, 0.0, 0.0],
            "AllMissingTrain": [np.nan, np.nan, np.nan, np.nan],
            "DupFeature": [1.0, 2.0, 3.0, 4.0],
        })
        X_test = pd.DataFrame({
            "ValidFeature": [5.0, 6.0],
            "TestOnlySignal": [0.0, 99.0],
            "AllMissingTrain": [10.0, 20.0],
            "DupFeature": [5.0, 6.0],
        })
        X_tr_clean, X_te_clean, filter_info = filter_features_on_train_only(X_train, X_test)
        self.assertEqual(list(X_tr_clean.columns), ["ValidFeature"])
        self.assertEqual(list(X_te_clean.columns), ["ValidFeature"])
        self.assertIn("TestOnlySignal", filter_info["dropped_constant_columns"])
        self.assertIn("AllMissingTrain", filter_info["dropped_all_missing_columns"])
        self.assertIn("DupFeature", filter_info["dropped_duplicate_columns"])

    def test_end_to_end_train_predict_and_docx_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            demo_df = make_demo_data(rows=300, random_state=42)
            results = train_project(
                data=demo_df,
                out_dir=out_dir,
                test_size=0.2,
                is_demo=True,
                random_state=42,
            )
            self.assertEqual(results["dataset_type"], "synthetic_demo")
            self.assertTrue((out_dir / "model.joblib").exists())
            self.assertTrue((out_dir / "feature_schema.json").exists())

            sample_records = demo_df.drop(columns=["Label"]).head(10)
            pred_res = predict_network_flows(
                records=sample_records,
                model_path=out_dir / "model.joblib",
                schema_path=out_dir / "feature_schema.json",
                output_csv_path=out_dir / "predictions.csv",
            )
            self.assertEqual(pred_res["total_flows_evaluated"], 10)
            self.assertTrue((out_dir / "predictions.csv").exists())

            docx_path = out_dir / "HemlataKumawat_ProjectReport.docx"
            generate_project_report_docx(docx_path=docx_path, output_dir=out_dir)
            self.assertTrue(docx_path.exists())
            self.assertGreater(docx_path.stat().st_size, 10000)


if __name__ == "__main__":
    unittest.main()
