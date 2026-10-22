# ML-Based Network Intrusion Detection System

**IBM SkillsBuild Cyber Security Bootcamp 2026 — BharatCares (CSRBOX Group)**  
**Student:** Hemlata Kumawat  
**Branch:** BCA

## Overview

This defensive cybersecurity learning project trains machine-learning classifiers on labeled network-flow records and predicts whether each record is **BENIGN** or **MALICIOUS**. It compares a Decision Tree with a Random Forest and reports standard classification metrics.

This is an offline, dataset-based educational project. It does **not** capture live traffic, block network activity, or guarantee that a record is safe.

## Dataset

- Official CIC-IDS2017 page: https://www.unb.ca/cic/datasets/ids-2017.html
- Accessible dataset mirror: https://huggingface.co/datasets/bvsam/cic-ids-2017

Use a labeled CSV containing numeric network-flow features and a `Label` column. The label `BENIGN` is mapped to class 0; other non-empty labels are mapped to class 1 (`MALICIOUS`). Review the dataset's license and terms before use or redistribution. Do not upload the full dataset to this repository unless you have verified redistribution rights.

## Features

- CSV loading and basic data cleaning
- Numeric feature validation, missing-value handling, and infinite-value handling
- Deterministic sampling and reproducible train/test split
- Decision Tree and Random Forest comparison
- Accuracy, malicious-class precision/recall/F1, false positives, false negatives, and ROC-AUC where available
- Confusion matrix, class distribution, correlation heatmap, and model comparison plots
- Saved model and feature schema
- Optional prediction on a separate CSV
- Synthetic demo mode to check that the pipeline runs without downloading a dataset

## Project structure

```text
ml-network-intrusion-detection/
├── HemlataKumawat_NetworkIntrusionDetection.py
├── requirements.txt
├── README.md
├── HemlataKumawat_ProjectReport.docx
├── .gitignore
└── outputs/                 # generated when the program runs
```

## Requirements

- Python 3.10 or newer recommended
- Internet access to install packages (not required after installation)
- A laptop or hosted Python environment; no GPU required

## Setup

Create and activate a virtual environment if you are using a local Python installation.

**Windows PowerShell**
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

**macOS/Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Quick pipeline check

The synthetic demo verifies that training, evaluation, and artifact creation work. It does not provide evidence of performance on real network traffic.

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --demo --output-dir outputs
```

Expected output artifacts include `model.joblib`, `feature_schema.json`, `evaluation_metrics.json`, `classification_report.txt`, `confusion_matrix.png`, `class_distribution.png`, `feature_correlation.png` (when at least two usable features exist), `model_comparison.png`, and `run_summary.json`.

## Train on CIC-IDS2017 data

1. Download an appropriate labeled CSV from the official dataset page or a suitable mirror.
2. Place the CSV somewhere accessible in your environment.
3. Run the script with the path to the file:

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --data path/to/your_labeled_file.csv --output-dir outputs --sample-size 100000
```

To use all rows in each supplied CSV, use `--sample-size 0`. Large files can require substantial RAM and processing time. For a first run, start with one manageable CSV and a smaller sample.

You can supply more than one CSV file:

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --data path/to/file1.csv path/to/file2.csv --output-dir outputs
```

The files should have compatible feature columns and a labeled `Label` column. Different columns are combined, with missing values filled during preprocessing.

## Predict a separate CSV

Train a model first. The prediction CSV must contain the same feature columns used in training. The target `Label` column, if present, is ignored.

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --predict path/to/unseen_flows.csv --output-dir outputs
```

Optionally choose an output path:

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --predict path/to/unseen_flows.csv --output-dir outputs --prediction-output outputs/my_predictions.csv
```

Predictions include `predicted_class` and `malicious_probability` when the estimator supports probability estimates. The score is a model estimate, not a guarantee.

## Evaluation metrics

- **Accuracy:** fraction of all test records classified correctly.
- **Precision (malicious class):** among records predicted malicious, the fraction that are malicious.
- **Recall (malicious class):** among truly malicious records, the fraction detected.
- **F1-score:** harmonic mean of precision and recall.
- **False positives:** benign records incorrectly predicted as malicious.
- **False negatives:** malicious records incorrectly predicted as benign.
- **ROC-AUC:** ranking metric when both classes and model probabilities are available.

Accuracy alone can be misleading when classes are imbalanced. False negatives may let malicious traffic go undetected; false positives may create unnecessary alerts.

## Important limitations

- The binary label mapping treats every non-empty, non-`BENIGN` label as malicious. Review source labels and dataset quality before interpreting results.
- Results depend on the selected dataset, features, split, and sample. They do not guarantee performance on new or real-time traffic.
- Random train/test splits may overestimate generalization when records are correlated or duplicated. Stronger evaluation can use time-based or scenario-based splits and deduplication.
- The project is not a live intrusion detection sensor, firewall, or prevention system.
- Synthetic demo data is only for pipeline verification. Never report demo metrics as CIC-IDS2017 results.

## Troubleshooting

- **Missing Label column:** ensure the CSV is labeled and has a `Label` column.
- **Missing feature columns during prediction:** use the same feature schema as training.
- **Only one class found:** use a dataset/sample containing both benign and malicious records.
- **Memory problems:** lower `--sample-size`, use one CSV at a time, and close other applications.
- **No Python command:** install Python and ensure it is available on PATH, or run the script from a Python notebook environment.

## Reproducibility

The code uses random seed `42`. The run summary and actual measured metrics are saved under `outputs/`. Retain the generated metrics with the dataset name, sample size, and run configuration when documenting experiments.

## Ethical use

Use this project for education and defensive security analysis only. Use public datasets or data you are authorized to analyze. Do not use predictions as the sole basis for blocking users or making security decisions.

## References

1. Canadian Institute for Cybersecurity, CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
2. Scikit-learn documentation: https://scikit-learn.org/stable/
3. pandas documentation: https://pandas.pydata.org/docs/
4. NumPy documentation: https://numpy.org/doc/
