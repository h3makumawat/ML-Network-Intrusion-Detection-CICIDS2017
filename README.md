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

- CSV loading, UTF-8 BOM stripping, duplicate header resolution, and non-behavioral identifier exclusion (`Flow ID`, IP addresses, `Timestamp`, `Unnamed: 0`)
- Numeric feature validation, missing-value (`NaN`) handling, and infinite-value (`+/-inf`) handling
- Deterministic chunked sampling and reproducible stratified train/test split (`random_state=42`)
- Strict leak-free preprocessing: all-missing, constant, and duplicate feature filtering plus median imputation (`SimpleImputer`) are fitted **exclusively on the training split (`X_train`)**
- Decision Tree and Random Forest comparison with balanced class weighting
- Accuracy, malicious-class precision/recall/F1, false positives, false negatives, and ROC-AUC where available
- Confusion matrix, class distribution, correlation heatmap, model comparison, and system architecture plots
- Saved model (`model.joblib`) and feature schema (`feature_schema.json`)
- Optional batch prediction on a separate CSV (`--predict`)
- Automated 30-section Microsoft Word project report generator (`--generate-report` -> `HemlataKumawat_ProjectReport.docx`)
- Synthetic demo mode (`--demo`) to check that the pipeline runs without downloading a dataset

## Project structure

```text
ml-network-intrusion-detection/
├── HemlataKumawat_NetworkIntrusionDetection.py
├── requirements.txt
├── README.md
├── HemlataKumawat_ProjectReport.docx
├── .gitignore
└── outputs/                 # generated when the program runs (excluded via .gitignore)
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

## Quick pipeline check (Synthetic Demo Mode)

The synthetic demo verifies that training, evaluation, prediction, report generation, and artifact creation work. It does not provide evidence of performance on real network traffic.

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --demo --output-dir outputs --generate-report
```

Expected output artifacts in `outputs/` include `model.joblib`, `feature_schema.json`, `evaluation_metrics.json`, `classification_report.txt`, `confusion_matrix.png`, `class_distribution.png`, `feature_correlation.png`, `model_comparison.png`, `system_architecture.png`, `predictions.csv`, and `run_summary.json`, along with `HemlataKumawat_ProjectReport.docx` in the project root.

## Train on CIC-IDS2017 data

1. Download an appropriate labeled CSV from the official dataset page or the Hugging Face mirror (for example, `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` or `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`).
2. Place the CSV inside a `data/` folder in your project directory.
3. Run the script with the path to the file and `--generate-report` to update the Word report with your real measured results:

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --data data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --output-dir outputs --sample-size 100000 --generate-report
```

To use all rows in each supplied CSV, use `--sample-size 0`. Large files can require substantial RAM and processing time. For a first run on a laptop, start with one manageable CSV and a sample size of `50000` to `100000`.

You can supply more than one CSV file (or a directory containing CSV files):

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --data data/file1.csv data/file2.csv --output-dir outputs --generate-report
```

The files should have compatible feature columns and a labeled `Label` column. Different columns are combined, with missing values filled using training-set medians during preprocessing.

## Predict a separate CSV

Train a model first. The prediction CSV must contain the same feature columns used in training. The target `Label` column, if present, is ignored.

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --predict path/to/unseen_flows.csv --output-dir outputs
```

Optionally choose an output path:

```bash
python HemlataKumawat_NetworkIntrusionDetection.py --predict path/to/unseen_flows.csv --output-dir outputs --prediction-output outputs/my_predictions.csv
```

Predictions include `predicted_class`, `malicious_probability` (when the estimator supports probability estimates), and `prediction_note`. The score is a model estimate, not a guarantee.

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
- **No Python command:** install Python and ensure it is available on PATH, or run the script from a Python virtual environment.

## Reproducibility

The code uses random seed `42`. The run summary and actual measured metrics are saved under `outputs/`. Retain the generated metrics with the dataset name, sample size, and run configuration when documenting experiments.

## Ethical use

Use this project for education and defensive security analysis only. Use public datasets or data you are authorized to analyze. Do not use predictions as the sole basis for blocking users or making security decisions.

## References

1. Canadian Institute for Cybersecurity, CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
2. Hugging Face CIC-IDS2017 Mirror: https://huggingface.co/datasets/bvsam/cic-ids-2017
3. Scikit-learn documentation: https://scikit-learn.org/stable/
4. pandas documentation: https://pandas.pydata.org/docs/
5. NumPy documentation: https://numpy.org/doc/
