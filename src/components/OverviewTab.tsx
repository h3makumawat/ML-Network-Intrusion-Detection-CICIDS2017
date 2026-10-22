import React, { useState } from 'react';
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Database,
  Download,
  FileSpreadsheet,
  Play,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { EvaluationMetricsPayload, ProjectStatePayload } from '../types';

interface OverviewTabProps {
  projectState: ProjectStatePayload;
  onRefreshState: (newState: ProjectStatePayload) => void;
  onNavigateTab: (tab: 'overview' | 'predictor' | 'deliverables' | 'report') => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  projectState,
  onRefreshState,
  onNavigateTab,
}) => {
  const metrics: EvaluationMetricsPayload | null = projectState.evaluationMetrics;
  const [sampleSize, setSampleSize] = useState<number>(800);
  const [randomSeed, setRandomSeed] = useState<number>(42);
  const [uploadedCsvText, setUploadedCsvText] = useState<string | null>(null);
  const [uploadedCsvName, setUploadedCsvName] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [runSuccessMsg, setRunSuccessMsg] = useState<string | null>(null);
  const [plotCacheBust, setPlotCacheBust] = useState<number>(Date.now());
  const [failedImages, setFailedImages] = useState<Record<string, boolean>>({});

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setUploadedCsvText(null);
      setUploadedCsvName(null);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setUploadedCsvText(typeof reader.result === 'string' ? reader.result : null);
      setUploadedCsvName(file.name);
    };
    reader.readAsText(file);
  };

  const handleExecutePipeline = async (e: React.FormEvent) => {
    e.preventDefault();
    setRunError(null);
    setRunSuccessMsg(null);

    if (sampleSize < 100 || sampleSize > 100000) {
      setRunError('Sample size must be between 100 and 100,000 rows for laptop memory safety.');
      return;
    }

    setIsRunning(true);
    try {
      const response = await fetch('/api/run-pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sampleSize,
          seed: randomSeed,
          csvContent: uploadedCsvText,
          csvFileName: uploadedCsvName,
        }),
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Pipeline execution failed');
      }
      onRefreshState(data.state);
      setPlotCacheBust(Date.now());
      setRunSuccessMsg(
        uploadedCsvName
          ? `Successfully trained and evaluated pipeline on uploaded CSV (${uploadedCsvName}) and updated HemlataKumawat_ProjectReport.docx.`
          : `Successfully ran pipeline verification (Sample Size: ${sampleSize.toLocaleString()}, Seed: ${randomSeed}) and updated all artifacts.`
      );
    } catch (err: any) {
      setRunError(err?.message || 'Error running Python pipeline');
    } finally {
      setIsRunning(false);
    }
  };

  if (!metrics) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-8 text-center">
        <Database className="w-10 h-10 text-slate-400 mx-auto mb-3" />
        <h2 className="text-lg font-semibold text-slate-900 mb-2">
          Awaiting Pipeline Execution
        </h2>
        <p className="text-sm text-slate-600 max-w-xl mx-auto mb-6">
          No evaluation metrics found in outputs/evaluation_metrics.json yet. Click the button
          below to execute HemlataKumawat_NetworkIntrusionDetection.py and generate all models, charts,
          and report sections.
        </p>
        <button
          type="button"
          onClick={handleExecutePipeline}
          disabled={isRunning}
          className="px-4 py-2 text-sm font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors"
        >
          {isRunning ? 'Executing Pipeline...' : 'Run Pipeline Verification'}
        </button>
      </div>
    );
  }

  const selectedModelName = metrics.selected_model;
  const bestModel = metrics.models[selectedModelName] || Object.values(metrics.models)[0];
  const modelList = Object.values(metrics.models);
  const cleaning = metrics.cleaning_summary;

  const plotCards = [
    {
      id: 'model_comparison.png',
      title: 'Model Performance Comparison (Held-Out Test Set)',
      description:
        'Side-by-side comparison of Decision Tree and Random Forest across Accuracy, Precision, Recall, and F1-Score.',
    },
    {
      id: 'confusion_matrix.png',
      title: 'Confusion Matrix Breakdown (TN, FP, FN, TP)',
      description:
        'Annotated 2x2 matrix showing benign traffic accurately cleared (TN), false alarms (FP), missed attacks (FN), and caught attacks (TP).',
    },
    {
      id: 'class_distribution.png',
      title: 'Network Flow Class Distribution',
      description:
        'Binary balance between BENIGN (0) and MALICIOUS (1) records in the evaluated dataset.',
    },
    {
      id: 'feature_correlation.png',
      title: 'Network Flow Feature Correlation Heatmap',
      description:
        'Pearson correlation matrix across usable numerical network-flow telemetry features.',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Hero & Pipeline Execution Control Bar */}
      <section className="bg-white border border-slate-200 rounded-xl p-6 lg:p-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          <div className="lg:col-span-7 flex flex-col justify-between space-y-4">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
                <span>IBM SkillsBuild Cyber Security Bootcamp 2026</span>
                <span aria-hidden="true">·</span>
                <span>BharatCares (CSRBOX Group)</span>
                <span aria-hidden="true">·</span>
                <span className="font-semibold text-slate-800">Student: Hemlata Kumawat (BCA)</span>
              </div>

              <h1
                className="text-2xl lg:text-3xl font-bold text-slate-900 tracking-tight"
                style={{ textWrap: 'balance' }}
              >
                ML-Based Network Intrusion Detection System Using CIC-IDS2017
              </h1>

              <p className="text-sm text-slate-600 leading-relaxed max-w-2xl">
                Supervised binary network-flow classification pipeline implemented in Python 3
                (<code className="text-xs font-mono bg-slate-100 px-1.5 py-0.5 rounded">HemlataKumawat_NetworkIntrusionDetection.py</code>).
                Normalizes CIC-IDS2017 flow headers, handles missing and infinite packet rates,
                prevents target and test-set leakage using scikit-learn Pipelines, and evaluates
                Decision Tree and Random Forest classifiers.
              </p>
            </div>

            {/* Explicit Data Source Integrity Banner */}
            <div
              className={`p-4 rounded-lg border ${
                metrics.is_synthetic_demo
                  ? 'bg-amber-50/70 border-amber-200 text-amber-950'
                  : 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
              }`}
            >
              <div className="flex items-start gap-3">
                {metrics.is_synthetic_demo ? (
                  <AlertTriangle className="w-5 h-5 text-amber-700 shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-700 shrink-0 mt-0.5" />
                )}
                <div className="space-y-1 text-xs leading-relaxed">
                  <p className="font-semibold">
                    Active Dataset Mode:{' '}
                    {metrics.is_synthetic_demo
                      ? 'Explicit Synthetic Demo Mode (Pipeline Verification)'
                      : 'Supplied CIC-IDS2017 CSV Dataset'}
                  </p>
                  <p>{metrics.synthetic_disclaimer}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Interactive Pipeline Re-Run / CSV Upload Form */}
          <div className="lg:col-span-5 bg-slate-50 border border-slate-200 rounded-lg p-5 flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 mb-1">
                Execute Python ML Pipeline
              </h2>
              <p className="text-xs text-slate-600 mb-4">
                Run in synthetic demo verification mode or upload a labeled CIC-IDS2017 CSV file
                to recompute all models, charts, and the Word report.
              </p>

              <form onSubmit={handleExecutePipeline} className="space-y-3.5">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label
                      htmlFor="sample-size-input"
                      className="block text-xs font-medium text-slate-700 mb-1"
                    >
                      Sample Row Limit
                    </label>
                    <input
                      id="sample-size-input"
                      type="number"
                      min={300}
                      max={100000}
                      step={500}
                      value={sampleSize}
                      onChange={(e) => setSampleSize(Number(e.target.value))}
                      className="w-full px-3 py-1.5 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-slate-900"
                    />
                  </div>
                  <div>
                    <label
                      htmlFor="random-seed-input"
                      className="block text-xs font-medium text-slate-700 mb-1"
                    >
                      Random Seed
                    </label>
                    <input
                      id="random-seed-input"
                      type="number"
                      value={randomSeed}
                      onChange={(e) => setRandomSeed(Number(e.target.value))}
                      className="w-full px-3 py-1.5 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-slate-900"
                    />
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="cicids-csv-upload"
                    className="block text-xs font-medium text-slate-700 mb-1"
                  >
                    Optional CIC-IDS2017 CSV File (Leave blank for Demo Mode)
                  </label>
                  <input
                    id="cicids-csv-upload"
                    type="file"
                    accept=".csv"
                    onChange={handleFileChange}
                    className="w-full text-xs text-slate-600 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-slate-300 file:text-xs file:font-medium file:bg-white file:text-slate-700 hover:file:bg-slate-100"
                  />
                  {uploadedCsvName && (
                    <p className="text-xs text-emerald-700 mt-1 font-mono">
                      Loaded CSV: {uploadedCsvName}
                    </p>
                  )}
                </div>

                {runError && (
                  <p className="text-xs text-red-700 bg-red-50 border border-red-200 rounded p-2">
                    {runError}
                  </p>
                )}
                {runSuccessMsg && (
                  <p className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded p-2">
                    {runSuccessMsg}
                  </p>
                )}

                <div className="flex items-center gap-2 pt-1">
                  <button
                    type="submit"
                    disabled={isRunning}
                    className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 disabled:opacity-50 transition-colors whitespace-nowrap"
                  >
                    {isRunning ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Running Python Pipeline...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5" />
                        <span>
                          {uploadedCsvName ? 'Train on Uploaded CSV' : 'Run Pipeline (Demo Mode)'}
                        </span>
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => onNavigateTab('predictor')}
                    className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-100 transition-colors whitespace-nowrap"
                  >
                    Test Flow Predictor
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>

        {/* Full-Width 4-Column KPI Strip Below Hero Split */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-200">
          <div className="p-4 bg-slate-50 rounded-lg border border-slate-200/80">
            <div className="text-xs text-slate-500 mb-1">
              Selected Best Model · Primary Metric
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-base font-bold text-slate-900 whitespace-nowrap">
                {selectedModelName}
              </span>
              <span className="text-base font-mono font-semibold text-emerald-700 tabular-nums whitespace-nowrap">
                F1: {(bestModel.f1_score * 100).toFixed(2)}%
              </span>
            </div>
            <div className="text-xs text-slate-600 mt-1 font-mono tabular-nums">
              Accuracy: {(bestModel.accuracy * 100).toFixed(2)}% · Train: {bestModel.training_time_seconds}s
            </div>
          </div>

          <div className="p-4 bg-slate-50 rounded-lg border border-slate-200/80">
            <div className="text-xs text-slate-500 mb-1">
              Attack Detection Recall · ROC-AUC
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-lg font-mono font-bold text-slate-900 tabular-nums">
                {(bestModel.recall * 100).toFixed(2)}%
              </span>
              <span className="text-sm font-mono font-medium text-slate-700 tabular-nums">
                AUC: {bestModel.roc_auc !== null ? bestModel.roc_auc.toFixed(4) : 'N/A'}
              </span>
            </div>
            <div className="text-xs text-slate-600 mt-1 font-mono tabular-nums">
              Caught {bestModel.confusion_matrix.true_positives_detected_attack.toLocaleString()} /{' '}
              {(
                bestModel.confusion_matrix.true_positives_detected_attack +
                bestModel.confusion_matrix.false_negatives_missed_attack
              ).toLocaleString()}{' '}
              test attacks
            </div>
          </div>

          <div className="p-4 bg-slate-50 rounded-lg border border-slate-200/80">
            <div className="text-xs text-slate-500 mb-1">
              Alert Precision · False Positives (FP)
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-lg font-mono font-bold text-slate-900 tabular-nums">
                {(bestModel.precision * 100).toFixed(2)}%
              </span>
              <span className="text-sm font-mono font-medium text-amber-700 tabular-nums">
                FP: {bestModel.false_positive_count}
              </span>
            </div>
            <div className="text-xs text-slate-600 mt-1 font-mono tabular-nums">
              False Positive Rate: {(bestModel.false_positive_rate * 100).toFixed(2)}% · FN:{' '}
              {bestModel.false_negative_count}
            </div>
          </div>

          <div className="p-4 bg-slate-50 rounded-lg border border-slate-200/80">
            <div className="text-xs text-slate-500 mb-1">
              Dataset Rows & Hygiene Audit
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-lg font-mono font-bold text-slate-900 tabular-nums">
                {cleaning.rows_retained.toLocaleString()} rows
              </span>
              <span className="text-sm font-mono font-medium text-slate-700 tabular-nums">
                {metrics.feature_count} features
              </span>
            </div>
            <div className="text-xs text-slate-600 mt-1 font-mono tabular-nums">
              Imputed {cleaning.missing_values_handled} NaN & {cleaning.infinite_values_handled} Inf
            </div>
          </div>
        </div>
      </section>

      {/* Model Comparison Table & Cybersecurity Metric Rationale */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-6">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                01. Comparative Model Evaluation on Held-Out Test Set
              </h2>
              <p className="text-xs text-slate-600 mt-0.5">
                Stratified 80/20 split ({metrics.train_row_count.toLocaleString()} train rows ·{' '}
                {metrics.test_row_count.toLocaleString()} test rows · Positive Class = 1 / MALICIOUS)
              </p>
            </div>
            <a
              href="/api/download/outputs/evaluation_metrics.json"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Metrics JSON</span>
            </a>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-xs font-semibold text-slate-600">
                  <th className="py-2.5 pr-3">Classifier Pipeline</th>
                  <th className="py-2.5 px-2 text-right">Accuracy</th>
                  <th className="py-2.5 px-2 text-right">Precision</th>
                  <th className="py-2.5 px-2 text-right">Recall</th>
                  <th className="py-2.5 px-2 text-right">F1-Score</th>
                  <th className="py-2.5 px-2 text-right">ROC-AUC</th>
                  <th className="py-2.5 px-2 text-right">FP</th>
                  <th className="py-2.5 pl-2 text-right">FN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm font-mono tabular-nums">
                {modelList.map((m) => {
                  const isBest = m.model_name === selectedModelName;
                  return (
                    <tr
                      key={m.model_name}
                      className={isBest ? 'bg-emerald-50/50 font-medium' : 'hover:bg-slate-50'}
                    >
                      <td className="py-3 pr-3 font-sans">
                        <span className="font-semibold text-slate-900">{m.model_name}</span>
                        {isBest && (
                          <span className="ml-2 text-xs text-emerald-800 font-medium">
                            · Selected
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-2 text-right">{(m.accuracy * 100).toFixed(2)}%</td>
                      <td className="py-3 px-2 text-right">{(m.precision * 100).toFixed(2)}%</td>
                      <td className="py-3 px-2 text-right">{(m.recall * 100).toFixed(2)}%</td>
                      <td className="py-3 px-2 text-right font-bold text-slate-900">
                        {(m.f1_score * 100).toFixed(2)}%
                      </td>
                      <td className="py-3 px-2 text-right">
                        {m.roc_auc !== null ? m.roc_auc.toFixed(4) : 'N/A'}
                      </td>
                      <td className="py-3 px-2 text-right text-amber-700">
                        {m.false_positive_count}
                      </td>
                      <td className="py-3 pl-2 text-right text-red-700">
                        {m.false_negative_count}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-200 space-y-2 text-xs text-slate-600 leading-relaxed">
            <p>
              <strong className="text-slate-900">Model Selection Justification:</strong>{' '}
              {metrics.selection_reasoning}
            </p>
            <p>
              <strong className="text-slate-900">Leak-Free Pipeline Guarantee:</strong>{' '}
              <code className="font-mono">SimpleImputer(strategy=&quot;median&quot;)</code>,{' '}
              <code className="font-mono">VarianceThreshold(0.0)</code>, and{' '}
              <code className="font-mono">StandardScaler()</code> are fitted strictly on the{' '}
              {metrics.train_row_count.toLocaleString()} training rows inside{' '}
              <code className="font-mono">sklearn.pipeline.Pipeline</code>. Target column{' '}
              <code className="font-mono">&apos;{cleaning.detected_label_column}&apos;</code> is
              excluded prior to feature matrix construction.
            </p>
          </div>
        </div>

        {/* Confusion Matrix & FP/FN Security Consequences */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-6 flex flex-col justify-between space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 mb-1">
              02. Security Error Analysis ({selectedModelName})
            </h2>
            <p className="text-xs text-slate-600 mb-4">
              Why Accuracy Alone Is Insufficient &amp; Operational Impact of FP vs. FN
            </p>

            {/* 2x2 Numeric Confusion Matrix Grid */}
            <div className="grid grid-cols-2 gap-3 mb-4 font-mono tabular-nums">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                <div className="text-xs font-sans text-slate-500">
                  True Negatives (TN · Benign Cleared)
                </div>
                <div className="text-xl font-bold text-slate-900 mt-0.5">
                  {bestModel.confusion_matrix.true_negatives_benign.toLocaleString()}
                </div>
              </div>
              <div className="p-3 bg-amber-50/60 border border-amber-200 rounded-lg">
                <div className="text-xs font-sans text-amber-900">
                  False Positives (FP · False Alarm)
                </div>
                <div className="text-xl font-bold text-amber-800 mt-0.5">
                  {bestModel.confusion_matrix.false_positives_false_alarm.toLocaleString()}{' '}
                  <span className="text-xs font-normal">
                    ({(bestModel.false_positive_rate * 100).toFixed(2)}% FPR)
                  </span>
                </div>
              </div>
              <div className="p-3 bg-red-50/60 border border-red-200 rounded-lg">
                <div className="text-xs font-sans text-red-900">
                  False Negatives (FN · Missed Attack)
                </div>
                <div className="text-xl font-bold text-red-800 mt-0.5">
                  {bestModel.confusion_matrix.false_negatives_missed_attack.toLocaleString()}{' '}
                  <span className="text-xs font-normal">
                    ({(bestModel.false_negative_rate * 100).toFixed(2)}% FNR)
                  </span>
                </div>
              </div>
              <div className="p-3 bg-emerald-50/60 border border-emerald-200 rounded-lg">
                <div className="text-xs font-sans text-emerald-900">
                  True Positives (TP · Attack Caught)
                </div>
                <div className="text-xl font-bold text-emerald-800 mt-0.5">
                  {bestModel.confusion_matrix.true_positives_detected_attack.toLocaleString()}
                </div>
              </div>
            </div>

            <div className="space-y-2.5 text-xs text-slate-600 leading-relaxed">
              <p>
                <strong className="text-slate-900">The Accuracy Paradox:</strong>{' '}
                {metrics.why_accuracy_is_insufficient}
              </p>
              <p>
                <strong className="text-slate-900">False Positives (FP) vs. False Negatives (FN):</strong>{' '}
                {metrics.false_positive_vs_false_negative_analysis.false_negative_consequences}{' '}
                Conversely, False Positives cause SOC analyst alert fatigue.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Dataset Hygiene & Top Feature Importances */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-1">
            03. Dataset Hygiene &amp; Preprocessing Audit
          </h2>
          <p className="text-xs text-slate-600 mb-4">
            Automated handling of CIC-IDS2017 column anomalies, missing values, and class balance
          </p>

          <dl className="divide-y divide-slate-200 text-xs">
            <div className="py-2.5 flex justify-between gap-4">
              <dt className="text-slate-600">Original Rows Scanned / Retained</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                {cleaning.original_row_count.toLocaleString()} scanned ·{' '}
                {cleaning.rows_retained.toLocaleString()} retained ({cleaning.retention_rate_percent}%)
              </dd>
            </div>
            <div className="py-2.5 flex justify-between gap-4">
              <dt className="text-slate-600">Detected Target Column (Excluded from X)</dt>
              <dd className="font-mono font-medium text-slate-900">
                &quot;{cleaning.detected_label_column}&quot;
              </dd>
            </div>
            <div className="py-2.5 flex justify-between gap-4">
              <dt className="text-slate-600">Binary Class Distribution</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                BENIGN: {cleaning.binary_class_distribution.BENIGN.toLocaleString()} (
                {cleaning.binary_class_distribution.benign_percent}%) · MALICIOUS:{' '}
                {cleaning.binary_class_distribution.MALICIOUS.toLocaleString()} (
                {cleaning.binary_class_distribution.malicious_percent}%)
              </dd>
            </div>
            <div className="py-2.5 flex justify-between gap-4">
              <dt className="text-slate-600">Missing (NaN) &amp; Infinite (Inf) Cells Imputed</dt>
              <dd className="font-mono font-medium text-slate-900 tabular-nums">
                {cleaning.missing_values_handled.toLocaleString()} NaN ·{' '}
                {cleaning.infinite_values_handled.toLocaleString()} Inf
              </dd>
            </div>
            <div className="py-2.5 flex justify-between gap-4">
              <dt className="text-slate-600">Constant / Zero-Variance Features Dropped</dt>
              <dd className="font-mono font-medium text-slate-900">
                {cleaning.constant_columns_removed.length > 0
                  ? cleaning.constant_columns_removed.join(', ')
                  : 'None'}
              </dd>
            </div>
          </dl>

          {/* Attack Category Breakdown */}
          <div className="mt-4 pt-4 border-t border-slate-200">
            <h3 className="text-xs font-semibold text-slate-900 mb-2">
              Traffic Category Breakdown in Dataset
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-xs tabular-nums">
              {Object.entries(cleaning.attack_category_distribution).map(([cat, count]) => (
                <div
                  key={cat}
                  className="px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded flex items-center justify-between gap-2"
                >
                  <span className="font-sans text-slate-700 truncate" title={cat}>
                    {cat}
                  </span>
                  <span className="font-semibold text-slate-900">{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-1">
            04. Top Predictive Network-Flow Features ({selectedModelName})
          </h2>
          <p className="text-xs text-slate-600 mb-4">
            Relative Gini importance scores learned strictly from the training partition
          </p>

          <div className="space-y-2.5">
            {metrics.top_feature_importances.slice(0, 10).map((item, idx) => {
              const maxImp = Math.max(
                metrics.top_feature_importances[0]?.importance || 0.1,
                0.01
              );
              const widthPct = Math.min(100, Math.round((item.importance / maxImp) * 100));
              return (
                <div key={item.feature} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium text-slate-800">
                      {idx + 1}. {item.feature}
                    </span>
                    <span className="font-mono text-slate-600 tabular-nums">
                      {(item.importance * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-slate-800 rounded-full"
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Generated Exploratory Data Analysis & Evaluation Visualizations */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              05. Generated Exploratory Data Analysis &amp; Evaluation Visualizations
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Publication-ready PNG plots saved in <code className="font-mono">outputs/</code> and
              automatically embedded into <code className="font-mono">YourName_ProjectReport.docx</code>
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {plotCards.map((plot) => (
            <div
              key={plot.id}
              className="border border-slate-200 rounded-lg overflow-hidden flex flex-col justify-between bg-slate-50/40"
            >
              <div className="p-4 border-b border-slate-200 bg-white flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">{plot.title}</h3>
                  <p className="text-xs text-slate-600 mt-0.5">{plot.description}</p>
                </div>
                <a
                  href={`/api/download/outputs/${plot.id}`}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 rounded hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>PNG</span>
                </a>
              </div>

              <div className="p-4 flex items-center justify-center bg-white min-h-[260px]">
                {!failedImages[plot.id] ? (
                  <img
                    src={`/api/plots/${plot.id}?t=${plotCacheBust}`}
                    alt={plot.title}
                    referrerPolicy="no-referrer"
                    onError={() =>
                      setFailedImages((prev) => ({ ...prev, [plot.id]: true }))
                    }
                    className="max-h-[340px] w-auto object-contain rounded"
                  />
                ) : (
                  <div className="text-center p-6 text-slate-500">
                    <BarChart3 className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                    <p className="text-xs font-medium">{plot.id}</p>
                    <p className="text-xs mt-1">Run the pipeline above to generate this chart.</p>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
