import React, { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { ProjectStatePayload } from '../types';
import {
  FLOW_PRESETS,
  KEY_INTERACTIVE_FEATURES,
  validateFlowFeatureInput,
} from '../utils/nidsLogic';

interface FlowPredictorTabProps {
  projectState: ProjectStatePayload;
}

export const FlowPredictorTab: React.FC<FlowPredictorTabProps> = ({ projectState }) => {
  const [activePresetKey, setActivePresetKey] = useState<string>('benign_https');
  const [featureValues, setFeatureValues] = useState<Record<string, string | number>>({
    ...FLOW_PRESETS.benign_https.values,
  });
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [predictionResult, setPredictionResult] = useState<any | null>(null);
  const [isPredicting, setIsPredicting] = useState<boolean>(false);
  const [batchCsvContent, setBatchCsvContent] = useState<string | null>(null);
  const [batchCsvName, setBatchCsvName] = useState<string | null>(null);
  const [batchSummary, setBatchSummary] = useState<any | null>(null);

  const requiredFeatures =
    projectState.featureSchema?.required_features ||
    Object.keys(FLOW_PRESETS.benign_https.values);

  const applyPreset = (presetKey: string) => {
    const preset = FLOW_PRESETS[presetKey];
    if (!preset) return;
    setActivePresetKey(presetKey);
    setFeatureValues({ ...preset.values });
    setValidationErrors([]);
  };

  const handleFeatureChange = (featureName: string, rawVal: string) => {
    setFeatureValues((prev) => ({
      ...prev,
      [featureName]: rawVal,
    }));
  };

  const handleEvaluateSingleFlow = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationErrors([]);

    // Fill any unexposed schema features with training medians or preset defaults
    const completeInput: Record<string, string | number> = {
      ...FLOW_PRESETS.benign_https.values,
      ...(projectState.featureSchema?.training_feature_medians || {}),
      ...featureValues,
    };

    const validation = validateFlowFeatureInput(completeInput, requiredFeatures);
    if (!validation.valid) {
      setValidationErrors(validation.errors);
      return;
    }

    setIsPredicting(true);
    try {
      const response = await fetch('/api/predict-flow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flowRecord: validation.cleanedFeatures }),
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Flow evaluation failed');
      }
      setPredictionResult(data.result);
    } catch (err: any) {
      setValidationErrors([err?.message || 'Prediction request failed']);
    } finally {
      setIsPredicting(false);
    }
  };

  const handleBatchCsvUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) {
      setBatchCsvContent(null);
      setBatchCsvName(null);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setBatchCsvContent(typeof reader.result === 'string' ? reader.result : null);
      setBatchCsvName(file.name);
    };
    reader.readAsText(file);
  };

  const handleRunBatchPrediction = async () => {
    if (!batchCsvContent) return;
    setIsPredicting(true);
    setValidationErrors([]);
    try {
      const response = await fetch('/api/predict-flow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csvContent: batchCsvContent }),
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Batch CSV prediction failed');
      }
      setBatchSummary(data.result);
    } catch (err: any) {
      setValidationErrors([err?.message || 'Batch CSV validation error']);
    } finally {
      setIsPredicting(false);
    }
  };

  const singleRowPred = predictionResult?.predictions?.[0] || null;

  return (
    <div className="space-y-8">
      {/* Header & Preset Selector */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-slate-200">
          <div>
            <h1 className="text-xl font-bold text-slate-900">
              Interactive Network-Flow Intrusion Predictor
            </h1>
            <p className="text-xs text-slate-600 mt-1">
              Evaluates network-flow telemetry against the trained scikit-learn pipeline (
              <code className="font-mono">outputs/model.joblib</code>) and validates feature
              alignment against <code className="font-mono">outputs/feature_schema.json</code>.
            </p>
          </div>

          {/* Preset Segmented Control */}
          <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-100 rounded-lg">
            {Object.entries(FLOW_PRESETS).map(([key, preset]) => (
              <button
                key={key}
                type="button"
                onClick={() => applyPreset(key)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activePresetKey === key
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {preset.title}
              </button>
            ))}
          </div>
        </div>

        {/* Single-Flow Form & Live Model Output */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 pt-6">
          <form onSubmit={handleEvaluateSingleFlow} className="lg:col-span-7 space-y-5">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                Network Flow Telemetry Parameters (12 Key CIC-IDS2017 Features)
              </h2>
              <button
                type="button"
                onClick={() => applyPreset(activePresetKey)}
                className="inline-flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset to Preset</span>
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {KEY_INTERACTIVE_FEATURES.map((feat) => (
                <div key={feat.name} className="space-y-1">
                  <label
                    htmlFor={`feat-${feat.name}`}
                    className="block text-xs font-medium text-slate-700"
                    title={feat.description}
                  >
                    {feat.label}{' '}
                    <span className="text-slate-400 font-normal">({feat.unit})</span>
                  </label>
                  <input
                    id={`feat-${feat.name}`}
                    type="text"
                    value={featureValues[feat.name] ?? ''}
                    onChange={(e) => handleFeatureChange(feat.name, e.target.value)}
                    className="w-full px-3 py-1.5 text-sm font-mono tabular-nums bg-slate-50 border border-slate-300 rounded-md focus:bg-white focus:outline-none focus:ring-2 focus:ring-slate-900"
                  />
                </div>
              ))}
            </div>

            {validationErrors.length > 0 && (
              <div
                role="alert"
                className="p-3.5 bg-red-50 border border-red-200 rounded-lg text-xs text-red-900 space-y-1"
              >
                <div className="font-semibold flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 text-red-700 shrink-0" />
                  <span>Input Feature Schema Validation Error:</span>
                </div>
                <ul className="list-disc list-inside space-y-0.5 pl-1">
                  {validationErrors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex items-center gap-3 pt-2">
              <button
                type="submit"
                disabled={isPredicting}
                className="inline-flex items-center gap-2 px-5 py-2.5 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 disabled:opacity-50 transition-colors whitespace-nowrap"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{isPredicting ? 'Evaluating Flow...' : 'Evaluate Network Flow'}</span>
              </button>
              <span className="text-xs text-slate-500">
                Remaining 12 flow features default to training-set medians
              </span>
            </div>
          </form>

          {/* Prediction Result Panel */}
          <div className="lg:col-span-5 bg-slate-50 border border-slate-200 rounded-xl p-6 flex flex-col justify-between space-y-5">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 mb-1">
                Model Classification Output
              </h2>
              <p className="text-xs text-slate-600 mb-4">
                Active Classifier:{' '}
                <span className="font-semibold text-slate-900">
                  {projectState.featureSchema?.selected_model_name || 'Random Forest'}
                </span>
              </p>

              {singleRowPred ? (
                <div className="space-y-4">
                  <div
                    data-testid="prediction-verdict-box"
                    className={`p-5 rounded-lg border ${
                      singleRowPred.predicted_class === 'MALICIOUS'
                        ? 'bg-red-50 border-red-200 text-red-950'
                        : 'bg-emerald-50 border-emerald-200 text-emerald-950'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2.5">
                        {singleRowPred.predicted_class === 'MALICIOUS' ? (
                          <ShieldAlert className="w-6 h-6 text-red-700 shrink-0" />
                        ) : (
                          <ShieldCheck className="w-6 h-6 text-emerald-700 shrink-0" />
                        )}
                        <div>
                          <div className="text-xs font-semibold opacity-80">
                            Predicted Flow Class
                          </div>
                          <div className="text-2xl font-bold font-mono tracking-tight">
                            {singleRowPred.predicted_class}
                          </div>
                        </div>
                      </div>

                      <div className="text-right font-mono tabular-nums">
                        <div className="text-xs opacity-75">Confidence Score</div>
                        <div className="text-xl font-bold">
                          {(singleRowPred.confidence_score * 100).toFixed(2)}%
                        </div>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-black/10 flex items-center justify-between text-xs font-mono tabular-nums">
                      <span>Malicious Probability P(y=1):</span>
                      <span className="font-bold">
                        {(singleRowPred.malicious_probability * 100).toFixed(2)}%
                      </span>
                    </div>
                  </div>

                  <div className="p-3.5 bg-white border border-slate-200 rounded-lg space-y-2 text-xs text-slate-600">
                    <div className="font-semibold text-slate-900">
                      Schema Validation Audit:
                    </div>
                    <ul className="list-disc list-inside space-y-1">
                      {(predictionResult.validation_report?.validation_notes || []).map(
                        (note: string, idx: number) => (
                          <li key={idx}>{note}</li>
                        )
                      )}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="p-8 bg-white border border-slate-200 rounded-lg text-center space-y-2">
                  <p className="text-sm font-medium text-slate-800">
                    Ready to Evaluate Flow Telemetry
                  </p>
                  <p className="text-xs text-slate-500">
                    Select a preset above or modify flow parameters on the left, then click
                    &quot;Evaluate Network Flow&quot; to execute real inference.
                  </p>
                </div>
              )}
            </div>

            {/* Mandatory Operational Disclaimer */}
            <div className="p-3.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-600 leading-relaxed">
              <strong className="text-slate-900">Operational Disclaimer:</strong> This prediction
              is a statistical model estimate based on tabular flow features, not a guarantee of
              network safety. This tool does not capture live packets or block traffic (it is not
              an active Intrusion Prevention System).
            </div>
          </div>
        </div>
      </section>

      {/* Batch CSV Flow Prediction & Saved Predictions Preview */}
      <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Batch CSV Network-Flow Prediction &amp; Output Preview (<code className="font-mono">outputs/predictions.csv</code>)
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Upload any CSV matching the CIC-IDS2017 feature schema or inspect the latest batch
              predictions generated by the pipeline.
            </p>
          </div>
          <a
            href="/api/download/outputs/predictions.csv"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download predictions.csv</span>
          </a>
        </div>

        {/* Batch Upload Bar */}
        <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <FileSpreadsheet className="w-5 h-5 text-slate-600 shrink-0" />
            <div>
              <label
                htmlFor="batch-predict-csv-input"
                className="block text-xs font-semibold text-slate-900"
              >
                Classify a Separate CSV File of Network Flows
              </label>
              <input
                id="batch-predict-csv-input"
                type="file"
                accept=".csv"
                onChange={handleBatchCsvUpload}
                className="mt-1 text-xs text-slate-600 file:mr-3 file:py-1 file:px-2.5 file:rounded file:border file:border-slate-300 file:text-xs file:font-medium file:bg-white file:text-slate-700"
              />
            </div>
          </div>
          <button
            type="button"
            disabled={!batchCsvContent || isPredicting}
            onClick={handleRunBatchPrediction}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 disabled:opacity-40 transition-colors whitespace-nowrap shrink-0"
          >
            Run Batch CSV Prediction
          </button>
        </div>

        {batchSummary && (
          <div className="p-4 bg-emerald-50/70 border border-emerald-200 rounded-lg text-xs text-emerald-950 flex flex-wrap items-center justify-between gap-4">
            <div>
              <strong>Batch Prediction Completed ({batchCsvName}):</strong> Evaluated{' '}
              <span className="font-mono">{batchSummary.total_flows_evaluated}</span> flows ·
              Predicted BENIGN:{' '}
              <span className="font-mono font-bold">{batchSummary.predicted_benign_count}</span> ·
              Predicted MALICIOUS:{' '}
              <span className="font-mono font-bold">{batchSummary.predicted_malicious_count}</span>
            </div>
            <a
              href="/api/download/outputs/predictions.csv"
              className="underline font-semibold"
            >
              Download Updated predictions.csv
            </a>
          </div>
        )}

        {/* Preview Table of outputs/predictions.csv */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold text-slate-600">
                <th className="py-2 pr-3">Row #</th>
                <th className="py-2 px-2">Predicted Class</th>
                <th className="py-2 px-2 text-right">Malicious Prob</th>
                <th className="py-2 px-2 text-right">Confidence</th>
                <th className="py-2 px-2 text-right">Dest Port</th>
                <th className="py-2 px-2 text-right">Flow Duration (μs)</th>
                <th className="py-2 px-2 text-right">Total Fwd Pkts</th>
                <th className="py-2 pl-2">Model Estimate Disclaimer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs font-mono tabular-nums">
              {projectState.samplePredictions.slice(0, 10).map((row, idx) => {
                const isMal = row.Predicted_Class === 'MALICIOUS';
                return (
                  <tr key={idx} className="hover:bg-slate-50">
                    <td className="py-2.5 pr-3 text-slate-500">#{idx + 1}</td>
                    <td className="py-2.5 px-2 font-semibold">
                      <span className={isMal ? 'text-red-700' : 'text-emerald-700'}>
                        {row.Predicted_Class}
                      </span>
                    </td>
                    <td className="py-2.5 px-2 text-right">
                      {(Number(row.Malicious_Probability || 0) * 100).toFixed(2)}%
                    </td>
                    <td className="py-2.5 px-2 text-right">
                      {(Number(row.Confidence_Score || 0) * 100).toFixed(2)}%
                    </td>
                    <td className="py-2.5 px-2 text-right">
                      {Math.round(Number(row['Destination Port'] || 0))}
                    </td>
                    <td className="py-2.5 px-2 text-right">
                      {Math.round(Number(row['Flow Duration'] || 0)).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-2 text-right">
                      {Math.round(Number(row['Total Fwd Packets'] || 0))}
                    </td>
                    <td className="py-2.5 pl-2 font-sans text-slate-500 truncate max-w-xs">
                      {row.Model_Disclaimer}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
