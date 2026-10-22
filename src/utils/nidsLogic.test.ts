import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeConfusionMatrixRates,
  FLOW_PRESETS,
  formatBytes,
  validateFlowFeatureInput,
} from './nidsLogic';

test('validateFlowFeatureInput accepts valid numeric flow presets', () => {
  const preset = FLOW_PRESETS.benign_https.values;
  const required = Object.keys(preset);
  const res = validateFlowFeatureInput(preset, required);
  assert.equal(res.valid, true);
  assert.equal(res.errors.length, 0);
  assert.equal(res.cleanedFeatures['Destination Port'], 443);
});

test('validateFlowFeatureInput rejects empty, non-numeric, or out-of-range ports', () => {
  const base = { ...FLOW_PRESETS.benign_https.values };
  const required = Object.keys(base);

  const badInput = {
    ...base,
    'Destination Port': 99999,
    'Flow Duration': 'invalid_number',
    'Total Fwd Packets': '',
  };

  const res = validateFlowFeatureInput(badInput, required);
  assert.equal(res.valid, false);
  assert.equal(res.errors.length, 3);
});

test('computeConfusionMatrixRates calculates precision, recall, F1, FPR, and FNR accurately', () => {
  const rates = computeConfusionMatrixRates(540, 35, 59, 166);
  assert.equal(rates.total, 800);
  assert.equal(rates.accuracy, 0.8825);
  assert.equal(rates.precision, 0.8259);
  assert.equal(rates.recall, 0.7378);
  assert.equal(rates.f1Score, 0.7793);
});

test('formatBytes formats byte counts cleanly', () => {
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(713875), '697.1 KB');
  assert.equal(formatBytes(3373666), '3.22 MB');
});
