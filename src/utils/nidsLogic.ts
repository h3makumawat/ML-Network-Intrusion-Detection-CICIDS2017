export interface FlowFeatureInput {
  [key: string]: number | string;
}

export interface FlowValidationResult {
  valid: boolean;
  errors: string[];
  cleanedFeatures: Record<string, number>;
}

export interface ConfusionMatrixRates {
  total: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
}

export const KEY_INTERACTIVE_FEATURES: Array<{
  name: string;
  label: string;
  unit: string;
  min: number;
  max: number;
  step: number;
  description: string;
}> = [
  {
    name: 'Destination Port',
    label: 'Destination Port',
    unit: 'port',
    min: 1,
    max: 65535,
    step: 1,
    description: 'Target TCP/UDP transport port (e.g., 80 HTTP, 443 HTTPS, 22 SSH, 53 DNS)',
  },
  {
    name: 'Flow Duration',
    label: 'Flow Duration',
    unit: 'μs',
    min: 0,
    max: 120000000,
    step: 100,
    description: 'Total bidirectional session duration in microseconds',
  },
  {
    name: 'Total Fwd Packets',
    label: 'Total Fwd Packets',
    unit: 'pkts',
    min: 1,
    max: 5000,
    step: 1,
    description: 'Total packets sent from source client to destination server',
  },
  {
    name: 'Total Backward Packets',
    label: 'Total Backward Packets',
    unit: 'pkts',
    min: 0,
    max: 5000,
    step: 1,
    description: 'Total response packets sent from destination server back to client',
  },
  {
    name: 'Fwd Packet Length Mean',
    label: 'Fwd Packet Length Mean',
    unit: 'bytes',
    min: 0,
    max: 1500,
    step: 1,
    description: 'Average payload size in bytes for forward packets',
  },
  {
    name: 'Bwd Packet Length Mean',
    label: 'Bwd Packet Length Mean',
    unit: 'bytes',
    min: 0,
    max: 1500,
    step: 1,
    description: 'Average payload size in bytes for backward response packets',
  },
  {
    name: 'Flow Bytes/s',
    label: 'Flow Bytes/s',
    unit: 'B/s',
    min: 0,
    max: 50000000,
    step: 100,
    description: 'Overall byte throughput rate per second across the flow',
  },
  {
    name: 'Flow Packets/s',
    label: 'Flow Packets/s',
    unit: 'pkt/s',
    min: 0,
    max: 500000,
    step: 10,
    description: 'Overall packet transmission rate per second',
  },
  {
    name: 'Flow IAT Mean',
    label: 'Flow IAT Mean',
    unit: 'μs',
    min: 0,
    max: 10000000,
    step: 10,
    description: 'Mean Inter-Arrival Time (microseconds) between consecutive packets',
  },
  {
    name: 'SYN Flag Count',
    label: 'SYN Flag Count',
    unit: 'flags',
    min: 0,
    max: 10,
    step: 1,
    description: 'Count of TCP SYN synchronization flags in the flow',
  },
  {
    name: 'RST Flag Count',
    label: 'RST Flag Count',
    unit: 'flags',
    min: 0,
    max: 10,
    step: 1,
    description: 'Count of TCP connection reset (RST) flags',
  },
  {
    name: 'Active Mean',
    label: 'Active Mean',
    unit: 'μs',
    min: 0,
    max: 1000000,
    step: 1,
    description: 'Mean time the flow was actively transmitting before becoming idle',
  },
  {
    name: 'Idle Mean',
    label: 'Idle Mean',
    unit: 'μs',
    min: 0,
    max: 1000000,
    step: 1,
    description: 'Mean time the flow remained idle between active bursts',
  },
];

export const FLOW_PRESETS: Record<
  string,
  { title: string; subtitle: string; category: string; values: Record<string, number> }
> = {
  benign_https: {
    title: 'Normal HTTPS Web Session',
    subtitle: 'Port 443 · Balanced bidirectional packets · Low packet rate',
    category: 'BENIGN Baseline',
    values: {
      'Destination Port': 443,
      'Flow Duration': 2.8,
      'Total Fwd Packets': 14,
      'Total Backward Packets': 12,
      'Total Length of Fwd Packets': 980,
      'Total Length of Bwd Packets': 1840,
      'Fwd Packet Length Max': 512,
      'Fwd Packet Length Mean': 230,
      'Bwd Packet Length Max': 980,
      'Bwd Packet Length Mean': 380,
      'Flow Bytes/s': 362758,
      'Flow Packets/s': 4.8,
      'Flow IAT Mean': 4800,
      'Flow IAT Std': 3100,
      'Flow IAT Max': 14200,
      'Fwd IAT Mean': 5100,
      'Bwd IAT Mean': 5400,
      'Fwd PSH Flags': 0,
      'SYN Flag Count': 0,
      'RST Flag Count': 0,
      'ACK Flag Count': 1,
      'Average Packet Size': 309,
      Init_Win_bytes_forward: 29200,
      'Active Mean': 14.5,
      'Idle Mean': 28.0,
    },
  },
  dos_hulk: {
    title: 'High-Volume DoS Hulk Flood Pattern',
    subtitle: 'Port 80 · High forward packet burst · Elevated flow packet rate',
    category: 'Simulated DoS Pattern',
    values: {
      'Destination Port': 80,
      'Flow Duration': 4.5,
      'Total Fwd Packets': 44,
      'Total Backward Packets': 8,
      'Total Length of Fwd Packets': 3800,
      'Total Length of Bwd Packets': 6400,
      'Fwd Packet Length Max': 1380,
      'Fwd Packet Length Mean': 560,
      'Bwd Packet Length Max': 1460,
      'Bwd Packet Length Mean': 800,
      'Flow Bytes/s': 249523,
      'Flow Packets/s': 16.5,
      'Flow IAT Mean': 920,
      'Flow IAT Std': 850,
      'Flow IAT Max': 3400,
      'Fwd IAT Mean': 890,
      'Bwd IAT Mean': 1120,
      'Fwd PSH Flags': 1,
      'SYN Flag Count': 2,
      'RST Flag Count': 1,
      'ACK Flag Count': 0,
      'Average Packet Size': 616,
      Init_Win_bytes_forward: 256,
      'Active Mean': 18.0,
      'Idle Mean': 32.0,
    },
  },
  port_scan: {
    title: 'Reconnaissance TCP SYN Port Probe',
    subtitle: 'Port 21 · High packet burst · Elevated bytes & packet rate',
    category: 'Simulated Probe Pattern',
    values: {
      'Destination Port': 21,
      'Flow Duration': 5.1,
      'Total Fwd Packets': 39,
      'Total Backward Packets': 2,
      'Total Length of Fwd Packets': 3100,
      'Total Length of Bwd Packets': 1400,
      'Fwd Packet Length Max': 1100,
      'Fwd Packet Length Mean': 500,
      'Bwd Packet Length Max': 900,
      'Bwd Packet Length Mean': 700,
      'Flow Bytes/s': 295238,
      'Flow Packets/s': 14.2,
      'Flow IAT Mean': 750,
      'Flow IAT Std': 600,
      'Flow IAT Max': 2600,
      'Fwd IAT Mean': 710,
      'Bwd IAT Mean': 980,
      'Fwd PSH Flags': 1,
      'SYN Flag Count': 2,
      'RST Flag Count': 1,
      'ACK Flag Count': 0,
      'Average Packet Size': 516,
      Init_Win_bytes_forward: 512,
      'Active Mean': 16.0,
      'Idle Mean': 29.0,
    },
  },
};

/**
 * Validates user-supplied network flow feature values before sending to the model.
 * Ensures no empty strings, NaN, or Infinity values bypass validation.
 */
export function validateFlowFeatureInput(
  rawInput: FlowFeatureInput,
  requiredFeatures: string[]
): FlowValidationResult {
  const errors: string[] = [];
  const cleanedFeatures: Record<string, number> = {};

  for (const featureName of requiredFeatures) {
    const rawVal = rawInput[featureName];
    if (rawVal === undefined || rawVal === null || String(rawVal).trim() === '') {
      errors.push(`Feature "${featureName}" is required and cannot be empty.`);
      continue;
    }

    const parsed = Number(rawVal);
    if (!Number.isFinite(parsed)) {
      errors.push(
        `Feature "${featureName}" must be a finite numeric value (received "${rawVal}").`
      );
      continue;
    }

    if (featureName === 'Destination Port' && (parsed < 0 || parsed > 65535)) {
      errors.push('Destination Port must be between 0 and 65535.');
      continue;
    }

    if (featureName === 'Flow Duration' && parsed < 0) {
      errors.push('Flow Duration cannot be negative.');
      continue;
    }

    cleanedFeatures[featureName] = parsed;
  }

  return {
    valid: errors.length === 0,
    errors,
    cleanedFeatures,
  };
}

/**
 * Computes derived confusion matrix metrics from TN, FP, FN, TP counts.
 */
export function computeConfusionMatrixRates(
  tn: number,
  fp: number,
  fn: number,
  tp: number
): ConfusionMatrixRates {
  const total = Math.max(tn + fp + fn + tp, 1);
  const accuracy = (tp + tn) / total;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1Score =
    precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;
  const falseNegativeRate = fn + tp > 0 ? fn / (fn + tp) : 0;

  return {
    total: tn + fp + fn + tp,
    accuracy: Number(accuracy.toFixed(4)),
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1Score: Number(f1Score.toFixed(4)),
    falsePositiveRate: Number(falsePositiveRate.toFixed(4)),
    falseNegativeRate: Number(falseNegativeRate.toFixed(4)),
  };
}

/**
 * Formats byte size into human-readable KB / MB string.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
