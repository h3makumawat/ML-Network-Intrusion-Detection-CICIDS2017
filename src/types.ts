export interface ConfusionMatrixData {
  true_negatives_benign: number;
  false_positives_false_alarm: number;
  false_negatives_missed_attack: number;
  true_positives_detected_attack: number;
  matrix_2x2: [[number, number], [number, number]];
}

export interface ModelEvaluation {
  model_name: string;
  training_time_seconds: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number | null;
  confusion_matrix: ConfusionMatrixData;
  false_positive_count: number;
  false_negative_count: number;
  false_positive_rate: number;
  false_negative_rate: number;
  classification_report_text: string;
}

export interface CleaningSummary {
  original_row_count: number;
  sampled_row_count: number;
  rows_retained: number;
  rows_dropped_invalid_label: number;
  retention_rate_percent: number;
  initial_column_count: number;
  features_used_count: number;
  feature_names: string[];
  detected_label_column: string;
  duplicate_columns_removed: string[];
  identifier_columns_excluded: string[];
  constant_columns_removed: string[];
  non_numeric_columns_removed: string[];
  missing_values_handled: number;
  infinite_values_handled: number;
  binary_class_distribution: {
    BENIGN: number;
    MALICIOUS: number;
    benign_percent: number;
    malicious_percent: number;
  };
  attack_category_distribution: Record<string, number>;
}

export interface EvaluationMetricsPayload {
  timestamp_utc: string;
  data_source_mode: 'SYNTHETIC_DEMO_DATA' | 'CIC_IDS2017_CSV';
  is_synthetic_demo: boolean;
  synthetic_disclaimer: string;
  positive_class_definition: {
    label_int: number;
    label_name: string;
    explanation: string;
  };
  why_accuracy_is_insufficient: string;
  false_positive_vs_false_negative_analysis: {
    false_positive_consequences: string;
    false_negative_consequences: string;
  };
  train_row_count: number;
  test_row_count: number;
  feature_count: number;
  selected_model: string;
  selection_metric: string;
  selection_reasoning: string;
  models: Record<string, ModelEvaluation>;
  top_feature_importances: Array<{ feature: string; importance: number }>;
  cleaning_summary: CleaningSummary;
}

export interface DeliverableItem {
  filename: string;
  category?: 'mandatory' | 'config';
  description: string;
  exists: boolean;
  sizeBytes: number;
  updatedAt: string | null;
  downloadUrl: string;
}

export interface FeatureSchemaPayload {
  schema_version: string;
  project: string;
  created_at_utc: string;
  data_source_mode: string;
  selected_model_name: string;
  positive_class_label: string;
  feature_count: number;
  required_features: string[];
  training_feature_medians: Record<string, number>;
  training_feature_means: Record<string, number>;
  top_feature_importances: Array<{ feature: string; importance: number }>;
}

export interface ProjectStatePayload {
  evaluationMetrics: EvaluationMetricsPayload | null;
  runSummary: any;
  featureSchema: FeatureSchemaPayload | null;
  classificationReport: string;
  deliverables: DeliverableItem[];
  artifacts: DeliverableItem[];
  samplePredictions: Array<Record<string, string>>;
}
