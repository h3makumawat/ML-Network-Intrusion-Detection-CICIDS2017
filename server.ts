import express from 'express';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { createServer as createViteServer } from 'vite';

const execFileAsync = promisify(execFile);
const ROOT_DIR = process.cwd();
const OUTPUTS_DIR = path.join(ROOT_DIR, 'outputs');
const DATA_DIR = path.join(ROOT_DIR, 'data');
const PYTHON_BIN = fs.existsSync(path.join(ROOT_DIR, '.venv', 'bin', 'python'))
  ? path.join(ROOT_DIR, '.venv', 'bin', 'python')
  : 'python3';

const MANDATORY_FILES: Array<{
  filename: string;
  category: 'mandatory' | 'config';
  description: string;
}> = [
  {
    filename: 'HemlataKumawat_NetworkIntrusionDetection.py',
    category: 'mandatory',
    description:
      'Complete runnable Python 3 ML pipeline (CIC-IDS2017 ingestion, BOM/whitespace cleaning, train-only feature filtering, EDA, leak-free pipelines, evaluation, prediction, and DOCX builder).',
  },
  {
    filename: 'requirements.txt',
    category: 'mandatory',
    description:
      'External Python package dependencies with compatible version constraints (pandas, numpy, scikit-learn, matplotlib, seaborn, joblib, python-docx).',
  },
  {
    filename: 'HemlataKumawat_ProjectReport.docx',
    category: 'mandatory',
    description:
      'Polished 30-section Microsoft Word academic project report for Student: Hemlata Kumawat (Branch: BCA) with embedded architecture diagram, EDA charts, and evaluation tables.',
  },
  {
    filename: 'README.md',
    category: 'mandatory',
    description:
      'Complete GitHub-ready project overview for Hemlata Kumawat (BCA), dataset links, virtual environment setup, CLI commands (--demo, --data, --predict), and troubleshooting.',
  },
  {
    filename: '.gitignore',
    category: 'config',
    description:
      'Git ignore rules excluding virtual environments, Python caches, CSV/PCAP datasets, model binaries, and runtime outputs.',
  },
];

const ARTIFACT_FILES: Array<{
  filename: string;
  description: string;
}> = [
  {
    filename: 'model.joblib',
    description: 'Serialized best scikit-learn Pipeline (SimpleImputer + Selected Random Forest Classifier).',
  },
  {
    filename: 'feature_schema.json',
    description: 'Required inference feature column schema, training medians, and top feature importances.',
  },
  {
    filename: 'evaluation_metrics.json',
    description: 'Measured Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix counts.',
  },
  {
    filename: 'classification_report.txt',
    description: 'Detailed text classification report for the selected model.',
  },
  {
    filename: 'confusion_matrix.png',
    description: 'Annotated Confusion Matrix heatmap (TN, FP, FN, TP).',
  },
  {
    filename: 'class_distribution.png',
    description: 'Network flow class distribution chart (BENIGN vs MALICIOUS).',
  },
  {
    filename: 'feature_correlation.png',
    description: 'Pearson correlation heatmap of usable numerical network-flow features.',
  },
  {
    filename: 'model_comparison.png',
    description: 'Grouped bar chart comparing Decision Tree vs Random Forest across 4 metrics.',
  },
  {
    filename: 'system_architecture.png',
    description: 'Five-stage ML Network Intrusion Detection architecture workflow diagram.',
  },
  {
    filename: 'predictions.csv',
    description: 'Batch flow predictions with predicted_class, malicious_probability, and prediction_note.',
  },
  {
    filename: 'run_summary.json',
    description: 'Execution audit log recording status, selected model, and generated output files.',
  },
];

function readJsonSafe(filePath: string): any {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    }
  } catch (err) {
    console.error(`Failed to parse JSON at ${filePath}:`, err);
  }
  return null;
}

function parsePredictionsPreview(csvPath: string, limit = 25): Array<Record<string, string>> {
  try {
    if (!fs.existsSync(csvPath)) return [];
    const content = fs.readFileSync(csvPath, 'utf-8');
    const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
    if (lines.length < 2) return [];
    const headers = lines[0].split(',');
    const rows: Array<Record<string, string>> = [];
    for (let i = 1; i < Math.min(lines.length, limit + 1); i++) {
      const cols = lines[i].split(',');
      const rowObj: Record<string, string> = {};
      headers.forEach((h, idx) => {
        rowObj[h.trim()] = cols[idx] ?? '';
      });
      rows.push(rowObj);
    }
    return rows;
  } catch (err) {
    console.error('Error parsing predictions preview:', err);
    return [];
  }
}

function buildProjectState() {
  const evaluationMetrics = readJsonSafe(path.join(OUTPUTS_DIR, 'evaluation_metrics.json'));
  const runSummary = readJsonSafe(path.join(OUTPUTS_DIR, 'run_summary.json'));
  const featureSchema = readJsonSafe(path.join(OUTPUTS_DIR, 'feature_schema.json'));
  const classificationReportPath = path.join(OUTPUTS_DIR, 'classification_report.txt');
  const classificationReport = fs.existsSync(classificationReportPath)
    ? fs.readFileSync(classificationReportPath, 'utf-8')
    : '';

  const deliverables = MANDATORY_FILES.map((item) => {
    const fullPath = path.join(ROOT_DIR, item.filename);
    const exists = fs.existsSync(fullPath);
    const stat = exists ? fs.statSync(fullPath) : null;
    return {
      ...item,
      exists,
      sizeBytes: stat ? stat.size : 0,
      updatedAt: stat ? stat.mtime.toISOString() : null,
      downloadUrl: `/api/download/${encodeURIComponent(item.filename)}`,
    };
  });

  const artifacts = ARTIFACT_FILES.map((item) => {
    const fullPath = path.join(OUTPUTS_DIR, item.filename);
    const exists = fs.existsSync(fullPath);
    const stat = exists ? fs.statSync(fullPath) : null;
    return {
      ...item,
      exists,
      sizeBytes: stat ? stat.size : 0,
      updatedAt: stat ? stat.mtime.toISOString() : null,
      downloadUrl: `/api/download/outputs/${encodeURIComponent(item.filename)}`,
    };
  });

  const samplePredictions = parsePredictionsPreview(path.join(OUTPUTS_DIR, 'predictions.csv'), 20);

  return {
    evaluationMetrics,
    runSummary,
    featureSchema,
    classificationReport,
    deliverables,
    artifacts,
    samplePredictions,
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '50mb' }));

  // 1. Get complete project state, metrics, schema, deliverables, and artifacts
  app.get('/api/status', (_req, res) => {
    res.json(buildProjectState());
  });

  // 2. Inspect source text of mandatory files
  app.get('/api/source/:filename', (req, res) => {
    const allowedTextFiles: Record<string, string> = {
      'HemlataKumawat_NetworkIntrusionDetection.py': path.join(
        ROOT_DIR,
        'HemlataKumawat_NetworkIntrusionDetection.py'
      ),
      'YourName_NetworkIntrusionDetection.py': path.join(
        ROOT_DIR,
        'HemlataKumawat_NetworkIntrusionDetection.py'
      ),
      'requirements.txt': path.join(ROOT_DIR, 'requirements.txt'),
      'README.md': path.join(ROOT_DIR, 'README.md'),
      '.gitignore': path.join(ROOT_DIR, '.gitignore'),
      'classification_report.txt': path.join(OUTPUTS_DIR, 'classification_report.txt'),
      'feature_schema.json': path.join(OUTPUTS_DIR, 'feature_schema.json'),
      'evaluation_metrics.json': path.join(OUTPUTS_DIR, 'evaluation_metrics.json'),
      'run_summary.json': path.join(OUTPUTS_DIR, 'run_summary.json'),
    };

    const target = allowedTextFiles[req.params.filename];
    if (!target || !fs.existsSync(target)) {
      res.status(404).json({ error: `File ${req.params.filename} not found.` });
      return;
    }

    res.type('text/plain; charset=utf-8').send(fs.readFileSync(target, 'utf-8'));
  });

  // 3. Download root mandatory deliverables
  app.get('/api/download/:filename', (req, res) => {
    const allowedRootFiles = new Set([
      'HemlataKumawat_NetworkIntrusionDetection.py',
      'HemlataKumawat_ProjectReport.docx',
      'YourName_NetworkIntrusionDetection.py',
      'YourName_ProjectName.py',
      'requirements.txt',
      'YourName_ProjectReport.docx',
      'README.md',
      '.gitignore',
    ]);
    const fname = req.params.filename;
    if (!allowedRootFiles.has(fname)) {
      res.status(404).json({ error: 'Requested deliverable not in allowed root list.' });
      return;
    }
    const filePath = path.join(ROOT_DIR, fname);
    if (!fs.existsSync(filePath)) {
      res.status(404).json({ error: 'File does not exist yet.' });
      return;
    }
    res.download(filePath, fname);
  });

  // 4. Download generated artifacts from outputs/
  app.get('/api/download/outputs/:filename', (req, res) => {
    const allowedArtifacts = new Set(ARTIFACT_FILES.map((a) => a.filename));
    const fname = req.params.filename;
    if (!allowedArtifacts.has(fname)) {
      res.status(404).json({ error: 'Requested output artifact not found.' });
      return;
    }
    const filePath = path.join(OUTPUTS_DIR, fname);
    if (!fs.existsSync(filePath)) {
      res.status(404).json({ error: 'Artifact file does not exist on disk.' });
      return;
    }
    res.download(filePath, fname);
  });

  // 5. Serve generated PNG plots
  app.get('/api/plots/:plotname', (req, res) => {
    const allowedPlots = new Set([
      'class_distribution.png',
      'feature_correlation.png',
      'model_comparison.png',
      'confusion_matrix.png',
      'system_architecture.png',
    ]);
    const pname = req.params.plotname;
    if (!allowedPlots.has(pname)) {
      res.status(404).send('Plot not found');
      return;
    }
    const filePath = path.join(OUTPUTS_DIR, pname);
    if (!fs.existsSync(filePath)) {
      res.status(404).send('Plot file not generated yet');
      return;
    }
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(filePath);
  });

  // 6. Execute Python ML Pipeline (Demo mode or Uploaded CSV) & regenerate DOCX report
  app.post('/api/run-pipeline', async (req, res) => {
    try {
      const {
        sampleSize = 800,
        seed = 42,
        studentName = 'Hemlata Kumawat',
        institution = '[Institution / College Name]',
        csvContent = null,
        csvFileName = null,
      } = req.body || {};

      const safeSampleSize = Math.min(Math.max(Number(sampleSize) || 800, 100), 100000);
      const safeSeed = Number(seed) || 42;

      const cliArgs: string[] = [
        path.join(ROOT_DIR, 'HemlataKumawat_NetworkIntrusionDetection.py'),
        '--output-dir',
        OUTPUTS_DIR,
        '--sample-size',
        String(safeSampleSize),
        '--seed',
        String(safeSeed),
        '--generate-report',
        '--student-name',
        String(studentName).slice(0, 120),
        '--institution',
        String(institution).slice(0, 160),
      ];

      if (csvContent && typeof csvContent === 'string' && csvContent.trim().length > 0) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        const cleanName = String(csvFileName || 'uploaded_cicids2017.csv').replace(
          /[^a-zA-Z0-9._-]/g,
          '_'
        );
        const savedCsvPath = path.join(DATA_DIR, cleanName);
        fs.writeFileSync(savedCsvPath, csvContent, 'utf-8');
        cliArgs.push('--data', savedCsvPath);
      } else {
        cliArgs.push('--demo');
      }

      const { stdout, stderr } = await execFileAsync(PYTHON_BIN, cliArgs, {
        cwd: ROOT_DIR,
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024,
      });

      res.json({
        success: true,
        logs: `${stdout}\n${stderr}`.trim(),
        state: buildProjectState(),
      });
    } catch (err: any) {
      console.error('Pipeline execution failed:', err);
      res.status(400).json({
        success: false,
        error: err?.stderr || err?.message || 'Failed to execute Python pipeline.',
      });
    }
  });

  // 7. Run Real Model Inference on a Single Flow Record or CSV Batch
  app.post('/api/predict-flow', async (req, res) => {
    try {
      const { flowRecord, csvContent } = req.body || {};

      const inlineScript = `
import json, sys, pandas as pd
from pathlib import Path
from io import StringIO
from HemlataKumawat_NetworkIntrusionDetection import predict_network_flows

payload = json.loads(sys.stdin.read())
out_dir = Path("outputs")
if payload.get("csvContent"):
    df = pd.read_csv(StringIO(payload["csvContent"]))
    res = predict_network_flows(
        records=df,
        model_path=out_dir / "model.joblib",
        schema_path=out_dir / "feature_schema.json",
        output_csv_path=out_dir / "predictions.csv",
    )
else:
    res = predict_network_flows(
        records=payload["flowRecord"],
        model_path=out_dir / "model.joblib",
        schema_path=out_dir / "feature_schema.json",
        output_csv_path=None,
    )
print(json.dumps(res))
`;

      const child = execFile(
        PYTHON_BIN,
        ['-c', inlineScript],
        { cwd: ROOT_DIR, timeout: 25000, maxBuffer: 5 * 1024 * 1024 },
        (error, stdout, stderr) => {
          if (error) {
            res.status(400).json({
              success: false,
              error: (stderr || error.message || 'Prediction failed').trim(),
            });
            return;
          }
          try {
            const parsed = JSON.parse(stdout.trim());
            res.json({ success: true, result: parsed });
          } catch (parseErr) {
            res.status(500).json({
              success: false,
              error: `Failed to parse prediction output: ${stdout}`,
            });
          }
        }
      );

      child.stdin?.write(JSON.stringify({ flowRecord, csvContent }));
      child.stdin?.end();
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: err?.message || 'Internal prediction error.',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(ROOT_DIR, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NIDS Workbench Server listening at http://localhost:${PORT}`);
  });
}

startServer();
