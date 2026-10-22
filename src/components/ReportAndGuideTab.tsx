import React, { useState } from 'react';
import { CheckSquare, Download, FileText, GitBranch, RefreshCw, Terminal } from 'lucide-react';
import { ProjectStatePayload } from '../types';

interface ReportAndGuideTabProps {
  projectState: ProjectStatePayload;
  onRefreshState: (newState: ProjectStatePayload) => void;
}

export const ReportAndGuideTab: React.FC<ReportAndGuideTabProps> = ({
  projectState,
  onRefreshState,
}) => {
  const [studentName, setStudentName] = useState<string>('Hemlata Kumawat (Branch: BCA)');
  const [institution, setInstitution] = useState<string>(
    '[Institution / College Name]'
  );
  const [isRebuilding, setIsRebuilding] = useState<boolean>(false);
  const [rebuildNotice, setRebuildNotice] = useState<string | null>(null);

  const metrics = projectState.evaluationMetrics;
  const selectedModel = metrics?.selected_model || 'Random Forest';
  const bestMetrics = metrics?.models?.[selectedModel];

  const handleCustomizeReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsRebuilding(true);
    setRebuildNotice(null);
    try {
      const response = await fetch('/api/run-pipeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sampleSize: metrics?.cleaning_summary?.sampled_row_count || 800,
          seed: 42,
          studentName,
          institution,
        }),
      });
      const data = await response.json();
      if (response.ok && data.success) {
        onRefreshState(data.state);
        setRebuildNotice(
          'Successfully updated HemlataKumawat_ProjectReport.docx with your custom details!'
        );
      }
    } finally {
      setIsRebuilding(false);
    }
  };

  const reportSections = [
    { num: 1, title: 'Cover Page', summary: 'Formal title banner, metadata grid, and submission date.' },
    { num: 2, title: 'Project Title', summary: 'ML-Based Network Intrusion Detection System Using CIC-IDS2017.' },
    { num: 3, title: 'Student Details', summary: `Student: Hemlata Kumawat · Branch: BCA.` },
    { num: 4, title: 'Institution', summary: `Populated with "${institution}".` },
    { num: 5, title: 'IBM SkillsBuild Cyber Security Bootcamp 2026', summary: 'Academic program context and defensive cybersecurity alignment.' },
    { num: 6, title: 'BharatCares (CSRBOX Group)', summary: 'Implementing partner acknowledgment.' },
    { num: 7, title: 'Abstract', summary: 'Executive summary of the CIC-IDS2017 flow classification pipeline and results.' },
    { num: 8, title: 'Introduction', summary: 'Role of network-flow telemetry in modern Security Operations Centers (SOCs).' },
    { num: 9, title: 'Problem Statement', summary: 'Addressing data leakage, NaN/Inf flow rates, and the Accuracy Paradox.' },
    { num: 10, title: 'Project Objectives', summary: 'Five measurable engineering and cybersecurity evaluation objectives.' },
    { num: 11, title: 'Scope of the Project', summary: 'Clear distinction between offline dataset classification and live IPS packet blocking.' },
    { num: 12, title: 'Background on Network Intrusion Detection', summary: 'Comparison of Signature-based IDS vs. Supervised Flow-based ML NIDS.' },
    { num: 13, title: 'Dataset Description and Source Links', summary: 'Official UNB CIC-IDS2017 link, Hugging Face mirror, and Label column taxonomy.' },
    { num: 14, title: 'Technologies and Tools Used', summary: 'Python 3, pandas, NumPy, scikit-learn, matplotlib, seaborn, joblib, python-docx.' },
    { num: 15, title: 'System Architecture', summary: 'Five-stage block diagram (embedded Figure 1: system_architecture.png).' },
    { num: 16, title: 'Methodology and Workflow', summary: 'Step-by-step execution lifecycle from chunked CSV ingestion to model serialization.' },
    { num: 17, title: 'Data Preprocessing', summary: 'UTF-8 BOM/header normalization, train-only constant/duplicate filtering, and median imputation.' },
    { num: 18, title: 'Exploratory Data Analysis', summary: 'Class distribution and correlation heatmaps (embedded Figures 2 & 3).' },
    { num: 19, title: 'Machine-Learning Algorithms', summary: 'Mathematical and operational comparison of Decision Tree and Random Forest.' },
    { num: 20, title: 'Training and Testing Methodology', summary: 'Stratified 80/20 split, balanced class weights, and train-only pipeline fitting.' },
    { num: 21, title: 'Evaluation Metrics and Their Definitions', summary: 'Positive class = MALICIOUS (1); formulas for Accuracy, Precision, Recall, F1, ROC-AUC.' },
    {
      num: 22,
      title: 'Actual Experimental Results',
      summary: bestMetrics
        ? `Measured ${selectedModel}: Accuracy=${(bestMetrics.accuracy * 100).toFixed(2)}%, Precision=${(bestMetrics.precision * 100).toFixed(2)}%, Recall=${(bestMetrics.recall * 100).toFixed(2)}%, F1=${(bestMetrics.f1_score * 100).toFixed(2)}%, ROC-AUC=${bestMetrics.roc_auc} (embedded Figures 4 & 5).`
        : 'Populated automatically from outputs/evaluation_metrics.json.',
    },
    { num: 23, title: 'Results Interpretation', summary: 'Analysis of why Random Forest ensemble outperforms single Decision Tree.' },
    { num: 24, title: 'Discussion of False Positives and False Negatives', summary: 'SOC alert fatigue (FP) vs. undetected cyber intrusions (FN).' },
    { num: 25, title: 'Limitations', summary: 'Offline CSV analysis, concept drift, zero-day attacks, and adversarial traffic shaping.' },
    { num: 26, title: 'Ethical Considerations', summary: 'Authorized network monitoring, IP anonymization, and human-in-the-loop review.' },
    { num: 27, title: 'Future Enhancements', summary: 'Multi-class attack categorization, time-based splitting, and SHAP explainability.' },
    { num: 28, title: 'Conclusion', summary: 'Summary of key defensive ML takeaways.' },
    { num: 29, title: 'References', summary: 'Academic citations (UNB CIC-IDS2017; Hugging Face Mirror; Scikit-learn).' },
    { num: 30, title: 'Instructions for Reproducing the Experiment', summary: 'Exact terminal commands for venv setup, --demo check, --data training, and --predict.' },
  ];

  return (
    <div className="space-y-8">
      {/* DOCX Report Customizer & Downloader */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          <div className="lg:col-span-7 space-y-3">
            <h1 className="text-xl font-bold text-slate-900">
              Microsoft Word Project Report (<code className="font-mono">HemlataKumawat_ProjectReport.docx</code>)
            </h1>
            <p className="text-xs text-slate-600 leading-relaxed">
              Generated programmatically using <code className="font-mono">python-docx</code> for{' '}
              <strong>Student: Hemlata Kumawat (Branch: BCA)</strong> with all 30 mandatory bootcamp
              sections, formatted tables, page numbers, embedded PNG visualizations, and clearly
              labeled experimental results.
            </p>
            <div className="pt-2">
              <a
                href="/api/download/HemlataKumawat_ProjectReport.docx"
                download="HemlataKumawat_ProjectReport.docx"
                className="inline-flex items-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <Download className="w-4 h-4" />
                <span>Download HemlataKumawat_ProjectReport.docx</span>
              </a>
            </div>
          </div>

          <form
            onSubmit={handleCustomizeReport}
            className="lg:col-span-5 bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-3"
          >
            <h2 className="text-xs font-semibold text-slate-900">
              Optional: Update Institution in DOCX Report
            </h2>
            <div>
              <label
                htmlFor="report-student-name"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Student Name &amp; Branch
              </label>
              <input
                id="report-student-name"
                type="text"
                value={studentName}
                onChange={(e) => setStudentName(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded-md"
              />
            </div>
            <div>
              <label
                htmlFor="report-institution"
                className="block text-xs font-medium text-slate-700 mb-1"
              >
                Institution / College Name
              </label>
              <input
                id="report-institution"
                type="text"
                value={institution}
                onChange={(e) => setInstitution(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-white border border-slate-300 rounded-md"
              />
            </div>
            {rebuildNotice && (
              <p className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded p-2">
                {rebuildNotice}
              </p>
            )}
            <button
              type="submit"
              disabled={isRebuilding}
              className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-900 bg-white border border-slate-300 rounded-md hover:bg-slate-100 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRebuilding ? 'animate-spin' : ''}`} />
              <span>{isRebuilding ? 'Rebuilding DOCX...' : 'Update & Rebuild DOCX Report'}</span>
            </button>
          </form>
        </div>
      </section>

      {/* Beginner-Friendly Execution & GitHub Submission Checklist */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-6 space-y-4">
          <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-700" />
            <span>Step-by-Step Local Execution &amp; Dataset Guide</span>
          </h2>
          <p className="text-xs text-slate-600">
            How to run your project on your laptop and train on the real CIC-IDS2017 CSV dataset:
          </p>

          <ol className="space-y-3 text-xs text-slate-700 list-decimal list-inside leading-relaxed">
            <li>
              <strong>Download the 4 Mandatory Files:</strong> Download{' '}
              <code className="font-mono">HemlataKumawat_NetworkIntrusionDetection.py</code>,{' '}
              <code className="font-mono">requirements.txt</code>,{' '}
              <code className="font-mono">HemlataKumawat_ProjectReport.docx</code>, and{' '}
              <code className="font-mono">README.md</code> (plus <code className="font-mono">.gitignore</code>)
              into a folder named <code className="font-mono">ml-network-intrusion-detection/</code>.
            </li>
            <li>
              <strong>Create Virtual Environment &amp; Install Packages:</strong>
              <pre className="mt-1.5 p-2.5 bg-slate-900 text-slate-100 rounded font-mono text-[11px] overflow-x-auto">
{`python -m venv .venv
source .venv/bin/activate   # Windows: .\\.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt`}
              </pre>
            </li>
            <li>
              <strong>Download CIC-IDS2017 CSV Dataset:</strong> Download one or more labeled CSVs
              from{' '}
              <a
                href="https://huggingface.co/datasets/bvsam/cic-ids-2017"
                target="_blank"
                rel="noreferrer"
                className="underline text-slate-900 font-medium"
              >
                Hugging Face Mirror (bvsam/cic-ids-2017)
              </a>{' '}
              or the{' '}
              <a
                href="https://www.unb.ca/cic/datasets/ids-2017.html"
                target="_blank"
                rel="noreferrer"
                className="underline text-slate-900 font-medium"
              >
                Official UNB CIC Page
              </a>{' '}
              and place them inside a <code className="font-mono">data/</code> subfolder.
            </li>
            <li>
              <strong>Run Training, Evaluation &amp; Report Update on Real Data:</strong>
              <pre className="mt-1.5 p-2.5 bg-slate-900 text-slate-100 rounded font-mono text-[11px] overflow-x-auto">
{`python HemlataKumawat_NetworkIntrusionDetection.py \\
  --data data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \\
  --output-dir outputs \\
  --sample-size 100000 \\
  --generate-report`}
              </pre>
            </li>
            <li>
              <strong>Run Flow Prediction on a Separate CSV:</strong>
              <pre className="mt-1.5 p-2.5 bg-slate-900 text-slate-100 rounded font-mono text-[11px] overflow-x-auto">
{`python HemlataKumawat_NetworkIntrusionDetection.py \\
  --predict path/to/unseen_flows.csv \\
  --output-dir outputs`}
              </pre>
            </li>
          </ol>
        </div>

        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-xl p-6 space-y-4">
          <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-slate-700" />
            <span>GitHub Upload &amp; Getting Your Submission URL</span>
          </h2>
          <p className="text-xs text-slate-600">
            Recommended repository name: <code className="font-mono font-semibold">ml-network-intrusion-detection</code>
          </p>

          <div className="space-y-3 text-xs text-slate-700 leading-relaxed">
            <p>
              <strong>1. Recommended Repository Structure:</strong>
            </p>
            <pre className="p-2.5 bg-slate-900 text-slate-100 rounded font-mono text-[11px] overflow-x-auto">
{`ml-network-intrusion-detection/
├── HemlataKumawat_NetworkIntrusionDetection.py
├── requirements.txt
├── README.md
├── HemlataKumawat_ProjectReport.docx
├── .gitignore
└── outputs/   (generated at runtime; excluded via .gitignore)`}
            </pre>

            <p>
              <strong>2. Commands to Upload &amp; Get Your Actual GitHub URL:</strong>
            </p>
            <pre className="p-2.5 bg-slate-900 text-slate-100 rounded font-mono text-[11px] overflow-x-auto">
{`git init
git add HemlataKumawat_NetworkIntrusionDetection.py requirements.txt README.md HemlataKumawat_ProjectReport.docx .gitignore
git commit -m "Add ML-Based Network Intrusion Detection System (CIC-IDS2017)"
git branch -M main
git remote add origin https://github.com/<your-username>/ml-network-intrusion-detection.git
git push -u origin main`}
            </pre>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600">
              <strong className="text-slate-900">Your Final Submission URL:</strong> Once uploaded,
              open your repository in a browser and copy the URL from the address bar:{' '}
              <code className="font-mono text-slate-900">
                https://github.com/&lt;your-github-username&gt;/ml-network-intrusion-detection
              </code>
            </div>
          </div>
        </div>
      </section>

      {/* Complete 30-Section Index of YourName_ProjectReport.docx */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="flex items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-700" />
              <span>All 30 Mandatory Sections Included in YourName_ProjectReport.docx</span>
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Verified against the IBM SkillsBuild Cyber Security Bootcamp 2026 report rubric
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {reportSections.map((sec) => (
            <div
              key={sec.num}
              className="p-3.5 bg-slate-50/70 border border-slate-200 rounded-lg space-y-1"
            >
              <div className="text-xs font-semibold text-slate-900">
                <span className="font-mono text-slate-500 mr-1">
                  {String(sec.num).padStart(2, '0')}.
                </span>
                {sec.title}
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">{sec.summary}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
