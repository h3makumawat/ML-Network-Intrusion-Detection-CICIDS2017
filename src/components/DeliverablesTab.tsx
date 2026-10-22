import React, { useEffect, useState } from 'react';
import { Check, Copy, Download, FileCode, FileText, FolderOpen } from 'lucide-react';
import { ProjectStatePayload } from '../types';
import { formatBytes } from '../utils/nidsLogic';

interface DeliverablesTabProps {
  projectState: ProjectStatePayload;
}

const INSPECTABLE_FILES = [
  {
    id: 'HemlataKumawat_NetworkIntrusionDetection.py',
    label: 'HemlataKumawat_NetworkIntrusionDetection.py',
  },
  { id: 'requirements.txt', label: 'requirements.txt' },
  { id: 'README.md', label: 'README.md' },
  { id: '.gitignore', label: '.gitignore' },
  { id: 'classification_report.txt', label: 'outputs/classification_report.txt' },
  { id: 'feature_schema.json', label: 'outputs/feature_schema.json' },
  { id: 'evaluation_metrics.json', label: 'outputs/evaluation_metrics.json' },
];

export const DeliverablesTab: React.FC<DeliverablesTabProps> = ({ projectState }) => {
  const [selectedFile, setSelectedFile] = useState<string>(
    'HemlataKumawat_NetworkIntrusionDetection.py'
  );
  const [fileContent, setFileContent] = useState<string>('Loading file contents...');
  const [isLoadingText, setIsLoadingText] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    let active = true;
    setIsLoadingText(true);
    fetch(`/api/source/${encodeURIComponent(selectedFile)}`)
      .then((res) => {
        if (!res.ok) throw new Error(`Unable to load ${selectedFile}`);
        return res.text();
      })
      .then((txt) => {
        if (active) setFileContent(txt);
      })
      .catch((err) => {
        if (active) setFileContent(`Error loading file: ${err.message}`);
      })
      .finally(() => {
        if (active) setIsLoadingText(false);
      });
    return () => {
      active = false;
    };
  }, [selectedFile]);

  const handleCopyContent = async () => {
    try {
      await navigator.clipboard.writeText(fileContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback if clipboard API restricted in iframe
      const textarea = document.createElement('textarea');
      textarea.value = fileContent;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-8">
      {/* Mandatory 4 Bootcamp Deliverables */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-slate-900">
            Mandatory Bootcamp Submission Deliverables
          </h1>
          <p className="text-xs text-slate-600 mt-1">
            All four mandatory files required for the IBM SkillsBuild Cyber Security Bootcamp 2026
            (conducted by BharatCares / CSRBOX Group) plus <code className="font-mono">.gitignore</code>.
            Click any file to download directly or inspect its full source below.
          </p>
        </div>

        <div className="divide-y divide-slate-200 border border-slate-200 rounded-lg">
          {projectState.deliverables.map((item, idx) => (
            <div
              key={item.filename}
              className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-slate-50/80 transition-colors"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 font-mono">
                  <span>
                    {idx + 1}. {item.filename}
                  </span>
                  <span className="font-sans font-normal text-xs text-slate-500">
                    · {formatBytes(item.sizeBytes)}
                  </span>
                </div>
                <p className="text-xs text-slate-600 max-w-2xl">{item.description}</p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {INSPECTABLE_FILES.some((f) => f.id === item.filename) && (
                  <button
                    type="button"
                    onClick={() => setSelectedFile(item.filename)}
                    className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-100 transition-colors whitespace-nowrap"
                  >
                    Inspect Source
                  </button>
                )}
                <a
                  href={item.downloadUrl}
                  download={item.filename}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </a>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Interactive Source Code & Text Artifact Viewer */}
      <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-slate-700" />
              <span>Complete Source File Inspector</span>
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Inspect or copy the complete, unabridged contents of every text deliverable.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-100 rounded-lg">
            {INSPECTABLE_FILES.map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setSelectedFile(f.id)}
                className={`px-2.5 py-1.5 text-xs font-mono rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  selectedFile === f.id
                    ? 'bg-white text-slate-900 font-semibold shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {f.id}
              </button>
            ))}
          </div>
        </div>

        <div className="border border-slate-200 rounded-lg overflow-hidden">
          <div className="bg-slate-900 text-slate-100 px-4 py-2.5 flex items-center justify-between text-xs font-mono">
            <span>{selectedFile}</span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyContent}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-100 rounded transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied!' : 'Copy Full File'}</span>
              </button>
            </div>
          </div>
          <pre className="p-4 bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto max-h-[520px] leading-relaxed">
            {isLoadingText ? 'Loading file content...' : fileContent}
          </pre>
        </div>
      </section>

      {/* Runtime Generated Output Artifacts Inventory (outputs/) */}
      <section className="bg-white border border-slate-200 rounded-xl p-6">
        <div className="mb-4">
          <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-slate-700" />
            <span>Generated Pipeline Artifacts (<code className="font-mono">outputs/</code> Directory)</span>
          </h2>
          <p className="text-xs text-slate-600 mt-0.5">
            Every artifact generated by running <code className="font-mono">YourName_NetworkIntrusionDetection.py</code>.
            Note: In accordance with GitHub best practices, <code className="font-mono">outputs/</code> and
            model binaries (<code className="font-mono">*.joblib</code>) are excluded from version control via <code className="font-mono">.gitignore</code>.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold text-slate-600">
                <th className="py-2.5 pr-4">Artifact Path</th>
                <th className="py-2.5 px-3">Purpose &amp; Contents</th>
                <th className="py-2.5 px-3 text-right">File Size</th>
                <th className="py-2.5 pl-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs">
              {projectState.artifacts.map((art) => (
                <tr key={art.filename} className="hover:bg-slate-50">
                  <td className="py-3 pr-4 font-mono font-medium text-slate-900 whitespace-nowrap">
                    outputs/{art.filename}
                  </td>
                  <td className="py-3 px-3 text-slate-600">{art.description}</td>
                  <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-700 whitespace-nowrap">
                    {art.exists ? formatBytes(art.sizeBytes) : 'Missing'}
                  </td>
                  <td className="py-3 pl-3 text-right whitespace-nowrap">
                    {art.exists && (
                      <a
                        href={art.downloadUrl}
                        download={art.filename}
                        className="inline-flex items-center gap-1 px-2.5 py-1 font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded transition-colors"
                      >
                        <Download className="w-3 h-3" />
                        <span>Download</span>
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
