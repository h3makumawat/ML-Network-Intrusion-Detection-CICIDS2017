import React, { useEffect, useState } from 'react';
import { Download } from 'lucide-react';
import { DeliverablesTab } from './components/DeliverablesTab';
import { FlowPredictorTab } from './components/FlowPredictorTab';
import { OverviewTab } from './components/OverviewTab';
import { ReportAndGuideTab } from './components/ReportAndGuideTab';
import { ProjectStatePayload } from './types';

type ActiveTab = 'overview' | 'predictor' | 'deliverables' | 'report';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [projectState, setProjectState] = useState<ProjectStatePayload | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ProjectStatePayload = await res.json();
      setProjectState(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load NIDS project status');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const navItems: Array<{ id: ActiveTab; label: string }> = [
    { id: 'overview', label: 'Evaluation & EDA' },
    { id: 'predictor', label: 'Flow Predictor' },
    { id: 'deliverables', label: 'Deliverables & Code' },
    { id: 'report', label: 'Report & Guide' },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-3 md:gap-8 px-4 sm:px-6 lg:px-8 py-3.5">
          {/* Zone 1: Single text element wordmark */}
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('overview');
            }}
            className="text-sm sm:text-lg font-bold tracking-tight text-slate-900 font-display whitespace-nowrap shrink-0"
          >
            CIC-IDS2017 NIDS Workbench
          </a>

          {/* Zone 2: 4 concise single-line text navigation links */}
          <nav
            aria-label="Primary Workspace Navigation"
            className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600"
          >
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
                    isActive
                      ? 'text-slate-900 border-slate-900 font-semibold'
                      : 'border-transparent hover:text-slate-900 hover:border-slate-300'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Zone 3: 1 primary action */}
          <div className="flex items-center gap-2 shrink-0">
            <a
              href="/api/download/HemlataKumawat_ProjectReport.docx"
              download="HemlataKumawat_ProjectReport.docx"
              className="inline-flex items-center gap-1.5 px-3 sm:px-3.5 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5 shrink-0" />
              <span className="sm:hidden">Report (.docx)</span>
              <span className="hidden sm:inline">Download Report (.docx)</span>
            </a>
          </div>
        </div>

        {/* Mobile Secondary Tab Bar (only visible on < md screens) */}
        <div className="md:hidden border-t border-slate-200 px-4 py-2 flex items-center gap-2 overflow-x-auto bg-slate-50">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 transition-colors ${
                  isActive
                    ? 'bg-slate-900 text-white'
                    : 'bg-white text-slate-700 border border-slate-200'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {loading ? (
          <div className="space-y-6">
            <div className="h-44 bg-white border border-slate-200 rounded-xl p-6 animate-pulse" />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="h-72 bg-white border border-slate-200 rounded-xl p-6 animate-pulse" />
              <div className="h-72 bg-white border border-slate-200 rounded-xl p-6 animate-pulse" />
            </div>
          </div>
        ) : error || !projectState ? (
          <div className="bg-white border border-red-200 rounded-xl p-8 text-center space-y-3">
            <p className="text-sm font-semibold text-red-800">
              Unable to load project status: {error}
            </p>
            <button
              type="button"
              onClick={fetchStatus}
              className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg"
            >
              Retry Connection
            </button>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewTab
                projectState={projectState}
                onRefreshState={(newState) => setProjectState(newState)}
                onNavigateTab={(tab) => setActiveTab(tab)}
              />
            )}
            {activeTab === 'predictor' && (
              <FlowPredictorTab projectState={projectState} />
            )}
            {activeTab === 'deliverables' && (
              <DeliverablesTab projectState={projectState} />
            )}
            {activeTab === 'report' && (
              <ReportAndGuideTab
                projectState={projectState}
                onRefreshState={(newState) => setProjectState(newState)}
              />
            )}
          </>
        )}
      </main>

      {/* Quiet Academic Footer */}
      <footer className="bg-white border-t border-slate-200 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div>
            IBM SkillsBuild Cyber Security Bootcamp 2026 · BharatCares (CSRBOX Group) · Student: Hemlata Kumawat (BCA)
          </div>
          <div className="flex items-center gap-4">
            <a
              href="https://www.unb.ca/cic/datasets/ids-2017.html"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-900 transition-colors"
            >
              UNB CIC-IDS2017 Dataset
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="https://huggingface.co/datasets/bvsam/cic-ids-2017"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-900 transition-colors"
            >
              Hugging Face Mirror
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
