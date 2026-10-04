import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanResults } from '../services/api';

export default function Reports() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    getScanResults()
      .then((d) => { if (mounted) { setData(d); setLoading(false); } })
      .catch(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  const handleDownloadJson = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `llmguard-audit-${data.scan_id ?? 'latest'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCsv = () => {
    if (!data?.results?.length) return;
    const headers = ['id', 'category', 'name', 'verdict', 'detail', 'timestamp'];
    const rows = data.results.map((r) =>
      headers.map((h) => JSON.stringify(r[h] ?? '')).join(',')
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `llmguard-audit-${data.scan_id ?? 'latest'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-outline">Compiling security reports…</div>
      </div>
    );
  }

  const hasResults = data?.status === 'completed' && (data?.total ?? 0) > 0;
  const summary = data?.summary ?? {};

  return (
    <div className="p-space-xl space-y-space-lg w-full max-w-4xl">
      {/* Header */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-headline-sm text-base font-bold text-on-surface">
            Security Audit & Compliance Reports
          </h1>
          <div className="font-mono text-xs text-outline mt-1">
            Export automated evaluation telemetry in JSON, CSV, or formatted PDF format.
          </div>
        </div>
      </div>

      {!hasResults ? (
        <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-space-xl text-center flex flex-col items-center gap-4 py-16">
          <span className="material-symbols-outlined text-[48px] text-surface-container-highest">
            assessment
          </span>
          <h2 className="font-headline-md text-on-surface">No Completed Audits</h2>
          <p className="font-body-sm text-outline max-w-sm">
            Execute a security scan to produce downloadable forensic artifacts and compliance reports.
          </p>
          <button onClick={() => navigate('/run-scan')} className="btn-primary mt-2">
            <span className="material-symbols-outlined text-[16px]">play_arrow</span>
            <span>Run Security Scan</span>
          </button>
        </div>
      ) : (
        <>
          {/* Main Report Card */}
          <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col md:flex-row items-start justify-between gap-6">
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-primary font-bold">
                  Audit Run #{data.scan_id ?? '0942'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-primary/10 text-primary border border-primary/20">
                  {data.mode}
                </span>
              </div>
              <div className="font-body-sm text-xs text-outline">
                Completed: {data.completed_at ? new Date(data.completed_at).toLocaleString() : 'Recent'}
              </div>

              <div className="grid grid-cols-4 gap-4 pt-2">
                {[
                  { label: 'TOTAL TESTS', val: data.total, color: 'text-on-surface' },
                  { label: 'SAFE', val: summary.SAFE ?? 0, color: 'text-tertiary' },
                  { label: 'VULNERABLE', val: summary.VULNERABLE ?? 0, color: 'text-error' },
                  { label: 'ERRORS', val: summary.TARGET_ERROR ?? 0, color: 'text-amber-300' },
                ].map(({ label, val, color }) => (
                  <div key={label}>
                    <div className="font-label-sm text-[9px] text-outline uppercase">{label}</div>
                    <div className={`font-headline-xl text-xl font-bold mt-0.5 ${color}`}>{val}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex flex-col gap-2 w-full md:w-auto shrink-0">
              <button onClick={() => window.print()} className="btn-primary">
                <span className="material-symbols-outlined text-[16px]">picture_as_pdf</span>
                <span>Export PDF Report</span>
              </button>
              <button onClick={handleDownloadJson} className="btn-secondary">
                <span className="material-symbols-outlined text-[16px]">download</span>
                <span>Download JSON Payload</span>
              </button>
              <button onClick={handleDownloadCsv} className="btn-secondary">
                <span className="material-symbols-outlined text-[16px]">table_view</span>
                <span>Download CSV Matrix</span>
              </button>
            </div>
          </div>

          {/* Category Breakdown in Report */}
          {data.category_stats && (
            <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm space-y-3">
              <div className="font-headline-sm text-sm font-semibold text-on-surface">
                Category Risk Distribution
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-body-sm text-body-sm">
                  <thead className="border-b border-surface-container-high/70 bg-surface-container-lowest">
                    <tr className="font-label-sm text-[10px] uppercase text-outline tracking-wider">
                      <th className="py-2.5 px-4">Threat Category</th>
                      <th className="py-2.5 px-4">Total</th>
                      <th className="py-2.5 px-4">Safe</th>
                      <th className="py-2.5 px-4">Vulnerable</th>
                      <th className="py-2.5 px-4">Errors</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-container-high/30">
                    {Object.entries(data.category_stats).map(([cat, s]) => (
                      <tr key={cat} className="hover:bg-surface-container-low transition-colors">
                        <td className="py-2.5 px-4 text-on-surface font-medium">{cat}</td>
                        <td className="py-2.5 px-4 font-mono text-outline">{s.total}</td>
                        <td className="py-2.5 px-4 font-mono text-tertiary font-semibold">{s.SAFE}</td>
                        <td className={`py-2.5 px-4 font-mono font-semibold ${s.VULNERABLE > 0 ? 'text-error' : 'text-outline'}`}>
                          {s.VULNERABLE}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-outline">{s.TARGET_ERROR}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
