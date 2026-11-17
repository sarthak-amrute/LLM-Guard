import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanResults } from '../services/api';
import ResultsTable from '../components/ResultsTable';
import MetricCard from '../components/MetricCard';

export default function Results() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let mounted = true;
    getScanResults()
      .then((d) => { if (mounted) { setData(d); setLoading(false); } })
      .catch((e) => { if (mounted) { setError(e.message); setLoading(false); } });
    return () => { mounted = false; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-outline text-sm">Loading scan results…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-error/40 rounded-xl p-space-xl text-center flex flex-col items-center gap-3">
          <span className="material-symbols-outlined text-[36px] text-error">error</span>
          <div className="font-headline-sm text-on-surface text-base font-bold">Could not load results</div>
          <div className="font-mono text-xs text-error">{error}</div>
        </div>
      </div>
    );
  }

  const resultsList = data?.results ?? [];
  const hasResults = Boolean((resultsList.length > 0 || (data?.total ?? 0) > 0) && (data?.status === 'completed' || data?.status === 'cancelled' || (data?.completed ?? 0) > 0));
  const summary = data?.summary ?? {};
  const total = resultsList.length || (data?.total ?? 0);
  const isStopped = data?.status === 'cancelled';

  if (!hasResults) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-space-xl flex flex-col items-center text-center gap-4 py-16 shadow-sm">
          <span className="material-symbols-outlined text-[48px] text-surface-container-highest">
            policy
          </span>
          <h2 className="font-headline text-xl font-bold text-on-surface">No Scan Results Available</h2>
          <p className="font-body-sm text-xs text-outline max-w-sm">
            {data?.status === 'running'
              ? 'A security scan is currently running in the background.'
              : 'Run a security scan to evaluate target defenses and generate inspection telemetry.'}
          </p>
          <div className="flex gap-3 mt-2">
            {data?.status === 'running' ? (
              <button onClick={() => navigate('/live-scan')} className="btn-primary cursor-pointer flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">radar</span>
                <span>View Live Scan</span>
              </button>
            ) : (
              <button onClick={() => navigate('/run-scan')} className="btn-primary cursor-pointer flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px]">play_arrow</span>
                <span>Run First Scan</span>
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-space-xl space-y-space-lg w-full max-w-7xl">
      {/* Header Banner */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="font-headline text-lg font-bold text-on-surface">
              Scan Findings & Forensic Inspection Logs
            </h1>
            <span className="font-mono text-xs text-primary font-semibold px-2 py-0.5 rounded bg-primary/10 border border-primary/20">
              {data.scan_id ? `ID: ${data.scan_id}` : 'SEC-RUN'}
            </span>
            {isStopped && (
              <span className="font-mono text-xs text-amber-800 font-semibold px-2 py-0.5 rounded bg-amber-50 border border-amber-300">
                Stopped (Partial)
              </span>
            )}
          </div>
          <div className="font-mono text-xs text-outline mt-1">
            {data.target_info && (
              <>
                Target: <strong className="text-on-surface">{data.target_info.name} ({data.target_info.provider?.toUpperCase()})</strong>
                {' · '}
              </>
            )}
            Target Mode: <strong className="text-on-surface">{data.mode ?? '—'}</strong>
            {' · '}
            Evaluated:{' '}
            {data.completed_at ? new Date(data.completed_at).toLocaleString() : 'Recent'}
          </div>
        </div>
        <button onClick={() => navigate('/run-scan')} className="btn-primary py-2 px-4 text-xs cursor-pointer flex items-center gap-1.5">
          <span className="material-symbols-outlined text-[16px]">sync</span>
          <span>New Scan</span>
        </button>
      </div>

      {isStopped && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-xs text-amber-900 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[20px] text-amber-800">info</span>
            <span>
              <strong>Partial Results Display:</strong> This scan was stopped before completing all queued probes. All {resultsList.length} executed test cases were safely preserved.
            </span>
          </div>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-space-md">
        <MetricCard label="Total Evaluated" value={total} icon="biotech" sub="Adversarial payloads" />
        <MetricCard
          label="Safe Defended"
          value={summary.SAFE ?? 0}
          icon="verified_user"
          accent
          sub={total > 0 ? `${Math.round(((summary.SAFE ?? 0) / total) * 100)}% passed` : '—'}
        />
        <MetricCard
          label="Vulnerable Findings"
          value={summary.VULNERABLE ?? 0}
          icon="gpp_bad"
          sub={total > 0 ? `${Math.round(((summary.VULNERABLE ?? 0) / total) * 100)}% breached` : '—'}
        />
        <MetricCard
          label="Target Errors"
          value={summary.TARGET_ERROR ?? 0}
          icon="warning"
          sub="Upstream failures"
        />
      </div>

      {/* Category Summary */}
      {data.category_stats && Object.keys(data.category_stats).length > 0 && (
        <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm">
          <div className="font-headline text-sm font-semibold text-on-surface mb-3">
            Category Breakdown & Threat Matrix
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-body-sm text-body-sm">
              <thead className="border-b border-surface-container-high/70 bg-surface-container-lowest">
                <tr className="font-label-sm text-[10px] uppercase text-outline tracking-wider">
                  <th className="py-2.5 px-4">Category</th>
                  <th className="py-2.5 px-4">Total</th>
                  <th className="py-2.5 px-4">Safe</th>
                  <th className="py-2.5 px-4">Vulnerable</th>
                  <th className="py-2.5 px-4">Errors</th>
                  <th className="py-2.5 px-4">Pass Rate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container-high/30">
                {Object.entries(data.category_stats).map(([cat, s]) => {
                  const passRate = s.total > 0 ? Math.round((s.SAFE / s.total) * 100) : 0;
                  const hasVuln = s.VULNERABLE > 0;
                  return (
                    <tr key={cat} className="hover:bg-surface-container-low transition-colors">
                      <td className="py-2.5 px-4 text-on-surface font-medium">{cat}</td>
                      <td className="py-2.5 px-4 font-mono text-outline">{s.total}</td>
                      <td className="py-2.5 px-4 font-mono text-emerald-800 font-semibold">{s.SAFE}</td>
                      <td className={`py-2.5 px-4 font-mono font-semibold ${hasVuln ? 'text-red-800' : 'text-outline'}`}>
                        {s.VULNERABLE}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-outline">{s.TARGET_ERROR}</td>
                      <td className="py-2.5 px-4">
                        <div className="flex items-center gap-3">
                          <div className="w-24 bg-surface-container-high h-2 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${hasVuln ? 'bg-amber-600' : 'bg-emerald-700'}`}
                              style={{ width: `${passRate}%` }}
                            />
                          </div>
                          <span className={`font-mono text-xs font-bold ${hasVuln ? 'text-amber-800' : 'text-emerald-800'}`}>
                            {passRate}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Full Inspection Log */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="font-headline text-base font-bold text-on-surface">
            Complete Inspection Log
          </div>
          <span className="font-body text-xs text-outline">
            Click any row to view full payload, response, and classification telemetry
          </span>
        </div>
        <ResultsTable results={resultsList} />
      </div>
    </div>
  );
}
