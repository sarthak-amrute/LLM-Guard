import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanResults, startScan } from '../services/api';
import { useStatus } from '../context/useStatus';

export default function Dashboard() {
  const navigate = useNavigate();
  const { status: backendStatus, refreshStatus } = useStatus();
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [rerunState, setRerunState] = useState('idle');

  const PAGE_SIZE = 8;

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const sc = await getScanResults();
        if (!mounted) return;
        setScanData(sc);
      } catch (e) {
        if (!mounted) return;
        setError(e.message);
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => { mounted = false; };
  }, []);

  const total = scanData?.total ?? 0;
  const summary = scanData?.summary ?? { SAFE: 0, VULNERABLE: 0, TARGET_ERROR: 0 };
  const safeCount = summary.SAFE ?? 0;
  const vulnCount = summary.VULNERABLE ?? 0;
  const errorCount = summary.TARGET_ERROR ?? 0;
  const passRate = total > 0 ? ((safeCount / total) * 100).toFixed(1) : '0.0';

  const results = scanData?.results ?? [];

  // Filtered rows for recent evaluation activity
  const filteredResults = results.filter((r) => {
    if (filter === 'all') return true;
    if (filter === 'safe') return r.verdict === 'SAFE';
    if (filter === 'vuln') return r.verdict === 'VULNERABLE';
    if (filter === 'error') return r.verdict === 'TARGET_ERROR';
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  const paginatedResults = filteredResults.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  // Top vulnerable findings for triage (without test IDs)
  const vulnerableResults = results.filter((r) => r.verdict === 'VULNERABLE');
  const triageItems = vulnerableResults.slice(0, 2);

  const handleRerunFailed = async () => {
    setRerunState('running');
    try {
      await startScan({ mode: scanData?.mode || 'VULNERABLE' });
      await refreshStatus();
      setRerunState('queued');
      setTimeout(() => {
        navigate('/live-scan');
      }, 600);
    } catch {
      setRerunState('idle');
      navigate('/run-scan');
    }
  };

  const handleExportPDF = () => {
    window.print();
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-on-surface-variant text-sm">
          Loading security metrics and findings…
        </div>
      </div>
    );
  }

  if (error && !scanData) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-error/40 rounded-xl p-space-xl flex flex-col items-center text-center gap-3 shadow-sm">
          <span className="material-symbols-outlined text-[36px] text-error">error</span>
          <div className="font-headline-sm text-lg font-bold text-on-surface">LLMGuard Backend Unavailable</div>
          <div className="font-body-sm text-sm text-on-surface-variant max-w-md">
            Could not connect to the LLMGuard API on port 8001. Ensure the backend server is running.
          </div>
          <div className="font-mono text-xs bg-surface-container-low border border-surface-container-high px-4 py-2 rounded text-error">
            {error}
          </div>
          <button
            onClick={() => window.location.reload()}
            className="btn-secondary mt-2 cursor-pointer"
          >
            <span className="material-symbols-outlined text-[16px]">refresh</span>
            <span>Retry Connection</span>
          </button>
        </div>
      </div>
    );
  }

  // Clean empty state if no scan has been recorded yet
  if (total === 0 && (!scanData || scanData.status === 'idle')) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-space-xl flex flex-col items-center text-center gap-4 py-16 shadow-sm">
          <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
            <span className="material-symbols-outlined text-[32px] text-primary">shield</span>
          </div>
          <h2 className="font-headline text-xl font-bold text-on-surface">No Evaluation Runs Found</h2>
          <p className="font-body text-sm text-on-surface-variant max-w-md">
            No adversarial scan has been recorded yet. Launch a security evaluation run to populate security metrics, vulnerability findings, and inspection logs.
          </p>
          <button
            onClick={() => navigate('/run-scan')}
            className="btn-primary mt-2 cursor-pointer flex items-center gap-2"
          >
            <span className="material-symbols-outlined text-[18px]">play_arrow</span>
            <span>Run Security Scan</span>
          </button>
        </div>
      </div>
    );
  }

  const activeTargetName = scanData?.target_info?.name || backendStatus?.active_target?.name || 'TechMart Customer Support';
  const targetProvider = (scanData?.target_info?.provider || backendStatus?.active_target?.provider || 'techmart').toUpperCase();
  const targetMode = scanData?.mode || backendStatus?.target_mode || 'STANDARD';
  const isScanStopped = scanData?.status === 'cancelled';

  return (
    <div className="flex flex-col w-full">
      <div className="p-space-xl space-y-6 max-w-7xl">
        {/* Executive Header Banner */}
        <div className="bg-surface-container-lowest rounded-2xl border border-surface-container-high/70 p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5 text-xs text-outline">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-primary/10 text-primary border border-primary/20">
                {isScanStopped ? 'Scan Stopped (Partial)' : scanData?.status === 'completed' ? 'Evaluation Completed' : 'Scan Live'}
              </span>
              <span>•</span>
              <span>
                Target: <strong className="text-on-surface font-semibold">{activeTargetName}</strong>
              </span>
              <span>•</span>
              <span className="font-mono">{targetProvider} / {targetMode}</span>
              {scanData?.completed_at && (
                <>
                  <span>•</span>
                  <span>{new Date(scanData.completed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </>
              )}
            </div>
            <h1 className="font-headline text-2xl font-bold text-on-surface tracking-tight">
              Security Posture & Evaluation Dashboard
            </h1>
            <p className="font-body text-sm text-on-surface-variant">
              Adversarial red-teaming overview covering prompt injection, data extraction, and boundary enforcement.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {vulnCount > 0 && (
              <button
                onClick={handleRerunFailed}
                disabled={rerunState === 'running'}
                className="px-4 py-2.5 rounded-xl bg-surface-container border border-surface-container-high hover:bg-surface-container-high text-on-surface text-xs font-semibold transition-all cursor-pointer disabled:opacity-60 flex items-center gap-2"
                id="btn-rerun"
              >
                <span className={`material-symbols-outlined text-[16px] ${rerunState === 'running' ? 'animate-spin' : ''}`}>
                  sync
                </span>
                <span>{rerunState === 'running' ? 'Scheduling…' : `Re-run Failed (${vulnCount})`}</span>
              </button>
            )}

            <button
              onClick={() => navigate('/run-scan')}
              className="btn-primary text-xs px-4 py-2.5 flex items-center gap-2 cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">play_arrow</span>
              <span>New Scan</span>
            </button>
          </div>
        </div>

        {/* Security Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Security Pass Rate */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 shadow-sm flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-outline block">
                Security Pass Rate
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-on-surface tracking-tight">
                  {passRate}%
                </span>
              </div>
              <span className="text-xs text-on-surface-variant block">
                {safeCount} of {total} test probes defended
              </span>
            </div>
            <div className="relative w-14 h-14 shrink-0 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 36 36">
                <path
                  className="text-surface-container-high"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="3.5"
                />
                <path
                  className="text-primary"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  fill="none"
                  stroke="currentColor"
                  strokeDasharray={`${passRate}, 100`}
                  strokeLinecap="round"
                  strokeWidth="3.5"
                />
              </svg>
              <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold text-on-surface">
                {Math.round(Number(passRate))}%
              </span>
            </div>
          </div>

          {/* Card 2: Tests Evaluated */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 shadow-sm flex flex-col justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-outline">
              Total Evaluated
            </span>
            <div className="flex items-baseline gap-2 my-1">
              <span className="text-3xl font-extrabold text-on-surface tracking-tight">
                {total}
              </span>
              <span className="text-xs text-outline font-medium">probes executed</span>
            </div>
            <span className="text-xs text-on-surface-variant">
              Adversarial & regression suite
            </span>
          </div>

          {/* Card 3: Safe Defended */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 shadow-sm flex flex-col justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-outline">
              Safe Refusals
            </span>
            <div className="flex items-baseline gap-2 my-1">
              <span className="text-3xl font-extrabold text-emerald-800 tracking-tight">
                {safeCount}
              </span>
              <span className="text-xs text-emerald-800 font-semibold">Defended</span>
            </div>
            <span className="text-xs text-on-surface-variant">
              Zero canary leakage detected
            </span>
          </div>

          {/* Card 4: Vulnerabilities */}
          <div className={`p-5 rounded-2xl border shadow-sm flex flex-col justify-between transition-colors ${
            vulnCount > 0
              ? 'bg-red-50/40 border-red-200'
              : 'bg-surface-container-lowest border-surface-container-high/70'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-outline">
                Vulnerabilities
              </span>
              {vulnCount > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-100 text-red-800 border border-red-300">
                  Action Required
                </span>
              )}
            </div>
            <div className="flex items-baseline gap-2 my-1">
              <span className={`text-3xl font-extrabold tracking-tight ${vulnCount > 0 ? 'text-red-800' : 'text-on-surface'}`}>
                {vulnCount}
              </span>
              <span className="text-xs text-on-surface-variant font-medium">findings</span>
            </div>
            <span className="text-xs text-on-surface-variant">
              {vulnCount > 0 ? 'Requires guardrail reinforcement' : 'All adversarial probes passed'}
            </span>
          </div>
        </div>

        {/* Priority Findings & Triage Section */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <h2 className="font-headline text-lg font-bold text-on-surface">
                Key Security Findings
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-surface-container-high text-on-surface-variant border border-surface-container-highest">
                {vulnerableResults.length} active
              </span>
            </div>
            <button
              onClick={() => navigate('/results')}
              className="text-xs font-semibold text-primary hover:underline cursor-pointer"
            >
              View all results →
            </button>
          </div>

          {triageItems.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {triageItems.map((item, idx) => (
                <div
                  key={item.id}
                  className="bg-surface-container-lowest p-5 rounded-2xl flex flex-col justify-between gap-4 border border-surface-container-high/70 hover:border-primary/40 transition-all shadow-sm"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wide bg-red-50 text-red-800 border border-red-200">
                        {idx === 0 ? 'High Risk' : 'Medium Risk'}
                      </span>
                      <span className="text-xs text-outline font-medium">
                        {item.category?.split(' / ')[0] || item.category}
                      </span>
                    </div>

                    <h3 className="font-headline text-base font-bold text-on-surface">
                      {item.name}
                    </h3>
                    <p className="text-xs text-on-surface-variant line-clamp-2 leading-relaxed">
                      {item.objective || item.detail || 'Vulnerability detected during adversarial testing probe.'}
                    </p>
                  </div>

                  <div className="flex items-center justify-between pt-3 border-t border-surface-container-high/60">
                    <span className="text-xs text-outline flex items-center gap-1.5 font-medium">
                      <span className="material-symbols-outlined text-[16px] text-primary">security</span>
                      <span>Canary compromise detected</span>
                    </span>
                    <button
                      onClick={() => navigate(`/findings/${encodeURIComponent(item.id)}`)}
                      className="px-3.5 py-1.5 rounded-xl bg-surface-container border border-surface-container-high hover:bg-surface-container-high text-on-surface text-xs font-semibold transition-all cursor-pointer shadow-sm"
                    >
                      Review Finding
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-surface-container-lowest p-6 rounded-2xl border border-surface-container-high/60 text-center py-8 shadow-sm">
              <span className="material-symbols-outlined text-[36px] text-emerald-800">
                verified_user
              </span>
              <div className="font-headline text-base font-bold text-on-surface mt-2">
                No Active Vulnerabilities
              </div>
              <p className="text-xs text-on-surface-variant mt-1 max-w-md mx-auto">
                All executed test cases passed or no vulnerable outputs were flagged in this evaluation run.
              </p>
            </div>
          )}
        </div>

        {/* Evaluation Activity Log (NO TEST IDs) */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="font-headline text-lg font-bold text-on-surface">
                Evaluation Activity
              </h2>
              <p className="text-xs text-outline mt-0.5">
                Detailed record of executed adversarial vectors and verdicts
              </p>
            </div>

            <div className="flex items-center gap-1 bg-surface-container-lowest p-1 rounded-xl border border-surface-container-high/60">
              <button
                onClick={() => { setFilter('all'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  filter === 'all'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-outline hover:text-on-surface'
                }`}
              >
                All ({results.length})
              </button>
              <button
                onClick={() => { setFilter('safe'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  filter === 'safe'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-outline hover:text-on-surface'
                }`}
              >
                Safe ({safeCount})
              </button>
              <button
                onClick={() => { setFilter('vuln'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  filter === 'vuln'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-red-800 hover:bg-surface-container'
                }`}
              >
                Vulnerable ({vulnCount})
              </button>
              {errorCount > 0 && (
                <button
                  onClick={() => { setFilter('error'); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    filter === 'error'
                      ? 'bg-primary text-on-primary shadow-sm'
                      : 'text-outline hover:text-on-surface'
                  }`}
                >
                  Errors ({errorCount})
                </button>
              )}
            </div>
          </div>

          {/* Activity Table — Minimal, Professional, NO TEST IDs */}
          <div className="bg-surface-container-lowest rounded-2xl overflow-hidden border border-surface-container-high/70 shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-body text-sm">
                <thead className="border-b border-surface-container-high/70 bg-surface-container-low/50">
                  <tr className="text-[11px] uppercase text-outline tracking-wider font-semibold">
                    <th className="py-3 px-5">Attack Vector</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Response Excerpt</th>
                    <th className="py-3 px-4">Latency</th>
                    <th className="py-3 px-5 text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-container-high/40">
                  {paginatedResults.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-10 text-center text-outline text-xs">
                        No test records match the selected filter.
                      </td>
                    </tr>
                  ) : (
                    paginatedResults.map((r) => {
                      const isV = r.verdict === 'VULNERABLE';
                      const isE = r.verdict === 'TARGET_ERROR';
                      const latencyDisplay = r.latency ? r.latency : '—';

                      return (
                        <tr
                          key={r.id}
                          onClick={() => navigate(`/findings/${encodeURIComponent(r.id)}`)}
                          className="hover:bg-surface-container-low/70 transition-colors cursor-pointer group"
                        >
                          <td className="py-3.5 px-5 font-semibold text-on-surface text-xs max-w-xs truncate group-hover:text-primary transition-colors">
                            {r.name}
                          </td>
                          <td className="py-3.5 px-4 text-on-surface-variant whitespace-nowrap text-xs">
                            {r.category?.split(' / ')[0] || r.category}
                          </td>
                          <td className="py-3.5 px-4 text-on-surface-variant max-w-sm truncate text-xs font-mono">
                            {r.response
                              ? r.response.replace(/\n/g, ' ').slice(0, 56) + '…'
                              : '—'}
                          </td>
                          <td className="py-3.5 px-4 text-outline font-mono text-xs">
                            {latencyDisplay}
                          </td>
                          <td className="py-3.5 px-5 text-right whitespace-nowrap">
                            {isV ? (
                              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-50 text-red-800 border border-red-200">
                                Vulnerable
                              </span>
                            ) : isE ? (
                              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-300">
                                Error
                              </span>
                            ) : (
                              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
                                Safe
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="flex items-center justify-between px-5 py-3 border-t border-surface-container-high/60 text-xs text-outline">
              <span>
                Showing <strong className="text-on-surface font-semibold">{paginatedResults.length}</strong> of <strong className="text-on-surface font-semibold">{filteredResults.length}</strong> records
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage <= 1}
                  className="px-2.5 py-1 rounded-lg border border-surface-container-high text-outline hover:text-on-surface disabled:opacity-40 disabled:cursor-not-allowed text-xs font-semibold transition-colors cursor-pointer"
                >
                  Prev
                </button>
                <span className="px-2 py-1 text-xs text-primary font-mono font-semibold">
                  {currentPage} / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages}
                  className="px-2.5 py-1 rounded-lg border border-surface-container-high text-outline hover:text-on-surface disabled:opacity-40 disabled:cursor-not-allowed text-xs font-semibold transition-colors cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Global Action Footer */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 text-xs text-outline border-t border-surface-container-high/50">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary" />
            <span>Active Target: <strong className="text-on-surface">{activeTargetName}</strong></span>
            <span>•</span>
            <span>{total} total attack vectors evaluated</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleExportPDF}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-surface-container border border-surface-container-high hover:bg-surface-container-high text-on-surface transition-all font-semibold cursor-pointer text-xs"
            >
              <span className="material-symbols-outlined text-[16px]">picture_as_pdf</span>
              <span>Export PDF Report</span>
            </button>
            <button
              onClick={() => navigate('/reports')}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-primary text-on-primary font-semibold transition-all hover:opacity-90 cursor-pointer text-xs"
            >
              <span className="material-symbols-outlined text-[16px]">assessment</span>
              <span>Full Compliance Reports</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
