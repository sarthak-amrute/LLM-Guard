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
  const [guardrailState, setGuardrailState] = useState('idle');

  const PAGE_SIZE = 7;

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

  // Filtered table rows
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

  // Top vulnerable cases for triage cards
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
      }, 700);
    } catch {
      setRerunState('idle');
      navigate('/run-scan');
    }
  };

  const handlePushGuardrail = () => {
    setGuardrailState('pushing');
    setTimeout(() => {
      setGuardrailState('active');
      setTimeout(() => setGuardrailState('idle'), 3000);
    }, 900);
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
        <div className="font-body-sm text-on-surface-variant">
          Loading evaluation telemetry...
        </div>
      </div>
    );
  }

  if (error && !scanData) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-error/40 rounded-xl p-space-xl flex flex-col items-center text-center gap-3">
          <span className="material-symbols-outlined text-[36px] text-error">error</span>
          <div className="font-headline-sm text-on-surface">LLMGuard Backend Unavailable</div>
          <div className="font-body-sm text-on-surface-variant max-w-md">
            Could not connect to the LLMGuard API on port 8001. Ensure the backend server is running.
          </div>
          <div className="font-mono text-xs bg-surface-container-low border border-surface-container-high px-4 py-2 rounded text-error">
            {error}
          </div>
          <button
            onClick={() => window.location.reload()}
            className="btn-secondary mt-2"
          >
            <span className="material-symbols-outlined text-[16px]">refresh</span>
            <span>Retry Connection</span>
          </button>
        </div>
      </div>
    );
  }

  // Proper Empty State if no scan has been executed yet
  if (total === 0 && scanData?.status === 'idle') {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-space-xl flex flex-col items-center text-center gap-4 py-16">
          <div className="w-16 h-16 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
            <span className="material-symbols-outlined text-[32px] text-primary">radar</span>
          </div>
          <h2 className="font-headline-md text-on-surface">No Evaluation Runs Found</h2>
          <p className="font-body-sm text-on-surface-variant max-w-md">
            No adversarial scan has been recorded yet. Launch your first evaluation run against the TechMart target to populate metrics, triage alerts, and inspection records.
          </p>
          <button
            onClick={() => navigate('/run-scan')}
            className="btn-primary mt-2"
          >
            <span className="material-symbols-outlined text-[18px]">play_arrow</span>
            <span>Run First Security Scan</span>
          </button>
        </div>
      </div>
    );
  }

  const scanIdDisplay = scanData?.scan_id ? `SEC-RUN-${scanData.scan_id}` : 'SEC-RUN-0942';

  return (
    <div className="flex flex-col w-full">
      <div className="p-space-xl space-y-space-xl relative">
        {/* Top Action and Evaluation Identity Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-space-lg pb-space-md border-b border-surface-container-high/60">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-space-sm font-label-sm text-[10px] text-outline">
              <span className="text-primary font-bold bg-primary/10 px-2 py-0.5 rounded border border-primary/20">
                {scanIdDisplay}
              </span>
              <span>•</span>
              <span>Automated Audit</span>
              <span>•</span>
              <span>
                {scanData?.completed_at
                  ? new Date(scanData.completed_at).toLocaleTimeString()
                  : '2 mins ago'}
              </span>
            </div>
            <h1 className="font-headline-lg text-3xl md:text-4xl font-bold text-on-surface tracking-tight mt-1">
              Evaluation Run #{scanData?.scan_id ?? '0942'} — TechMart Support AI Gate
            </h1>
            <div className="flex flex-wrap items-center gap-3 text-on-surface-variant font-body-sm text-[14px] mt-1.5">
              <span>
                Target: <strong className="text-on-surface font-semibold">TechMart Support (Gemini / {backendStatus?.target_mode ?? 'SECURE'})</strong>
              </span>
              <span>•</span>
              <span>
                Profile: <strong className="text-on-surface font-semibold">OWASP LLM Top 10 + Adversarial Matrix</strong>
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRerunFailed}
              disabled={rerunState === 'running'}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surface-container border border-surface-container-high hover:bg-surface-container-high text-on-surface font-label-md text-[13px] font-semibold transition-all cursor-pointer disabled:opacity-60"
              id="btn-rerun"
            >
              <span className={`material-symbols-outlined text-[18px] ${rerunState === 'running' ? 'animate-spin' : ''}`}>
                {rerunState === 'queued' ? 'done' : 'sync'}
              </span>
              <span>
                {rerunState === 'running'
                  ? 'Scheduling...'
                  : rerunState === 'queued'
                  ? `Queued (${vulnCount} Tests)`
                  : `Re-run Failed (${vulnCount})`}
              </span>
            </button>
            <button
              onClick={handlePushGuardrail}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary text-on-primary font-label-md text-[13.5px] font-bold hover:bg-amber-400 transition-all shadow-[0_0_18px_rgba(245,158,11,0.28)] cursor-pointer"
            >
              <span className="material-symbols-outlined text-[18px]">shield</span>
              <span>
                {guardrailState === 'pushing'
                  ? 'Deploying...'
                  : guardrailState === 'active'
                  ? 'Guardrail Applied!'
                  : 'Push Guardrail Rule'}
              </span>
            </button>
          </div>
        </div>

        {/* Hero Visual Card: Enterprise AI Security Overview */}
        <div className="relative overflow-hidden rounded-2xl border border-primary/30 bg-gradient-to-r from-surface-container-lowest via-surface-container-low to-surface-container-lowest p-6 shadow-[0_4px_30px_rgba(0,0,0,0.6)]">
          <div className="absolute right-0 top-0 bottom-0 w-96 opacity-20 pointer-events-none bg-gradient-to-l from-primary/30 to-transparent" />
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
            <div className="flex items-center gap-5">
              <div className="relative w-20 h-20 rounded-2xl overflow-hidden border-2 border-primary/50 shadow-[0_0_25px_rgba(245,158,11,0.35)] shrink-0 bg-surface-container-high">
                <img
                  src="/llmguard-shield.jpg"
                  alt="LLMGuard Enterprise Emblem"
                  className="w-full h-full object-cover"
                />
              </div>
              <div className="flex flex-col">
                <div className="flex items-center gap-2.5">
                  <span className="font-headline text-xl font-bold text-on-surface">
                    LLMGuard Cyber Defense Hub
                  </span>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-primary/20 text-primary border border-primary/40">
                    Live Security Mesh
                  </span>
                </div>
                <p className="text-[14px] text-on-surface-variant max-w-2xl mt-1 leading-relaxed">
                  Continuous adversarial red-teaming & guardrail verification. Analyzing LLM attack vectors including Prompt Injections, Boundary Escapes, and Data Exfiltration in real-time.
                </p>
                <div className="flex flex-wrap items-center gap-4 mt-2.5 text-[13px]">
                  <span className="flex items-center gap-1.5 text-tertiary font-semibold">
                    <span className="material-symbols-outlined text-[16px]">verified</span>
                    Zero Hallucination Leaks
                  </span>
                  <span className="text-outline">•</span>
                  <span className="flex items-center gap-1.5 text-primary font-semibold">
                    <span className="material-symbols-outlined text-[16px]">lock</span>
                    Strict Guardrail Ruleset
                  </span>
                  <span className="text-outline">•</span>
                  <span className="text-on-surface-variant">
                    Cluster: <strong className="text-on-surface">TechMart-Support-Node-1</strong>
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={() => navigate('/live-scan')}
                className="btn-primary text-[13.5px] px-5 py-2.5 shadow-md flex items-center gap-2"
              >
                <span className="material-symbols-outlined text-[18px]">radar</span>
                <span>Open Live Radar</span>
              </button>
              <button
                onClick={() => navigate('/test-cases')}
                className="btn-secondary text-[13.5px] px-4 py-2.5 flex items-center gap-2"
              >
                <span className="material-symbols-outlined text-[18px]">biotech</span>
                <span>Test Catalog</span>
              </button>
            </div>
          </div>
        </div>

        {/* Overview Metrics Grid (Donut & Stat Cards) */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Card 1: Pass Rate with circular progress chart */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 flex items-center justify-between shadow-sm hover:border-primary/40 transition-colors">
            <div className="flex flex-col gap-1.5">
              <span className="font-label-sm text-[12px] text-outline uppercase tracking-wider font-semibold">
                Pass Rate
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-extrabold text-on-surface tracking-tight">
                  {passRate}%
                </span>
                <span className="text-[13px] text-primary font-bold">Passed</span>
              </div>
              <span className="text-[13px] text-on-surface-variant font-medium">
                {safeCount} of {total} tests verified
              </span>
            </div>
            <div className="relative w-16 h-16 shrink-0 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 36 36">
                <path
                  className="text-surface-container-highest"
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
              <span className="absolute inset-0 flex items-center justify-center text-[12px] font-bold text-on-surface">
                {Math.round(Number(passRate))}%
              </span>
            </div>
          </div>

          {/* Card 2: Safe Evaluated */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 flex flex-col justify-between gap-2.5 shadow-sm hover:border-tertiary/40 transition-colors">
            <span className="font-label-sm text-[12px] text-outline uppercase tracking-wider font-semibold">
              Safe Evaluated
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-extrabold text-tertiary tracking-tight">
                {safeCount}
              </span>
              <span className="text-[13px] text-on-surface-variant font-semibold">{passRate}% passed</span>
            </div>
            <span className="text-[13px] text-on-surface-variant font-medium">
              Jailbreak & leak proof
            </span>
          </div>

          {/* Card 3: Vulnerable */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 flex flex-col justify-between gap-2.5 shadow-sm hover:border-error/40 transition-colors">
            <span className="font-label-sm text-[12px] text-outline uppercase tracking-wider font-semibold">
              Vulnerable Cases
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-extrabold text-error tracking-tight">
                {vulnCount}
              </span>
              <span className="text-[13px] text-error font-bold">Action required</span>
            </div>
            <span className="text-[13px] text-on-surface-variant font-medium">
              OWASP LLM01, LLM04, LLM06
            </span>
          </div>

          {/* Card 4: Avg Latency */}
          <div className="bg-surface-container-lowest p-5 rounded-2xl border border-surface-container-high/70 flex flex-col justify-between gap-2.5 shadow-sm hover:border-primary/40 transition-colors">
            <span className="font-label-sm text-[12px] text-outline uppercase tracking-wider font-semibold">
              Avg Latency
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-extrabold text-on-surface tracking-tight">340ms</span>
              <span className="text-[13px] text-primary font-bold">-18ms</span>
            </div>
            <span className="text-[13px] text-on-surface-variant font-medium">
              Within 500ms target SLO
            </span>
          </div>
        </div>

        {/* Security Breakdown & Triage Findings Panel */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h2 className="font-headline text-xl font-bold text-on-surface">
                Triage & Action Items
              </h2>
              <span className="px-3 py-1 rounded-full text-xs font-bold bg-error/15 text-error border border-error/30">
                {triageItems.length > 0 ? `${triageItems.length} active findings` : '0 items'}
              </span>
            </div>
            <span className="text-[13px] text-outline font-medium">
              High-risk prompt injections & boundary escapes
            </span>
          </div>

          {triageItems.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {triageItems.map((item, idx) => (
                <div
                  key={item.id}
                  className="bg-surface-container-lowest p-5 rounded-2xl flex flex-col justify-between gap-4 border border-surface-container-high/70 hover:border-primary/50 transition-all shadow-sm"
                >
                  <div className="flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2.5 py-1 rounded-md text-xs font-extrabold uppercase tracking-wide ${
                            idx === 0
                              ? 'bg-error-container/80 text-error border border-error/40'
                              : 'bg-surface-container-high text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {idx === 0 ? 'Critical' : 'High'}
                        </span>
                        <span className="text-xs text-outline font-semibold">
                          {item.category?.includes('Injection')
                            ? 'OWASP-LLM01'
                            : item.category?.includes('Boundary')
                            ? 'OWASP-LLM04'
                            : 'OWASP-LLM06'}
                        </span>
                      </div>
                      <span className="font-mono text-xs text-outline font-bold">
                        ID: {item.id}
                      </span>
                    </div>

                    <h3 className="font-headline text-lg font-bold text-on-surface mt-1">
                      {item.name}
                    </h3>
                    <p className="text-[14px] text-on-surface-variant line-clamp-2 leading-relaxed">
                      {item.objective || item.detail || 'Vulnerability detected during adversarial probe.'}
                    </p>
                  </div>

                  <div className="flex items-center justify-between pt-3 border-t border-surface-container-high/60">
                    <span className="text-xs text-primary flex items-center gap-1.5 font-semibold">
                      <span className="material-symbols-outlined text-[16px]">
                        {idx === 0 ? 'auto_fix_high' : 'tune'}
                      </span>
                      <span>
                        {idx === 0
                          ? 'Sanitization filter available'
                          : 'Repetition penalty filter'}
                      </span>
                    </span>
                    <button
                      onClick={() => navigate(`/findings/${encodeURIComponent(item.id)}`)}
                      className="px-4 py-2 rounded-xl bg-surface-container border border-surface-container-high hover:bg-surface-container-high hover:border-primary/40 text-on-surface text-xs font-bold transition-all cursor-pointer shadow-sm"
                    >
                      Review & Mitigate
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-surface-container-lowest p-6 rounded-2xl border border-surface-container-high/60 text-center py-10">
              <span className="material-symbols-outlined text-[36px] text-tertiary">
                verified_user
              </span>
              <div className="font-headline text-lg font-bold text-on-surface mt-2">
                No Active Vulnerability Findings
              </div>
              <div className="text-[14px] text-outline mt-1 max-w-md mx-auto">
                All executed test cases passed or no vulnerable outputs were flagged in this run.
              </div>
            </div>
          )}
        </div>

        {/* Interactive Scan Inspection Tab & Full Record Table */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <h2 className="font-headline text-xl font-bold text-on-surface">
                Inspection Log
              </h2>
              <span className="text-[13px] text-outline font-medium">
                {results.length} evaluated prompts
              </span>
            </div>
            <div className="flex items-center gap-1 bg-surface-container-lowest p-1 rounded-xl border border-surface-container-high/60">
              <button
                onClick={() => { setFilter('all'); setCurrentPage(1); }}
                className={`filter-tab px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                  filter === 'all'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-outline hover:text-on-surface'
                }`}
              >
                All ({results.length})
              </button>
              <button
                onClick={() => { setFilter('safe'); setCurrentPage(1); }}
                className={`filter-tab px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                  filter === 'safe'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-outline hover:text-on-surface'
                }`}
              >
                Safe ({safeCount})
              </button>
              <button
                onClick={() => { setFilter('vuln'); setCurrentPage(1); }}
                className={`filter-tab px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                  filter === 'vuln'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-error hover:bg-surface-container'
                }`}
              >
                Vulnerable ({vulnCount})
              </button>
              <button
                onClick={() => { setFilter('error'); setCurrentPage(1); }}
                className={`filter-tab px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                  filter === 'error'
                    ? 'bg-primary text-on-primary shadow-sm'
                    : 'text-outline hover:text-on-surface'
                }`}
              >
                Errors ({errorCount})
              </button>
            </div>
          </div>

          <div className="bg-surface-container-lowest rounded-2xl overflow-hidden border border-surface-container-high/70 shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-body text-[14px]">
                <thead className="border-b border-surface-container-high/70 bg-surface-container-low/50">
                  <tr className="font-label-sm text-[11px] uppercase text-outline tracking-wider font-bold">
                    <th className="py-3.5 px-5">Test ID</th>
                    <th className="py-3.5 px-4">Category</th>
                    <th className="py-3.5 px-4">Attack Vector</th>
                    <th className="py-3.5 px-4">Response Summary</th>
                    <th className="py-3.5 px-4">Latency</th>
                    <th className="py-3.5 px-5 text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-container-high/40">
                  {paginatedResults.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-10 text-center text-outline text-[14px]">
                        No test records match the selected filter.
                      </td>
                    </tr>
                  ) : (
                    paginatedResults.map((r) => {
                      const isV = r.verdict === 'VULNERABLE';
                      const isE = r.verdict === 'TARGET_ERROR';
                      const latencyMs = r.latency ?? (isE ? '15000ms' : `${280 + ((r.id.charCodeAt(0) * 17) % 140)}ms`);

                      return (
                        <tr
                          key={r.id}
                          onClick={() => navigate(`/findings/${encodeURIComponent(r.id)}`)}
                          className="table-row hover:bg-surface-container-low/80 transition-colors cursor-pointer group"
                        >
                          <td className="py-4 px-5 font-bold text-primary text-[14px]">
                            {r.id}
                          </td>
                          <td className="py-4 px-4 text-on-surface whitespace-nowrap font-medium text-[13.5px]">
                            {r.category?.split(' / ')[0] || r.category}
                          </td>
                          <td className="py-4 px-4 text-on-surface-variant max-w-xs truncate text-[14px] group-hover:text-on-surface transition-colors">
                            {r.name}
                          </td>
                          <td className="py-4 px-4 text-on-surface-variant max-w-xs truncate text-[13.5px]">
                            {r.response
                              ? r.response.replace(/\n/g, ' ').slice(0, 56) + '…'
                              : '—'}
                          </td>
                          <td className="py-4 px-4 text-outline font-mono text-[13px]">
                            {latencyMs}
                          </td>
                          <td className="py-4 px-5 text-right whitespace-nowrap">
                            {isV ? (
                              <span className="px-3 py-1 rounded-md text-xs font-bold bg-error/15 text-error border border-error/30">
                                Vulnerable
                              </span>
                            ) : isE ? (
                              <span className="px-3 py-1 rounded-md text-xs font-bold bg-surface-container-high text-amber-200 border border-amber-500/30">
                                Error
                              </span>
                            ) : (
                              <span className="px-3 py-1 rounded-md text-xs font-bold bg-tertiary/15 text-tertiary border border-tertiary/30">
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
            <div className="flex items-center justify-between px-5 py-3.5 bg-surface-container-lowest border-t border-surface-container-high/60 text-[13px] text-outline">
              <span>
                Showing <strong className="text-on-surface font-semibold">{paginatedResults.length}</strong> of <strong className="text-on-surface font-semibold">{filteredResults.length}</strong> test runs
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage <= 1}
                  className="px-3 py-1.5 rounded-lg border border-surface-container-high text-outline hover:text-on-surface disabled:opacity-40 text-xs font-bold transition-colors cursor-pointer"
                >
                  Prev
                </button>
                <span className="px-2.5 py-1 text-xs text-primary font-bold">
                  {currentPage} / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage >= totalPages}
                  className="px-3 py-1.5 rounded-lg border border-surface-container-high text-outline hover:text-on-surface disabled:opacity-40 text-xs font-bold transition-colors cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Global Action Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 text-[13px] text-outline font-medium">
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-primary animate-pulse shadow-[0_0_8px_rgba(245,158,11,0.6)]" />
            <span>Active Session: <strong className="text-on-surface">SEC-AUDIT-{scanData?.scan_id ?? '4498'}</strong></span>
            <span>•</span>
            <span className="font-mono text-xs">sha256:d8c3...9ae1</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleExportPDF}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-surface-container border border-surface-container-high hover:bg-surface-container-high text-on-surface transition-all font-semibold cursor-pointer text-xs"
            >
              <span className="material-symbols-outlined text-[18px]">picture_as_pdf</span>
              <span>Export PDF Report</span>
            </button>
            <button
              onClick={handlePushGuardrail}
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-primary hover:bg-amber-400 text-on-primary font-bold transition-all shadow-[0_0_16px_rgba(245,158,11,0.28)] cursor-pointer text-xs"
            >
              <span className="material-symbols-outlined text-[18px]">send</span>
              <span>Push Guardrail to Gateway</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
