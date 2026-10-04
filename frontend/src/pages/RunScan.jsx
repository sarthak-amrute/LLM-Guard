import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAttacks, getTargetMode, setTargetMode, startScan } from '../services/api';
import { useStatus } from '../context/useStatus';

const ALL_CATEGORIES = [
  'Direct Prompt Injection',
  'System Prompt / Instruction Extraction',
  'Role / Authority Manipulation',
  'Indirect Prompt Injection / RAG Poisoning',
  'Sensitive Information Extraction',
  'Transformation / Encoding Attack',
  'Context Manipulation / Multi-step Attack',
  'Instruction Boundary Testing',
];

export default function RunScan() {
  const navigate = useNavigate();
  const { refreshStatus } = useStatus();

  const [targetInfo, setTargetInfo] = useState(null);
  const [attackCount, setAttackCount] = useState(null);
  const [selectedMode, setSelectedMode] = useState('SECURE');
  const [selectedCats, setSelectedCats] = useState(new Set(ALL_CATEGORIES));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [modeData, attackData] = await Promise.all([getTargetMode(), getAttacks()]);
        if (!mounted) return;
        setTargetInfo(modeData);
        setAttackCount(attackData.total);
        setSelectedMode(modeData.mode === 'VULNERABLE' ? 'VULNERABLE' : 'SECURE');
      } catch (e) {
        if (mounted) setError(e.message);
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => { mounted = false; };
  }, []);

  const toggleCat = (cat) => {
    setSelectedCats((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedCats.size === ALL_CATEGORIES.length) setSelectedCats(new Set());
    else setSelectedCats(new Set(ALL_CATEGORIES));
  };

  const handleModeChange = async (mode) => {
    setSelectedMode(mode);
    try {
      await setTargetMode(mode);
      await refreshStatus();
      setTargetInfo((prev) => ({ ...prev, mode }));
    } catch (e) {
      setError(`Failed to set mode: ${e.message}`);
    }
  };

  const handleStart = async () => {
    if (selectedCats.size === 0) return;
    setLaunching(true);
    setError(null);
    try {
      const cats = selectedCats.size === ALL_CATEGORIES.length ? undefined : [...selectedCats];
      await startScan({ mode: selectedMode, categories: cats });
      await refreshStatus();
      navigate('/live-scan');
    } catch (e) {
      setError(e.message);
      setLaunching(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-outline">Loading target configuration…</div>
      </div>
    );
  }

  const isTargetOffline = !targetInfo?.online;

  return (
    <div className="p-space-xl space-y-space-lg max-w-5xl">
      {/* Page Header */}
      <div className="flex flex-col gap-1 pb-space-md border-b border-surface-container-high/60">
        <div className="flex items-center gap-space-sm font-label-sm text-[10px] text-outline">
          <span className="text-primary font-bold bg-primary/10 px-2 py-0.5 rounded border border-primary/20">
            SEC-DISPATCH
          </span>
          <span>•</span>
          <span>Adversarial Testing Setup</span>
        </div>
        <h1 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight mt-1">
          Configure & Launch Security Scan
        </h1>
        <p className="font-body-sm text-on-surface-variant">
          Select target operational parameters, safety profile mode, and adversarial attack categories.
        </p>
      </div>

      {/* Target offline alert */}
      {isTargetOffline && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-space-md flex items-center gap-3">
          <span className="material-symbols-outlined text-amber-400 text-[24px]">warning</span>
          <div>
            <div className="font-headline text-xs font-bold text-amber-400">
              TechMart target service is unreachable
            </div>
            <div className="font-body-sm text-xs text-outline mt-0.5">
              Please start the TechMart Support backend on port 8000 before initiating an adversarial scan.
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-error-container/40 border border-error/40 rounded-xl p-space-md font-mono text-xs text-error">
          {error}
        </div>
      )}

      {/* Target Info */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm">
        <div className="font-headline-sm text-sm font-semibold text-on-surface mb-3 flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-[18px]">dns</span>
          <span>Target Configuration</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {[
            { label: 'Target System', value: 'TechMart Customer Support AI' },
            { label: 'Base URL', value: 'http://127.0.0.1:8000' },
            { label: 'Chat Endpoint', value: '/chat' },
            { label: 'Status', value: isTargetOffline ? 'Offline' : 'Online', color: isTargetOffline ? 'text-amber-400' : 'text-tertiary' },
            { label: 'Current Mode', value: targetInfo?.mode ?? '—', color: targetInfo?.mode === 'VULNERABLE' ? 'text-error' : 'text-tertiary' },
            { label: 'Evaluation Model', value: 'Gemini 2.5 Flash / Pro' },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="bg-surface-container-low border border-surface-container-high/50 rounded-lg p-3"
            >
              <div className="font-label-sm text-[10px] text-outline uppercase">{label}</div>
              <div className={`font-mono text-xs font-semibold mt-1 truncate ${color ?? 'text-on-surface'}`}>
                {value}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Mode Selector */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm">
        <div className="font-headline-sm text-sm font-semibold text-on-surface mb-1 flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-[18px]">tune</span>
          <span>Target Operating Mode</span>
        </div>
        <p className="font-body-sm text-xs text-outline mb-4">
          Switch the target system prompt to test defense robustness under hardened vs weak boundary conditions.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {['SECURE', 'VULNERABLE'].map((mode) => {
            const active = selectedMode === mode;
            const isV = mode === 'VULNERABLE';
            return (
              <button
                key={mode}
                type="button"
                onClick={() => handleModeChange(mode)}
                className={`p-4 rounded-xl text-left border transition-all cursor-pointer ${
                  active
                    ? isV
                      ? 'bg-error/10 border-error text-error shadow-sm'
                      : 'bg-primary/10 border-primary text-primary shadow-sm'
                    : 'bg-surface-container-low border-surface-container-high hover:border-outline text-on-surface-variant'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-headline text-sm font-bold">
                    {mode} MODE
                  </span>
                  {active && (
                    <span className="font-label-sm text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-surface-container-highest">
                      Selected
                    </span>
                  )}
                </div>
                <div className="font-body-sm text-xs text-outline">
                  {isV
                    ? 'Weak system prompt with minimal refusal constraints. Intended for vulnerability demonstration.'
                    : 'Hardened system prompt with strict refusal instructions and canary protections.'}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Attack Category Selector */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm">
        <div className="flex items-center justify-between mb-1">
          <div className="font-headline-sm text-sm font-semibold text-on-surface flex items-center gap-2">
            <span className="material-symbols-outlined text-primary text-[18px]">biotech</span>
            <span>Adversarial Attack Categories</span>
          </div>
          <button
            type="button"
            onClick={toggleAll}
            className="font-label-sm text-xs text-primary hover:underline cursor-pointer"
          >
            {selectedCats.size === ALL_CATEGORIES.length ? 'Deselect All' : 'Select All'}
          </button>
        </div>
        <p className="font-body-sm text-xs text-outline mb-4">
          {attackCount !== null ? `${attackCount} total probes in attack generator library` : 'Loading attack vectors...'}
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {ALL_CATEGORIES.map((cat) => {
            const checked = selectedCats.has(cat);
            return (
              <label
                key={cat}
                className={`flex items-center gap-3 p-3 rounded-lg border transition-all cursor-pointer ${
                  checked
                    ? 'bg-primary/5 border-primary/30 text-on-surface'
                    : 'bg-surface-container-low border-surface-container-high/50 text-outline'
                }`}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggleCat(cat)}
                  className="rounded text-primary focus:ring-primary h-4 w-4 accent-amber-500"
                />
                <span className="font-body-sm text-xs font-medium">
                  {cat}
                </span>
              </label>
            );
          })}
        </div>
        <div className="mt-3 font-label-sm text-[11px] text-outline">
          {selectedCats.size} of {ALL_CATEGORIES.length} categories enabled
        </div>
      </div>

      {/* Action Footer */}
      <div className="flex items-center justify-between pt-2">
        <div className="font-body-sm text-xs text-outline">
          Tests execute sequentially in a background worker thread.
        </div>
        <button
          onClick={handleStart}
          disabled={isTargetOffline || launching || selectedCats.size === 0}
          className="btn-primary py-2.5 px-6 text-sm"
        >
          {launching ? (
            <>
              <span className="material-symbols-outlined text-[18px] animate-spin">refresh</span>
              <span>Launching Scan...</span>
            </>
          ) : (
            <>
              <span className="material-symbols-outlined text-[18px]">play_arrow</span>
              <span>Start Security Scan</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}
