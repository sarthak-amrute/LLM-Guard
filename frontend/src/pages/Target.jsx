import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getTargetMode, setTargetMode } from '../services/api';
import { useStatus } from '../context/useStatus';

export default function Target() {
  const navigate = useNavigate();
  const { status: globalStatus, refreshStatus } = useStatus();
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [switching, setSwitching] = useState(false);
  const [switchMsg, setSwitchMsg] = useState(null);

  const load = useCallback(async () => {
    try {
      const data = await getTargetMode();
      setInfo(data);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleSwitch = async (newMode) => {
    setSwitching(true);
    setSwitchMsg(null);
    try {
      const result = await setTargetMode(newMode);
      setInfo((prev) => ({ ...prev, mode: result.mode }));
      await refreshStatus();
      setSwitchMsg({ ok: true, text: `Target mode successfully switched to ${result.mode}` });
    } catch (e) {
      setSwitchMsg({ ok: false, text: `Switch failed: ${e.message}` });
    } finally {
      setSwitching(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-outline">Fetching target configuration…</div>
      </div>
    );
  }

  const isOnline = info?.online ?? globalStatus?.target_online;
  const currentMode = info?.mode ?? globalStatus?.target_mode ?? 'UNKNOWN';

  return (
    <div className="p-space-xl space-y-space-lg max-w-4xl">
      {/* Header */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-[22px]">dns</span>
          </div>
          <div>
            <h1 className="font-headline-sm text-base font-bold text-on-surface">
              Target Node & Cluster Configuration
            </h1>
            <div className="font-mono text-xs text-outline mt-0.5">TechMart Customer Support AI Gateway</div>
          </div>
        </div>

        <span
          className={`px-2.5 py-1 rounded-full text-xs font-mono font-semibold flex items-center gap-1.5 border ${
            isOnline
              ? 'bg-tertiary/15 text-tertiary border-tertiary/30'
              : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
          }`}
        >
          <span className="w-2 h-2 rounded-full bg-current" />
          <span>{isOnline ? 'Online (Port 8000)' : 'Offline'}</span>
        </span>
      </div>

      {/* Offline Alert */}
      {!isOnline && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-space-md flex items-center gap-3">
          <span className="material-symbols-outlined text-amber-400 text-[24px]">warning</span>
          <div>
            <div className="font-headline text-xs font-bold text-amber-400">
              TechMart Target API is currently offline
            </div>
            <div className="font-body-sm text-xs text-outline mt-0.5">
              Launch the target app via: <code className="text-primary font-mono">uvicorn app.main:app --port 8000</code>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-error-container/40 border border-error/40 rounded-xl p-space-md font-mono text-xs text-error">
          {error}
        </div>
      )}

      {/* Target Details */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm space-y-3">
        <div className="font-headline-sm text-sm font-semibold text-on-surface">
          API Endpoint Specifications
        </div>
        <div className="divide-y divide-surface-container-high/40">
          {[
            { label: 'Target Base URL', value: 'http://127.0.0.1:8000' },
            { label: 'Chat Probe Endpoint', value: 'POST /chat — Accepts { "message": "..." }, returns { "response": "..." }' },
            { label: 'Mode State Endpoint', value: 'GET /mode — Returns current active prompt security policy' },
            { label: 'Mode Command Endpoint', value: 'POST /mode — Body: { "mode": "SECURE" | "VULNERABLE" }' },
          ].map(({ label, value }) => (
            <div key={label} className="py-2.5 flex flex-col sm:flex-row sm:items-start gap-2">
              <span className="font-label-sm text-xs text-outline w-44 shrink-0 font-medium">
                {label}
              </span>
              <span className="font-mono text-xs text-on-surface leading-relaxed">
                {value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Mode Control */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm space-y-3">
        <div className="font-headline-sm text-sm font-semibold text-on-surface">
          Live Policy Switching
        </div>
        <p className="font-body-sm text-xs text-outline">
          Toggle the TechMart target between hardened guardrails and weakened boundaries to validate adversarial sensitivity.
        </p>

        {switchMsg && (
          <div
            className={`p-3 rounded-lg font-mono text-xs border ${
              switchMsg.ok
                ? 'bg-tertiary/10 border-tertiary/30 text-tertiary'
                : 'bg-error/10 border-error/30 text-error'
            }`}
          >
            {switchMsg.text}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
          {['SECURE', 'VULNERABLE'].map((mode) => {
            const active = currentMode === mode;
            const isV = mode === 'VULNERABLE';
            return (
              <button
                key={mode}
                onClick={() => handleSwitch(mode)}
                disabled={switching || !isOnline || active}
                className={`p-4 rounded-xl text-left border transition-all cursor-pointer ${
                  active
                    ? isV
                      ? 'bg-error/10 border-error text-error shadow-sm'
                      : 'bg-primary/10 border-primary text-primary shadow-sm'
                    : 'bg-surface-container-low border-surface-container-high hover:border-outline text-on-surface-variant'
                } disabled:opacity-50`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-headline text-sm font-bold">
                    {mode} MODE
                  </span>
                  {active && (
                    <span className="font-label-sm text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-surface-container-highest">
                      Active
                    </span>
                  )}
                </div>
                <div className="font-body-sm text-xs text-outline">
                  {isV
                    ? 'Weak instructions with minimal boundary enforcement.'
                    : 'Hardened system prompt with strict refusal instructions.'}
                </div>
              </button>
            );
          })}
        </div>

        <div className="pt-3 flex gap-3">
          <button onClick={() => navigate('/run-scan')} className="btn-primary">
            <span className="material-symbols-outlined text-[16px]">play_arrow</span>
            <span>Run Security Scan</span>
          </button>
          <button onClick={load} className="btn-secondary">
            <span className="material-symbols-outlined text-[16px]">refresh</span>
            <span>Refresh State</span>
          </button>
        </div>
      </div>
    </div>
  );
}
