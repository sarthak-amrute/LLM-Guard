import { useState, useEffect } from 'react';
import { getStatus } from '../services/api';

function StatusRow({ label, value, mono = false, color }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-surface-container-high/40 last:border-b-0">
      <span className="font-body-sm text-xs text-outline">{label}</span>
      <span
        className={`text-xs ${mono ? 'font-mono font-semibold' : 'font-body-sm'} ${
          color ?? 'text-on-surface'
        }`}
      >
        {value ?? '—'}
      </span>
    </div>
  );
}

export default function Settings() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    getStatus()
      .then((d) => { if (mounted) { setStatus(d); setLoading(false); } })
      .catch(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  return (
    <div className="p-space-xl space-y-space-lg w-full max-w-3xl">
      {/* Header */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
          <span className="material-symbols-outlined text-primary text-[22px]">settings</span>
        </div>
        <div>
          <h1 className="font-headline-sm text-base font-bold text-on-surface">
            SecOps Suite Configuration & Settings
          </h1>
          <div className="font-mono text-xs text-outline mt-0.5">
            Gateway telemetry, service orchestration, and environment variables
          </div>
        </div>
      </div>

      {/* About Box */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-3">
        <div className="font-headline-sm text-sm font-semibold text-on-surface">
          About LLMGuard SecOps Engine
        </div>
        <p className="font-body-sm text-xs text-on-surface-variant leading-relaxed">
          LLMGuard is an adversarial testing and security evaluation suite purpose-built for LLM-driven applications. It systematically generates OWASP LLM Top 10 exploits, prompt injections, boundary bypasses, and data exfiltration vectors against target endpoints, evaluating canary token preservation and refusal integrity.
        </p>
      </div>

      {/* Live System Diagnostics */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm space-y-2">
        <div className="font-headline-sm text-sm font-semibold text-on-surface mb-2">
          Subsystem Diagnostics
        </div>
        {loading ? (
          <div className="font-body-sm text-xs text-outline">Querying endpoints…</div>
        ) : (
          <div className="divide-y divide-surface-container-high/40">
            <StatusRow
              label="LLMGuard API Engine"
              value={status?.llmguard === 'running' ? 'Operational (Online)' : 'Offline'}
              mono
              color={status?.llmguard === 'running' ? 'text-tertiary' : 'text-error'}
            />
            <StatusRow label="LLMGuard REST Port" value="8001" mono />
            <StatusRow label="Target System Name" value="TechMart Customer Support AI" />
            <StatusRow label="Target Port" value="8000" mono />
            <StatusRow
              label="Target Connectivity"
              value={status?.target_online ? 'Reachable' : 'Unreachable'}
              mono
              color={status?.target_online ? 'text-tertiary' : 'text-amber-400'}
            />
            <StatusRow
              label="Target Active Mode"
              value={status?.target_mode ?? 'UNKNOWN'}
              mono
              color={status?.target_mode === 'VULNERABLE' ? 'text-error' : 'text-tertiary'}
            />
            <StatusRow
              label="Scan Engine State"
              value={status?.scan_status ? status.scan_status.toUpperCase() : 'IDLE'}
              mono
              color="text-primary"
            />
          </div>
        )}
      </div>

      {/* Orchestration Commands */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm space-y-3">
        <div className="font-headline-sm text-sm font-semibold text-on-surface">
          Deployment & Service Run Commands
        </div>
        <div className="space-y-3">
          {[
            {
              label: 'Target Backend (TechMart)',
              cmd: 'cd "TechMart Support" && uvicorn app.main:app --port 8000',
            },
            {
              label: 'LLMGuard API Server',
              cmd: 'cd LLMGuard/app && python server.py',
            },
            {
              label: 'Frontend SPA Client',
              cmd: 'cd frontend && npm run dev',
            },
          ].map(({ label, cmd }) => (
            <div key={label} className="space-y-1">
              <span className="font-label-sm text-[10px] uppercase text-outline font-semibold">
                {label}
              </span>
              <div className="font-mono text-xs text-on-surface bg-surface-container-low border border-surface-container-high p-3 rounded-lg select-all">
                {cmd}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
