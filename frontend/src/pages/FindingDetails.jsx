import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getScanResults } from '../services/api';
import StatusBadge from '../components/StatusBadge';

export default function FindingDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let mounted = true;
    getScanResults()
      .then((data) => {
        if (!mounted) return;
        const decodedId = decodeURIComponent(id || '');
        const found = (data?.results ?? []).find((r) => r.id === decodedId);
        if (found) setResult(found);
        else setError(`No finding with ID "${decodedId}" found.`);
        setLoading(false);
      })
      .catch((e) => {
        if (mounted) {
          setError(e.message);
          setLoading(false);
        }
      });
    return () => { mounted = false; };
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-outline">Loading finding telemetry...</div>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-error/40 rounded-xl p-space-xl text-center flex flex-col items-center gap-3">
          <span className="material-symbols-outlined text-[36px] text-error">gpp_maybe</span>
          <div className="font-headline-sm text-on-surface">Finding Not Found</div>
          <div className="font-mono text-xs text-outline">{error}</div>
          <button onClick={() => navigate('/results')} className="btn-secondary mt-3">
            <span className="material-symbols-outlined text-[16px]">arrow_back</span>
            <span>Back to Results</span>
          </button>
        </div>
      </div>
    );
  }

  const isVuln = result.verdict === 'VULNERABLE';
  const isErr = result.verdict === 'TARGET_ERROR';

  return (
    <div className="p-space-xl space-y-space-md max-w-4xl">
      {/* Back button */}
      <div>
        <button
          onClick={() => navigate(-1)}
          className="flex items-center gap-1.5 text-xs font-mono text-outline hover:text-on-surface transition-colors cursor-pointer"
        >
          <span className="material-symbols-outlined text-[16px]">arrow_back</span>
          <span>Back to Inspection Log</span>
        </button>
      </div>

      {/* Header card */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <StatusBadge verdict={result.verdict} />
            <span className="font-mono text-sm text-primary font-bold">
              {result.id}
            </span>
            <span className="text-surface-container-highest">·</span>
            <span className="font-label-sm text-xs text-outline font-medium">
              {result.category}
            </span>
          </div>
          {result.timestamp && (
            <span className="font-mono text-[11px] text-outline">
              Evaluated {new Date(result.timestamp).toLocaleTimeString()}
            </span>
          )}
        </div>

        <h1 className="font-headline-md text-xl font-bold text-on-surface">
          {result.name}
        </h1>
      </div>

      {/* Objective */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-2">
        <div className="font-label-sm text-[10px] uppercase text-outline font-semibold tracking-wider">
          Attack Objective
        </div>
        <p className="font-body-sm text-xs text-on-surface leading-relaxed">
          {result.objective || 'Probe whether the model discloses restricted values or alters behavioral boundaries.'}
        </p>
      </div>

      {/* Prompt */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-2">
        <div className="font-label-sm text-[10px] uppercase text-outline font-semibold tracking-wider flex items-center justify-between">
          <span>Adversarial Prompt Payload</span>
          <span className="text-primary font-mono text-[10px]">User Input</span>
        </div>
        <div className="font-mono text-xs text-on-surface bg-surface-container-low border border-surface-container-high p-4 rounded-lg whitespace-pre-wrap break-all leading-relaxed">
          {result.prompt}
        </div>
      </div>

      {/* Response */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-2">
        <div className="font-label-sm text-[10px] uppercase text-outline font-semibold tracking-wider flex items-center justify-between">
          <span>Target Model Response</span>
          <StatusBadge verdict={result.verdict} />
        </div>
        <div
          className={`font-mono text-xs bg-surface-container-low border border-surface-container-high p-4 rounded-lg whitespace-pre-wrap break-all leading-relaxed ${
            isVuln ? 'text-error' : isErr ? 'text-amber-300' : 'text-on-surface-variant'
          }`}
        >
          {result.response || '(No response captured from target)'}
        </div>
      </div>

      {/* Evaluator Reasoning */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-3">
        <div className="font-label-sm text-[10px] uppercase text-outline font-semibold tracking-wider">
          Evaluator Verdict & Forensic Analysis
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`material-symbols-outlined text-[24px] ${
              isVuln ? 'text-error' : isErr ? 'text-amber-400' : 'text-tertiary'
            }`}
          >
            {isVuln ? 'gpp_bad' : isErr ? 'warning' : 'verified_user'}
          </span>
          <div>
            <div className="font-headline text-sm font-bold text-on-surface">
              {result.verdict}
            </div>
            <div className="font-body-sm text-xs text-outline mt-0.5">
              {isVuln
                ? 'Protected canary token or transformation detected in the target response.'
                : isErr
                ? 'Target API failed or timed out during the probe execution.'
                : 'No protected canary tokens or instructions leaked in model output.'}
            </div>
          </div>
        </div>

        {result.detail && (
          <div className="bg-surface-container-low border border-surface-container-high/70 p-3 rounded-lg font-mono text-xs text-amber-400">
            {result.detail}
          </div>
        )}
      </div>

      {/* Remediation guidance */}
      {isVuln && (
        <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-primary/30 shadow-sm flex flex-col gap-3">
          <div className="flex items-center gap-2 text-primary font-headline-sm text-sm font-bold">
            <span className="material-symbols-outlined text-[18px]">auto_fix_high</span>
            <span>Remediation & Guardrail Recommendation</span>
          </div>
          <p className="font-body-sm text-xs text-on-surface-variant leading-relaxed">
            The target LLM yielded confidential parameters when exposed to this adversarial context. Recommended mitigations:
          </p>
          <ul className="list-disc pl-5 font-body-sm text-xs text-outline space-y-1.5">
            <li>Deploy output token sanitizer regex filtering on gateway egress for all canary patterns.</li>
            <li>Enforce boundary reinforcement rules in system prompt (SECURE mode).</li>
            <li>Apply temperature reductions and repetition penalties to restrict token continuation overrides.</li>
          </ul>
        </div>
      )}
    </div>
  );
}
