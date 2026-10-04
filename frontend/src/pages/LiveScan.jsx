import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanStatus } from '../services/api';
import ScanProgress from '../components/ScanProgress';
import StatusBadge from '../components/StatusBadge';

export default function LiveScan() {
  const navigate = useNavigate();
  const [scanState, setScanState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const intervalRef = useRef(null);

  const poll = async () => {
    try {
      const data = await getScanStatus();
      setScanState(data);
      setError(null);
      if (data.status === 'completed' || data.status === 'error') {
        clearInterval(intervalRef.current);
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    poll();
    intervalRef.current = setInterval(poll, 1200);
    return () => clearInterval(intervalRef.current);
  }, []);

  const status = scanState?.status ?? 'idle';
  const isRunning = status === 'running';
  const isCompleted = status === 'completed';
  const isIdle = status === 'idle';

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          radar
        </span>
        <div className="font-body-sm text-outline">Connecting to scan engine…</div>
      </div>
    );
  }

  return (
    <div className="p-space-xl space-y-space-lg max-w-5xl">
      {/* Header bar */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span
            className={`material-symbols-outlined text-[28px] ${
              isRunning ? 'text-primary animate-pulse' : isCompleted ? 'text-tertiary' : 'text-outline'
            }`}
          >
            {isRunning ? 'radar' : isCompleted ? 'check_circle' : 'radio_button_unchecked'}
          </span>
          <div>
            <h1 className="font-headline-sm text-base font-bold text-on-surface">
              Live Telemetry & Evaluation Monitor
            </h1>
            <div className="font-mono text-[11px] text-outline mt-0.5">
              {scanState?.scan_id ? `Scan ID: ${scanState.scan_id}` : 'No active session'}
              {scanState?.mode ? ` · Mode: ${scanState.mode}` : ''}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <StatusBadge verdict={status} />
          {isCompleted && (
            <button
              onClick={() => navigate('/results')}
              className="btn-primary py-1.5 px-3.5 text-xs"
            >
              <span className="material-symbols-outlined text-[16px]">policy</span>
              <span>View Results</span>
            </button>
          )}
          {isIdle && (
            <button
              onClick={() => navigate('/run-scan')}
              className="btn-primary py-1.5 px-3.5 text-xs"
            >
              <span className="material-symbols-outlined text-[16px]">play_arrow</span>
              <span>Run Scan</span>
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-error-container/40 border border-error/40 rounded-xl p-space-md font-mono text-xs text-error">
          Backend error: {error}
        </div>
      )}

      {/* Idle view */}
      {isIdle && !error && (
        <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-space-xl flex flex-col items-center text-center gap-4 py-16">
          <span className="material-symbols-outlined text-[48px] text-surface-container-highest">
            radar
          </span>
          <div className="font-headline-sm text-on-surface">No Security Scan Running</div>
          <div className="font-body-sm text-outline max-w-sm">
            Launch an adversarial scan from the Run Scan page to monitor live payload execution and model verdicts.
          </div>
          <button onClick={() => navigate('/run-scan')} className="btn-primary mt-2">
            <span className="material-symbols-outlined text-[18px]">play_arrow</span>
            <span>Go to Run Scan</span>
          </button>
        </div>
      )}

      {/* Running or Completed Telemetry View */}
      {!isIdle && scanState && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-space-lg">
          {/* Progress & Timing */}
          <div className="flex flex-col gap-4">
            <ScanProgress
              status={scanState.status}
              total={scanState.total}
              completed={scanState.completed}
              currentAttack={scanState.current_attack}
              summary={scanState.summary}
            />

            {/* Timing Card */}
            <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-3">
              <div className="font-label-sm text-[10px] text-outline uppercase font-semibold">
                Timing Telemetry
              </div>
              <div className="flex flex-col gap-2">
                {[
                  {
                    label: 'Session Started',
                    value: scanState.started_at
                      ? new Date(scanState.started_at).toLocaleTimeString()
                      : '—',
                  },
                  {
                    label: 'Session Completed',
                    value: scanState.completed_at
                      ? new Date(scanState.completed_at).toLocaleTimeString()
                      : isRunning
                      ? 'In Progress…'
                      : '—',
                  },
                  {
                    label: 'Elapsed Duration',
                    value:
                      scanState.started_at && scanState.completed_at
                        ? `${Math.round(
                            (new Date(scanState.completed_at) - new Date(scanState.started_at)) /
                              1000
                          )}s`
                        : isRunning
                        ? 'Running…'
                        : '—',
                  },
                ].map(({ label, value }) => (
                  <div
                    key={label}
                    className="flex justify-between items-center text-xs py-1 border-b border-surface-container-high/30 last:border-b-0"
                  >
                    <span className="font-body-sm text-outline">{label}</span>
                    <span className="font-mono text-on-surface font-semibold">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Real-time Status Card */}
          <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-col gap-4">
            <div className="flex items-center gap-2">
              {isRunning && (
                <span className="w-2 h-2 rounded-full bg-primary animate-ping" />
              )}
              <span className="font-headline-sm text-sm font-semibold text-on-surface">
                Evaluation Activity Log
              </span>
            </div>

            {scanState.current_attack && isRunning && (
              <div className="bg-surface-container-low border border-primary/30 rounded-xl p-4 flex flex-col gap-2">
                <div className="font-label-sm text-[10px] text-primary uppercase font-bold tracking-wider">
                  Active Attack Execution
                </div>
                <div className="font-mono text-sm text-primary font-bold">
                  {scanState.current_attack.id}
                </div>
                <div className="font-headline text-xs font-semibold text-on-surface">
                  {scanState.current_attack.name}
                </div>
                <div className="font-body-sm text-xs text-outline">
                  Category: {scanState.current_attack.category}
                </div>
              </div>
            )}

            {isCompleted && (
              <div className="bg-surface-container-low border border-tertiary/30 rounded-xl p-6 text-center flex flex-col items-center gap-3">
                <span className="material-symbols-outlined text-tertiary text-[36px]">
                  check_circle
                </span>
                <div className="font-headline-sm text-base text-tertiary font-bold">
                  Evaluation Run Finished
                </div>
                <p className="font-body-sm text-xs text-on-surface-variant max-w-xs">
                  {scanState.summary?.VULNERABLE > 0
                    ? `${scanState.summary.VULNERABLE} vulnerability findings identified that need review and mitigation.`
                    : 'All test probes passed without leaking protected canary tokens.'}
                </p>
                <button
                  onClick={() => navigate('/results')}
                  className="btn-primary mt-2"
                >
                  <span className="material-symbols-outlined text-[16px]">policy</span>
                  <span>View Full Scan Results</span>
                </button>
              </div>
            )}

            <div className="flex-1 flex flex-col justify-end pt-4 border-t border-surface-container-high/50">
              <div className="flex items-center justify-between text-xs text-outline">
                <span>Progress: {scanState.completed} / {scanState.total}</span>
                <span>{isRunning ? 'Polling live (1.2s)' : 'Completed'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
