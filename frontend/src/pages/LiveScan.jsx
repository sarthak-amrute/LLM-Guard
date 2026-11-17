import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { getScanStatus, stopScan } from '../services/api';
import ScanProgress from '../components/ScanProgress';
import StatusBadge from '../components/StatusBadge';

export default function LiveScan() {
  const navigate = useNavigate();
  const [scanState, setScanState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stopError, setStopError] = useState('');
  const [stopping, setStopping] = useState(false);
  const [showStopConfirm, setShowStopConfirm] = useState(false);
  const intervalRef = useRef(null);

  useEffect(() => {
    let isMounted = true;
    const executePoll = async () => {
      try {
        const data = await getScanStatus();
        if (!isMounted) return;
        setScanState(data);
        setError(null);
        if (['completed', 'error', 'cancelled'].includes(data.status)) {
          clearInterval(intervalRef.current);
        }
      } catch (e) {
        if (!isMounted) return;
        setError(e.message);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    executePoll();
    intervalRef.current = setInterval(executePoll, 1200);
    return () => {
      isMounted = false;
      clearInterval(intervalRef.current);
    };
  }, []);

  const status = scanState?.status ?? 'idle';
  const isRunning = status === 'running';
  const isCompleted = status === 'completed';
  const isCancelled = status === 'cancelled';
  const isIdle = status === 'idle';
  const hasFinished = isCompleted || isCancelled;

  const requestStop = async () => {
    setStopping(true);
    setStopError('');
    try {
      await stopScan();
      setShowStopConfirm(false);
    } catch (cause) {
      setStopError(cause.message);
    } finally {
      setStopping(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          radar
        </span>
        <div className="font-body-sm text-outline text-sm">Connecting to scan engine…</div>
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
              isRunning ? 'text-primary animate-pulse' : isCompleted ? 'text-emerald-800' : isCancelled ? 'text-amber-800' : 'text-outline'
            }`}
          >
            {isRunning ? 'radar' : isCompleted ? 'check_circle' : isCancelled ? 'stop_circle' : 'radio_button_unchecked'}
          </span>
          <div>
            <h1 className="font-headline-sm text-base font-bold text-on-surface">
              Live Telemetry & Evaluation Monitor
            </h1>
            <div className="font-mono text-xs text-outline mt-0.5">
              {scanState?.scan_id ? `Scan ID: ${scanState.scan_id}` : 'No active session'}
              {scanState?.target_info ? ` · Target: ${scanState.target_info.name} (${scanState.target_info.provider.toUpperCase()})` : scanState?.mode ? ` · Mode: ${scanState.mode}` : ''}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <StatusBadge verdict={status} />
          {isRunning && (
            <button
              type="button"
              onClick={() => setShowStopConfirm(true)}
              disabled={stopping || scanState.stop_requested || scanState.finalizing}
              className="rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-bold text-red-800 hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50 cursor-pointer"
            >
              {scanState.finalizing ? 'Finalizing…' : stopping || scanState.stop_requested ? 'Stopping…' : 'Stop Scan'}
            </button>
          )}
          {hasFinished && (
            <button
              onClick={() => navigate('/results')}
              className="btn-primary py-1.5 px-3.5 text-xs cursor-pointer flex items-center gap-1.5"
            >
              <span className="material-symbols-outlined text-[16px]">policy</span>
              <span>View Results ({scanState.completed || 0})</span>
            </button>
          )}
          {isIdle && (
            <button
              onClick={() => navigate('/run-scan')}
              className="btn-primary py-1.5 px-3.5 text-xs cursor-pointer flex items-center gap-1.5"
            >
              <span className="material-symbols-outlined text-[16px]">play_arrow</span>
              <span>Run Scan</span>
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-xs text-red-800 font-medium">
          Backend error: {error}
        </div>
      )}
      {stopError && (
        <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-4 text-xs text-red-800 font-medium">
          Could not stop scan: {stopError}
        </div>
      )}

      {showStopConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-5 shadow-xl">
            <div className="mb-3 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-red-50 text-red-600">
                <span className="material-symbols-outlined text-[20px]">warning</span>
              </div>
              <div>
                <div className="text-lg font-semibold text-slate-900">Stop this security scan?</div>
                <div className="text-sm text-slate-500">Completed results will be preserved.</div>
              </div>
            </div>
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
              This will safely halt further adversarial tests. Any completed test executions and partial findings are retained for inspection and export.
            </div>
            <div className="mt-5 flex justify-end gap-3">
              <button type="button" onClick={() => setShowStopConfirm(false)} className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 cursor-pointer">
                Cancel
              </button>
              <button type="button" onClick={requestStop} disabled={stopping} className="rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-60 cursor-pointer">
                {stopping ? 'Stopping…' : 'Stop Scan'}
              </button>
            </div>
          </div>
        </div>
      )}

      {scanState?.target_errors?.length > 0 && (
        <section className="space-y-2 rounded-xl border border-amber-300 bg-amber-50 p-4">
          <h2 className="text-sm font-bold text-amber-800">
            Target/provider errors ({scanState.summary?.TARGET_ERROR ?? scanState.target_errors.length})
          </h2>
          <p className="text-xs text-on-surface-variant">
            These are failed requests, not SAFE results. The details below include the target’s upstream error response.
          </p>
          {scanState.target_errors.map((item, index) => (
            <pre key={`${item.test_id}-${index}`} className="whitespace-pre-wrap break-words rounded bg-surface-container-lowest p-3 font-mono text-xs text-on-surface border border-amber-200">
              {item.test_id}: {item.detail || 'No provider error detail recorded'}
            </pre>
          ))}
        </section>
      )}

      {/* Idle view */}
      {isIdle && !error && (
        <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-space-xl flex flex-col items-center text-center gap-4 py-16">
          <span className="material-symbols-outlined text-[48px] text-surface-container-highest">
            radar
          </span>
          <div className="font-headline-sm text-lg font-bold text-on-surface">No Security Scan Running</div>
          <div className="font-body-sm text-xs text-outline max-w-sm">
            Launch an adversarial scan from the Run Scan page to monitor live payload execution and model verdicts.
          </div>
          <button onClick={() => navigate('/run-scan')} className="btn-primary mt-2 cursor-pointer flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px]">play_arrow</span>
            <span>Go to Run Scan</span>
          </button>
        </div>
      )}

      {/* Running or Completed/Stopped Telemetry View */}
      {!isIdle && scanState && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-space-lg">
          {/* Progress & Timing */}
          <div className="flex flex-col gap-4">
            <ScanProgress
              status={scanState.status}
              total={scanState.total}
              completed={scanState.completed}
              currentAttack={scanState.currentAttack || scanState.current_attack}
              summary={scanState.summary}
            />

            {isCancelled && (
              <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-xs text-amber-900 font-medium space-y-1">
                <div className="font-bold flex items-center gap-1.5 text-amber-900">
                  <span className="material-symbols-outlined text-[18px]">info</span>
                  <span>Scan Stopped — Partial Results Preserved</span>
                </div>
                <div>
                  Halted at user request. {scanState.completed} completed test records have been saved and can be reviewed in Findings.
                </div>
              </div>
            )}

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
                <div className="font-mono text-xs text-primary font-bold">
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
              <div className="bg-surface-container-low border border-emerald-200 rounded-xl p-6 text-center flex flex-col items-center gap-3">
                <span className="material-symbols-outlined text-emerald-800 text-[36px]">
                  check_circle
                </span>
                <div className="font-headline-sm text-base text-emerald-800 font-bold">
                  Evaluation Run Finished
                </div>
                <p className="font-body-sm text-xs text-on-surface-variant max-w-xs">
                  {scanState.summary?.VULNERABLE > 0
                    ? `${scanState.summary.VULNERABLE} vulnerability findings identified that need review and mitigation.`
                    : 'All test probes passed without leaking protected canary tokens.'}
                </p>
                <button
                  onClick={() => navigate('/results')}
                  className="btn-primary mt-2 cursor-pointer flex items-center gap-1.5 text-xs"
                >
                  <span className="material-symbols-outlined text-[16px]">policy</span>
                  <span>View Full Scan Results</span>
                </button>
              </div>
            )}

            {isCancelled && (
              <div className="bg-surface-container-low border border-amber-300 rounded-xl p-6 text-center flex flex-col items-center gap-3">
                <span className="material-symbols-outlined text-amber-800 text-[36px]">
                  stop_circle
                </span>
                <div className="font-headline-sm text-base text-amber-800 font-bold">
                  Scan Stopped
                </div>
                <p className="font-body-sm text-xs text-on-surface-variant max-w-xs">
                  {scanState.completed} test executions completed before stop was requested. Partial findings are ready for review.
                </p>
                <button
                  onClick={() => navigate('/results')}
                  className="btn-primary mt-2 cursor-pointer flex items-center gap-1.5 text-xs"
                >
                  <span className="material-symbols-outlined text-[16px]">policy</span>
                  <span>View Preserved Results</span>
                </button>
              </div>
            )}

            <div className="flex-1 flex flex-col justify-end pt-4 border-t border-surface-container-high/50">
              <div className="flex items-center justify-between text-xs text-outline">
                <span>Progress: {scanState.completed} / {scanState.total}</span>
                <span>{isRunning ? 'Polling live (1.2s)' : isCancelled ? 'Stopped' : 'Completed'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
