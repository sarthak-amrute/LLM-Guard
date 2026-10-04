// Generic scan progress component used in LiveScan
export default function ScanProgress({ status, total, completed, currentAttack, summary }) {
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
  const isRunning = status === 'running';

  return (
    <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 flex flex-col gap-4 shadow-sm">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <div className="font-headline-sm text-sm font-semibold text-on-surface">
            Scan Progress
          </div>
          <div className="font-body-sm text-[11px] text-outline mt-0.5">
            {completed} of {total} tests evaluated
          </div>
        </div>
        <div
          className={`font-headline-xl text-3xl font-bold ${
            isRunning ? 'text-primary' : 'text-on-surface'
          }`}
        >
          {pct}%
        </div>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-surface-container-high h-2.5 rounded-full overflow-hidden">
        <div
          className="bg-primary h-full transition-all duration-300 rounded-full"
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* Live attack info */}
      {isRunning && currentAttack && (
        <div className="bg-surface-container-low border border-surface-container-high/60 rounded-lg p-3 flex flex-col gap-1">
          <div className="font-label-sm text-[10px] text-primary uppercase font-bold tracking-wider">
            Current Probe
          </div>
          <div className="flex gap-2 flex-wrap items-center mt-0.5">
            <span className="font-mono text-xs text-primary font-bold">
              {currentAttack.id}
            </span>
            <span className="text-surface-container-highest">|</span>
            <span className="font-headline text-xs text-on-surface font-semibold">
              {currentAttack.name}
            </span>
          </div>
          <div className="font-body-sm text-xs text-outline">
            {currentAttack.category}
          </div>
        </div>
      )}

      {/* Summary counts */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: 'SAFE', value: summary?.SAFE ?? 0, color: 'text-tertiary', border: 'border-tertiary/20' },
          { label: 'VULNERABLE', value: summary?.VULNERABLE ?? 0, color: 'text-error', border: 'border-error/20' },
          { label: 'ERROR', value: summary?.TARGET_ERROR ?? 0, color: 'text-amber-300', border: 'border-amber-500/20' },
        ].map(({ label, value, color, border }) => (
          <div
            key={label}
            className={`bg-surface-container-low border ${border} rounded-lg p-3 text-center`}
          >
            <div className={`font-headline-xl text-2xl font-bold ${color}`}>
              {value}
            </div>
            <div className="font-label-sm text-[9px] text-outline uppercase tracking-wider mt-1">
              {label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
