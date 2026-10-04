// Stat card used across Dashboard and Results
export default function MetricCard({ icon, label, value, sub, accent = false, children }) {
  return (
    <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 flex flex-col justify-between gap-2 shadow-sm">
      <div className="flex items-center justify-between">
        <span className="font-label-sm text-[10px] text-outline uppercase tracking-wider font-semibold">
          {label}
        </span>
        {icon && (
          <span
            className="material-symbols-outlined text-[20px]"
            style={{ color: accent ? '#10b981' : '#71717a' }}
          >
            {icon}
          </span>
        )}
      </div>
      <div>
        <div className="flex items-baseline gap-2">
          <span
            className={`font-headline-xl text-3xl font-bold ${
              accent ? 'text-tertiary' : 'text-on-surface'
            }`}
          >
            {value ?? '—'}
          </span>
        </div>
        {sub && (
          <span className="font-body-sm text-body-sm text-on-surface-variant block mt-1">
            {sub}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}
