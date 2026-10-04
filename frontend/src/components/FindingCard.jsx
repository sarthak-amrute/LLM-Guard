function trunc(str, n = 120) {
  if (!str) return '—';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

export default function FindingCard({ result, onClick }) {
  const isVuln = result.verdict === 'VULNERABLE';
  const isErr = result.verdict === 'TARGET_ERROR';

  return (
    <div
      onClick={onClick}
      className="bg-surface-container-lowest p-space-lg rounded-xl flex flex-col justify-between gap-space-md border border-surface-container-high/70 hover:border-primary/40 transition-colors shadow-sm cursor-pointer"
    >
      <div className="flex flex-col gap-space-xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                isVuln
                  ? 'bg-error-container/80 text-error border border-error/40'
                  : isErr
                  ? 'bg-surface-container-high text-amber-400 border border-amber-500/30'
                  : 'bg-tertiary/15 text-tertiary border border-tertiary/30'
              }`}
            >
              {isVuln ? 'Critical' : isErr ? 'Error' : 'Safe'}
            </span>
            <span className="font-label-sm text-xs text-outline font-medium">
              {result.category?.split(' / ')[0] || result.category}
            </span>
          </div>
          <span className="font-label-sm text-xs text-outline">
            ID: {result.id}
          </span>
        </div>

        <h3 className="font-headline-sm text-base font-semibold text-on-surface mt-1">
          {result.name}
        </h3>
        <p className="font-body-sm text-body-sm text-on-surface-variant line-clamp-2">
          {trunc(result.objective || result.detail || result.response, 130)}
        </p>
      </div>

      <div className="flex items-center justify-between pt-space-xs border-t border-surface-container-high/50">
        <span className="font-label-sm text-xs text-primary flex items-center gap-1 font-medium">
          <span className="material-symbols-outlined text-[14px]">
            {isVuln ? 'auto_fix_high' : 'verified_user'}
          </span>
          <span>
            {isVuln ? 'Sanitization filter recommended' : 'Verified safe baseline'}
          </span>
        </span>
        <button
          className="px-space-md py-1.5 rounded-lg bg-surface-container border border-surface-container-high hover:bg-surface-container-high text-on-surface font-label-md text-xs font-medium transition-colors"
        >
          Review & Mitigate
        </button>
      </div>
    </div>
  );
}
