// Shared status badge component
const BADGE_MAP = {
  SAFE: {
    cls: 'bg-tertiary/15 text-tertiary border-tertiary/30',
    label: 'Safe',
  },
  VULNERABLE: {
    cls: 'bg-error/15 text-error border-error/30',
    label: 'Vulnerable',
  },
  TARGET_ERROR: {
    cls: 'bg-surface-container-high text-amber-200 border-amber-500/30',
    label: 'Error',
  },
  running: {
    cls: 'bg-primary/15 text-primary border-primary/30',
    label: 'Running',
  },
  completed: {
    cls: 'bg-tertiary/15 text-tertiary border-tertiary/30',
    label: 'Completed',
  },
  idle: {
    cls: 'bg-surface-container text-outline border-surface-container-high',
    label: 'Idle',
  },
  error: {
    cls: 'bg-error-container/80 text-error border-error/40',
    label: 'Failed',
  },
  SECURE: {
    cls: 'bg-tertiary/15 text-tertiary border-tertiary/30',
    label: 'Secure',
  },
  VULNERABLE_MODE: {
    cls: 'bg-error/15 text-error border-error/30',
    label: 'Vulnerable',
  },
};

export default function StatusBadge({ verdict, label }) {
  const map = BADGE_MAP[verdict] || {
    cls: 'bg-surface-container text-outline border-surface-container-high',
    label: verdict ?? '—',
  };

  return (
    <span
      className={`px-2 py-0.5 rounded-full text-xs font-semibold border inline-flex items-center gap-1 ${map.cls}`}
    >
      {label ?? map.label}
    </span>
  );
}
