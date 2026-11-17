// Shared status badge component
const BADGE_MAP = {
  SAFE: {
    cls: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    label: 'Safe',
  },
  VULNERABLE: {
    cls: 'border-red-200 bg-red-50 text-red-800',
    label: 'Vulnerable',
  },
  TARGET_ERROR: {
    cls: 'border-amber-300 bg-amber-50 text-amber-800',
    label: 'Error',
  },
  running: {
    cls: 'border-blue-200 bg-blue-50 text-blue-800',
    label: 'Running',
  },
  RUNNING: {
    cls: 'border-blue-200 bg-blue-50 text-blue-800',
    label: 'Running',
  },
  completed: {
    cls: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    label: 'Completed',
  },
  COMPLETED: {
    cls: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    label: 'Completed',
  },
  cancelled: {
    cls: 'border-amber-300 bg-amber-50 text-amber-800',
    label: 'Stopped',
  },
  CANCELLED: {
    cls: 'border-amber-300 bg-amber-50 text-amber-800',
    label: 'Stopped',
  },
  stopped: {
    cls: 'border-amber-300 bg-amber-50 text-amber-800',
    label: 'Stopped',
  },
  idle: {
    cls: 'border-slate-200 bg-slate-100 text-slate-700',
    label: 'Idle',
  },
  error: {
    cls: 'border-red-200 bg-red-50 text-red-800',
    label: 'Failed',
  },
  FAILED: {
    cls: 'border-red-200 bg-red-50 text-red-800',
    label: 'Failed',
  },
  SECURE: {
    cls: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    label: 'Secure',
  },
  VULNERABLE_MODE: {
    cls: 'border-red-200 bg-red-50 text-red-800',
    label: 'Vulnerable',
  },
};

export default function StatusBadge({ verdict, label }) {
  const map = BADGE_MAP[verdict] || {
    cls: 'border-slate-200 bg-slate-100 text-slate-700',
    label: verdict ?? '—',
  };

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${map.cls}`}
    >
      {label ?? map.label}
    </span>
  );
}
