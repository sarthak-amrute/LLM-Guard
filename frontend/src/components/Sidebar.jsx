import { NavLink } from 'react-router-dom';
import { useStatus } from '../context/useStatus';

const NAV_ITEMS = [
  { to: '/dashboard',  icon: 'shield',      label: 'Dashboard' },
  { to: '/run-scan',   icon: 'play_arrow',  label: 'Run Scan' },
  { to: '/live-scan',  icon: 'radar',       label: 'Live Scan' },
  { to: '/results',    icon: 'policy',      label: 'Results' },
  { to: '/test-cases', icon: 'biotech',     label: 'Test Cases' },
  { to: '/reports',    icon: 'assessment',  label: 'Reports' },
];

export default function Sidebar({ onClose }) {
  const { status } = useStatus();
  const isOperational = status?.llmguard === 'running';

  return (
    <aside className="fixed left-0 top-0 h-full w-72 bg-surface-container-lowest z-50 flex flex-col justify-between border-r border-surface-container-high/60 shadow-[0_4px_30px_rgba(0,0,0,0.7)]">
      <div className="flex flex-col">
        {/* Brand Header */}
        <div className="h-20 px-space-md flex items-center justify-between bg-surface-container-lowest border-b border-surface-container-high/40">
          <div className="flex items-center gap-3">
            <div className="relative w-11 h-11 rounded-xl overflow-hidden border border-primary/40 shadow-[0_0_15px_rgba(245,158,11,0.25)] shrink-0 bg-surface-container-high">
              <img
                src="/llmguard-shield.jpg"
                alt="LLMGuard Shield"
                className="w-full h-full object-cover"
                onError={(e) => {
                  e.target.onerror = null;
                  e.target.style.display = 'none';
                  e.target.nextSibling.style.display = 'flex';
                }}
              />
              <div className="hidden w-full h-full items-center justify-center bg-primary/10">
                <span className="material-symbols-outlined text-primary text-[24px]">shield</span>
              </div>
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-1.5">
                <span className="font-headline text-base font-bold tracking-tight text-on-surface leading-none">
                  LLM<span className="text-primary font-black">Guard</span>
                </span>
                <span className="px-1.5 py-0.5 rounded bg-primary/20 text-primary text-[9px] font-bold uppercase tracking-wider border border-primary/30">
                  v2.4
                </span>
              </div>
              <span className="font-label-sm text-[11px] uppercase tracking-widest text-primary font-semibold mt-0.5">
                Enterprise SecOps
              </span>
            </div>
          </div>
          {onClose && (
            <button onClick={onClose} className="md:hidden text-outline hover:text-on-surface p-1.5 rounded-lg hover:bg-surface-container-high">
              <span className="material-symbols-outlined text-[20px]">close</span>
            </button>
          )}
        </div>

        {/* Section Label */}
        <div className="px-space-md pt-4 pb-2">
          <span className="font-label-sm text-[11px] uppercase text-outline tracking-wider font-semibold">
            SecOps Navigation
          </span>
        </div>

        {/* Nav Items */}
        <nav className="px-space-sm space-y-1.5">
          {NAV_ITEMS.map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              onClick={onClose}
              className={({ isActive }) =>
                isActive
                  ? 'flex items-center gap-3 px-3.5 py-2.5 rounded-xl transition-all bg-primary/15 text-primary border-l-3 border-primary font-bold text-[14px] shadow-sm'
                  : 'flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-[14px] text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all font-medium'
              }
            >
              <span className="material-symbols-outlined text-[22px]">{icon}</span>
              <span className="tracking-tight">{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Bottom Info & User Profile */}
      <div className="flex flex-col p- space-y-2.5 p-4 bg-surface-container-lowest border-t border-surface-container-high/40">
        {/* System Status Card */}
        <div className="bg-surface-container-low rounded-xl p-3 flex flex-col gap-1.5 border border-surface-container-high/60">
          <div className="flex items-center justify-between">
            <span className="font-label-sm text-[11px] uppercase text-outline font-semibold">System Status</span>
            <span className="relative flex h-2.5 w-2.5">
              <span
                className={`animate-ping absolute inline-flex h-full w-full rounded-full ${
                  isOperational ? 'bg-tertiary' : 'bg-error'
                } opacity-75`}
              />
              <span
                className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                  isOperational ? 'bg-tertiary' : 'bg-error'
                }`}
              />
            </span>
          </div>
          <div className="font-body-sm text-[13px] text-on-surface font-semibold truncate flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${isOperational ? 'bg-tertiary' : 'bg-error'}`} />
            {isOperational ? 'Gateway: Operational' : 'Gateway: Disconnected'}
          </div>
        </div>

        {/* Cluster Env Card */}
        <NavLink
          to="/target"
          className="bg-surface-container-low rounded-xl p-3 flex items-center justify-between border border-surface-container-high/60 hover:border-primary/40 transition-colors"
          title="Click to manage target cluster"
        >
          <div className="flex flex-col min-w-0">
            <span className="font-label-sm text-[11px] uppercase text-outline font-semibold">Cluster Env</span>
            <span className="font-body-sm text-[13px] text-primary font-semibold truncate">
              {status?.target_online ? 'prod-gpt4o-cluster' : 'cluster-offline'}
            </span>
          </div>
          <span className="material-symbols-outlined text-[20px] text-outline">swap_vert</span>
        </NavLink>

        {/* Auditor Profile */}
        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-primary flex items-center justify-center shadow-md">
              <span className="material-symbols-outlined text-on-primary text-[20px]">person</span>
            </div>
            <div className="flex flex-col min-w-0">
              <span className="text-[13px] text-on-surface font-bold truncate leading-snug">
                SecOps Auditor
              </span>
              <span className="text-[11px] text-outline truncate font-medium">
                Tier 3 Admin
              </span>
            </div>
          </div>
          <NavLink
            to="/settings"
            className="text-on-surface-variant hover:text-on-surface transition-colors p-2 rounded-lg hover:bg-surface-container-high"
            title="Settings"
          >
            <span className="material-symbols-outlined text-[20px]">settings</span>
          </NavLink>
        </div>
      </div>
    </aside>
  );
}
