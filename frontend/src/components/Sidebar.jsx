import { NavLink } from 'react-router-dom';
import { useStatus } from '../context/useStatus';
import {
  BarChart3,
  FileSearch,
  History,
  LayoutDashboard,
  PlayCircle,
  Settings,
  ShieldCheck,
  Target,
} from 'lucide-react';

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/run-scan', label: 'New Scan', icon: PlayCircle },
  { to: '/scan-history', label: 'Scan History', icon: History },
  { to: '/results', label: 'Findings', icon: FileSearch },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/target', label: 'Targets', icon: Target },
];

export default function Sidebar({ onClose, open = false }) {
  const { status } = useStatus();
  const isOperational = status?.llmguard === 'running';
  const activeTargetName = status?.active_target?.name || (status?.target_online ? 'TechMart Support' : 'No Target');

  return (
    <aside className={`fixed left-0 top-0 z-50 flex h-dvh w-[min(18rem,calc(100vw-3rem))] flex-col justify-between overflow-y-auto border-r border-[#274b3e] bg-[#193c32] text-[#f3f4e9] shadow-[0_12px_35px_rgba(15,35,27,0.2)] transition-transform duration-200 md:w-72 lg:translate-x-0 ${open ? 'translate-x-0' : '-translate-x-full'}`}>
      <div className="flex shrink-0 flex-col">
        <div className="flex h-20 items-center justify-between border-b border-white/10 px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-200/20 bg-emerald-100/10 text-emerald-200 shadow-sm">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold tracking-tight text-[#f5f4eb]">LLM<span className="text-emerald-200">Guard</span></span>
                <span className="rounded-full border border-emerald-200/20 bg-emerald-100/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-emerald-100">v2.4</span>
              </div>
              <span className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-[#a8bdb0]">LLM Security Platform</span>
            </div>
          </div>
          {onClose && (
            <button onClick={onClose} className="rounded-lg p-1.5 text-emerald-200/70 hover:bg-white/10 hover:text-white lg:hidden cursor-pointer" aria-label="Close navigation">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-5 w-5"><path d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          )}
        </div>

        <div className="px-5 pb-2 pt-5">
          <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#8fa99b]">Workspace</span>
        </div>

        <nav className="space-y-1 px-3">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              onClick={onClose}
              className={({ isActive }) =>
                isActive
                  ? 'flex items-center gap-3 rounded-xl border border-emerald-200/15 bg-emerald-100/10 px-3 py-2.5 font-semibold text-emerald-100'
                  : 'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-[#c2d0c6] transition hover:bg-white/5 hover:text-white'
              }
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="mt-auto shrink-0 space-y-3 border-t border-white/10 bg-[#15362d] p-4">
        <div className="rounded-xl border border-white/10 bg-white/5 p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#91a99b]">System Status</span>
            <span className={`inline-flex h-2.5 w-2.5 rounded-full ${isOperational ? 'bg-emerald-500' : 'bg-red-500'} shadow-[0_0_0_4px_rgba(148,163,184,0.12)]`} />
          </div>
          <div className="flex items-center gap-2 text-sm font-medium text-[#e1e9df]">
            <span className={`inline-block h-2 w-2 rounded-full ${isOperational ? 'bg-emerald-500' : 'bg-red-500'}`} />
            {isOperational ? 'Gateway online' : 'Gateway offline'}
          </div>
        </div>

        <NavLink to="/target" className="flex items-center justify-between rounded-xl border border-white/10 bg-white/5 p-3 text-left transition hover:border-emerald-200/20 hover:bg-white/10">
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#91a99b]">Active Target</div>
            <div className="mt-1 truncate text-sm font-semibold text-[#f3f4e9]" title={activeTargetName}>{activeTargetName}</div>
          </div>
          <Target className="h-4 w-4 text-slate-400" />
        </NavLink>

        <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/5 p-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-emerald-700 text-emerald-50 shadow-sm">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div>
              <div className="text-sm font-semibold text-[#f3f4e9]">SecOps Auditor</div>
              <div className="text-[11px] text-[#a8bdb0]">Tier 3 Admin</div>
            </div>
          </div>
          <NavLink to="/settings" className="rounded-lg p-2 text-[#a8bdb0] transition hover:bg-white/10 hover:text-white" aria-label="Settings">
            <Settings className="h-4 w-4" />
          </NavLink>
        </div>
      </div>
    </aside>
  );
}
