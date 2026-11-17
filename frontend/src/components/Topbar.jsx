import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Menu, Plus, Search, Settings, ShieldCheck } from 'lucide-react';
import { useStatus } from '../context/useStatus';

export default function Topbar({ onMenuClick }) {
  const navigate = useNavigate();
  const { status } = useStatus();
  const [search, setSearch] = useState('');

  const handleSearchSubmit = (e) => {
    if (e.key === 'Enter' && search.trim()) {
      navigate(`/test-cases?search=${encodeURIComponent(search.trim())}`);
    }
  };

  const isGuardrailActive = status?.target_mode === 'SECURE' || status?.target_online;
  const isOnline = status?.llmguard === 'running';

  return (
    <header className="fixed left-0 right-0 top-0 z-30 flex h-16 items-center justify-between gap-3 border-b border-[#e3e0d6] bg-[#fffefa]/95 px-3 backdrop-blur-sm sm:h-20 sm:px-6 lg:left-72">
      <div className="flex min-w-0 max-w-xl flex-1 items-center gap-2 sm:gap-4">
        {onMenuClick && (
          <button onClick={onMenuClick} className="shrink-0 rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900 lg:hidden" aria-label="Open menu">
            <Menu className="h-5 w-5" />
          </button>
        )}
        <div className="relative hidden w-full min-w-0 sm:block">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-10 pr-4 text-sm text-slate-900 placeholder:text-slate-400 outline-none transition focus:border-blue-300 focus:bg-white"
            placeholder="Search security tests, attack vectors, or findings..."
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={handleSearchSubmit}
          />
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2 sm:gap-4">
        <div className="hidden items-center gap-2.5 rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 xl:flex">
          <span className={`inline-block h-2.5 w-2.5 rounded-full ${isOnline ? 'bg-emerald-500' : 'bg-red-500'} shadow-[0_0_0_4px_rgba(16,185,129,0.12)]`} />
          <span className="text-sm text-slate-600">
            System: <span className="font-semibold text-slate-900">{isOnline ? 'Operational' : 'Offline'}</span>
          </span>
          <span className="text-slate-300">|</span>
          <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-blue-700">
            <ShieldCheck className="h-4 w-4" />
            {isGuardrailActive ? 'Guardrail Active' : 'Unfiltered Mode'}
          </span>
        </div>

        <button
          onClick={() => navigate('/run-scan')}
          className="inline-flex items-center gap-2 rounded-xl bg-primary px-3 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:opacity-90 sm:px-4 cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New Scan</span>
        </button>

        <button
          onClick={() => navigate('/results')}
          className="relative rounded-xl border border-slate-200 bg-white p-2.5 text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 cursor-pointer"
          aria-label="Findings"
          title="View Findings"
        >
          <Bell className="h-4 w-4" />
        </button>

        <button
          onClick={() => navigate('/settings')}
          className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-700 transition hover:border-primary/30 hover:bg-surface-container-high hover:text-primary cursor-pointer"
          aria-label="Open settings"
          title="Settings"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  );
}
