import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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

  return (
    <header className="fixed top-0 left-72 right-0 h-20 bg-surface-container-lowest/95 backdrop-blur-xl border-b border-surface-container-high/50 shadow-[0_2px_12px_rgba(0,0,0,0.5)] z-40 flex items-center justify-between px-6">
      {/* Mobile Menu Toggle & Search Bar */}
      <div className="flex items-center gap-4 flex-1 max-w-xl">
        {onMenuClick && (
          <button
            onClick={onMenuClick}
            className="md:hidden text-outline hover:text-on-surface p-1.5 mr-2 rounded-lg hover:bg-surface-container-high"
            aria-label="Open menu"
          >
            <span className="material-symbols-outlined text-[22px]">menu</span>
          </button>
        )}
        <div className="relative w-full">
          <span className="material-symbols-outlined absolute left-3.5 top-1/2 -translate-y-1/2 text-[20px] text-outline pointer-events-none">
            search
          </span>
          <input
            className="w-full bg-surface-container-low border border-surface-container-high/60 text-on-surface placeholder:text-outline text-[14px] rounded-xl pl-11 pr-4 py-2.5 outline-none focus:border-primary/70 focus:bg-surface-container transition-all shadow-inner"
            placeholder="Search security tests, endpoints, CVEs, attack vectors..."
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={handleSearchSubmit}
          />
        </div>
      </div>

      {/* Right Action Icons & Status */}
      <div className="flex items-center gap-4">
        {/* Latency & Guardrail indicator */}
        <div className="hidden xl:flex items-center gap-2.5 px-3.5 py-2 bg-surface-container-low border border-surface-container-high/60 rounded-xl shadow-sm">
          <span className="h-2.5 w-2.5 rounded-full bg-tertiary shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
          <span className="text-[13px] text-on-surface-variant font-medium">
            Latency: <span className="text-on-surface font-bold">142ms</span>
          </span>
          <span className="text-surface-container-highest">|</span>
          <span className="text-[13px] text-primary font-bold flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[16px]">verified_user</span>
            <span>{isGuardrailActive ? 'Guardrail Active' : 'Unfiltered Mode'}</span>
          </span>
        </div>

        {/* New Scan Button */}
        <button
          onClick={() => navigate('/run-scan')}
          className="flex items-center gap-2 bg-primary text-on-primary text-[13.5px] font-bold px-4 py-2.5 rounded-xl hover:bg-amber-400 transition-all shadow-[0_0_18px_rgba(245,158,11,0.3)] cursor-pointer"
        >
          <span className="material-symbols-outlined text-[20px]">add_moderator</span>
          <span>New Scan</span>
        </button>

        {/* Notification Bell */}
        <button
          onClick={() => navigate('/results')}
          className="relative text-on-surface-variant hover:text-on-surface transition-colors p-2 rounded-xl hover:bg-surface-container-high cursor-pointer"
          title="Notifications & Alerts"
        >
          <span className="material-symbols-outlined text-[22px]">notifications</span>
          <span className="absolute top-1.5 right-1.5 h-2.5 w-2.5 bg-error rounded-full ring-2 ring-surface-container-lowest" />
        </button>

        {/* User Avatar */}
        <div
          onClick={() => navigate('/settings')}
          className="w-10 h-10 rounded-xl bg-surface-container-high border border-outline-variant/60 flex items-center justify-center cursor-pointer hover:border-primary hover:shadow-[0_0_10px_rgba(245,158,11,0.2)] transition-all"
          title="SecOps Auditor Profile"
        >
          <span className="material-symbols-outlined text-primary text-[20px]">person</span>
        </div>
      </div>
    </header>
  );
}
