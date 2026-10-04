import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getAttacks, getScanResults } from '../services/api';

export default function TestCases() {
  const [searchParams] = useSearchParams();
  const [attacks, setAttacks] = useState([]);
  const [scanResults, setScanResults] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState(searchParams.get('search') || '');
  const [catFilter, setCatFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    let mounted = true;
    Promise.all([getAttacks(), getScanResults().catch(() => null)])
      .then(([attackData, scanData]) => {
        if (!mounted) return;
        setAttacks(attackData.attacks ?? []);
        const map = {};
        (scanData?.results ?? []).forEach((r) => { map[r.id] = r.verdict; });
        setScanResults(map);
        setLoading(false);
      })
      .catch((e) => {
        if (mounted) {
          setError(e.message);
          setLoading(false);
        }
      });
    return () => { mounted = false; };
  }, []);

  const categories = ['all', ...new Set(attacks.map((a) => a.category))];

  const filtered = attacks.filter((a) => {
    const matchesSearch = !search ||
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.id.toLowerCase().includes(search.toLowerCase()) ||
      a.category.toLowerCase().includes(search.toLowerCase()) ||
      a.objective.toLowerCase().includes(search.toLowerCase());
    const matchesCat = catFilter === 'all' || a.category === catFilter;
    const verdict = scanResults[a.id];
    const matchesStatus = statusFilter === 'all'
      || (statusFilter === 'SAFE' && verdict === 'SAFE')
      || (statusFilter === 'VULNERABLE' && verdict === 'VULNERABLE')
      || (statusFilter === 'TARGET_ERROR' && verdict === 'TARGET_ERROR')
      || (statusFilter === 'untested' && !verdict);
    return matchesSearch && matchesCat && matchesStatus;
  });

  const hasResults = Object.keys(scanResults).length > 0;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <span className="material-symbols-outlined animate-spin text-[32px] text-primary">
          refresh
        </span>
        <div className="font-body-sm text-outline">Loading attack library…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-space-xl">
        <div className="bg-surface-container-lowest border border-error/40 rounded-xl p-space-xl text-center">
          <div className="font-mono text-xs text-error">Failed to load attacks: {error}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-space-xl space-y-space-lg w-full">
      {/* Header */}
      <div className="bg-surface-container-lowest p-space-lg rounded-xl border border-surface-container-high/60 shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-headline-sm text-base font-bold text-on-surface">
            Adversarial Test Case Repository
          </h1>
          <div className="font-mono text-xs text-outline mt-1">
            {attacks.length} attack vectors across {new Set(attacks.map((a) => a.category)).size} categories
            {hasResults && ` · ${Object.keys(scanResults).length} evaluated in latest run`}
          </div>
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="bg-surface-container-lowest p-space-md rounded-xl border border-surface-container-high/60 shadow-sm flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[240px]">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-[18px] text-outline pointer-events-none">
            search
          </span>
          <input
            className="w-full bg-surface-container-low border border-surface-container-high/50 text-on-surface placeholder:text-outline font-body-sm text-xs rounded-lg pl-9 pr-3 py-2 outline-none focus:border-primary/60 transition-colors"
            placeholder="Search by ID, name, category, objective..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <select
          className="bg-surface-container-low border border-surface-container-high/50 text-on-surface font-body-sm text-xs rounded-lg px-3 py-2 outline-none focus:border-primary/60 cursor-pointer"
          value={catFilter}
          onChange={(e) => setCatFilter(e.target.value)}
        >
          {categories.map((c) => (
            <option key={c} value={c} className="bg-surface-container text-on-surface">
              {c === 'all' ? 'All Categories' : c}
            </option>
          ))}
        </select>

        {hasResults && (
          <select
            className="bg-surface-container-low border border-surface-container-high/50 text-on-surface font-body-sm text-xs rounded-lg px-3 py-2 outline-none focus:border-primary/60 cursor-pointer"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all" className="bg-surface-container text-on-surface">All Statuses</option>
            <option value="SAFE" className="bg-surface-container text-on-surface">Safe</option>
            <option value="VULNERABLE" className="bg-surface-container text-on-surface">Vulnerable</option>
            <option value="TARGET_ERROR" className="bg-surface-container text-on-surface">Error</option>
            <option value="untested" className="bg-surface-container text-on-surface">Not Tested</option>
          </select>
        )}

        <div className="font-mono text-xs text-outline ml-auto">
          {filtered.length} / {attacks.length} shown
        </div>
      </div>

      {/* Test Case Cards */}
      <div className="space-y-2.5">
        {filtered.length === 0 ? (
          <div className="bg-surface-container-lowest border border-surface-container-high/60 rounded-xl p-8 text-center text-outline text-xs">
            No attack vectors match your filters.
          </div>
        ) : (
          filtered.map((a) => {
            const verdict = scanResults[a.id];
            const isOpen = expanded === a.id;
            const isV = verdict === 'VULNERABLE';
            const isE = verdict === 'TARGET_ERROR';

            return (
              <div
                key={a.id}
                className="bg-surface-container-lowest rounded-xl border border-surface-container-high/60 overflow-hidden shadow-sm transition-colors"
              >
                <div
                  onClick={() => setExpanded(isOpen ? null : a.id)}
                  className="p-3.5 px-4 cursor-pointer flex flex-wrap items-center justify-between gap-3 hover:bg-surface-container-low transition-colors"
                >
                  <div className="flex items-center gap-3 flex-1 min-w-[200px]">
                    <span className="font-mono text-xs font-bold text-primary">
                      {a.id}
                    </span>
                    <span className="text-surface-container-highest">·</span>
                    <span className="font-label-sm text-xs text-outline">
                      {a.category?.split(' / ')[0]}
                    </span>
                    <span className="text-surface-container-highest">·</span>
                    <span className="font-headline text-xs font-semibold text-on-surface">
                      {a.name}
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    {verdict && (
                      <span
                        className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                          isV
                            ? 'bg-error/15 text-error border border-error/30'
                            : isE
                            ? 'bg-surface-container-high text-amber-200 border border-amber-500/30'
                            : 'bg-tertiary/15 text-tertiary border border-tertiary/30'
                        }`}
                      >
                        {verdict}
                      </span>
                    )}
                    <span
                      className={`material-symbols-outlined text-[18px] text-outline transition-transform ${
                        isOpen ? 'rotate-180' : ''
                      }`}
                    >
                      expand_more
                    </span>
                  </div>
                </div>

                {isOpen && (
                  <div className="p-4 border-t border-surface-container-high/50 bg-surface-container-low/40 flex flex-col gap-3">
                    <div>
                      <div className="font-label-sm text-[10px] text-outline uppercase font-semibold mb-1">
                        Probe Objective
                      </div>
                      <div className="font-body-sm text-xs text-on-surface-variant">
                        {a.objective}
                      </div>
                    </div>
                    <div>
                      <div className="font-label-sm text-[10px] text-outline uppercase font-semibold mb-1">
                        Adversarial Prompt Payload
                      </div>
                      <div className="font-mono text-xs text-on-surface bg-surface-container-lowest border border-surface-container-high p-3 rounded-lg whitespace-pre-wrap leading-relaxed">
                        {a.prompt}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
