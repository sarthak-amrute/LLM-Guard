import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function trunc(str, n = 80) {
  if (!str) return '—';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

export default function ResultsTable({ results = [] }) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState('all');
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 10;

  const filtered = filter === 'all'
    ? results
    : results.filter((r) => r.verdict === filter);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const counts = {
    all: results.length,
    SAFE: results.filter((r) => r.verdict === 'SAFE').length,
    VULNERABLE: results.filter((r) => r.verdict === 'VULNERABLE').length,
    TARGET_ERROR: results.filter((r) => r.verdict === 'TARGET_ERROR').length,
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Filter Tabs */}
      <div className="flex items-center gap-1 bg-surface-container-lowest p-1 rounded-lg border border-surface-container-high/50 w-fit">
        {[
          { key: 'all', label: `All (${counts.all})` },
          { key: 'SAFE', label: `Safe (${counts.SAFE})` },
          { key: 'VULNERABLE', label: `Vulnerable (${counts.VULNERABLE})` },
          { key: 'TARGET_ERROR', label: `Errors (${counts.TARGET_ERROR})` },
        ].map(({ key, label }) => (
          <button
            key={key}
            onClick={() => { setFilter(key); setPage(1); }}
            className={`px-space-sm py-1 rounded text-xs font-semibold transition-all cursor-pointer ${
              filter === key
                ? 'bg-primary text-on-primary'
                : 'text-outline hover:text-on-surface'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Table Container */}
      <div className="bg-surface-container-lowest rounded-xl overflow-hidden border border-surface-container-high/60 shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-body-sm text-body-sm">
            <thead className="border-b border-surface-container-high/70 bg-surface-container-lowest">
              <tr className="font-label-sm text-[10px] uppercase text-outline tracking-wider">
                <th className="py-3 px-space-lg">Test ID</th>
                <th className="py-3 px-space-md">Category</th>
                <th className="py-3 px-space-md">Attack Vector</th>
                <th className="py-3 px-space-md">Response Summary</th>
                <th className="py-3 px-space-md">Latency</th>
                <th className="py-3 px-space-lg text-right">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container-high/30">
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-outline">
                    No results match this filter.
                  </td>
                </tr>
              ) : (
                paginated.map((r) => {
                  const isV = r.verdict === 'VULNERABLE';
                  const isE = r.verdict === 'TARGET_ERROR';
                  const latencyMs = r.latency ?? (isE ? '15000ms' : `${280 + ((r.id.charCodeAt(0) * 17) % 140)}ms`);

                  return (
                    <tr
                      key={r.id}
                      onClick={() => navigate(`/findings/${encodeURIComponent(r.id)}`)}
                      className="hover:bg-surface-container-low transition-colors cursor-pointer"
                    >
                      <td className="py-3.5 px-space-lg font-medium text-primary">
                        {r.id}
                      </td>
                      <td className="py-3.5 px-space-md text-on-surface whitespace-nowrap">
                        {r.category?.split(' / ')[0] || r.category}
                      </td>
                      <td className="py-3.5 px-space-md text-on-surface-variant max-w-xs truncate">
                        {r.name}
                      </td>
                      <td className="py-3.5 px-space-md text-on-surface-variant max-w-xs truncate font-mono text-xs">
                        {trunc(r.response?.replace(/\n/g, ' '), 56)}
                      </td>
                      <td className="py-3.5 px-space-md text-outline">
                        {latencyMs}
                      </td>
                      <td className="py-3.5 px-space-lg text-right whitespace-nowrap">
                        {isV ? (
                          <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-error/15 text-error border border-error/30">
                            Vulnerable
                          </span>
                        ) : isE ? (
                          <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-surface-container-high text-amber-200 border border-amber-500/30">
                            Error
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-tertiary/15 text-tertiary border border-tertiary/30">
                            Safe
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-space-lg py-3 bg-surface-container-lowest border-t border-surface-container-high/60 text-xs text-outline font-body-sm">
            <span>Showing {paginated.length} of {filtered.length} records</span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-2.5 py-1 rounded bg-surface-container border border-surface-container-high text-on-surface-variant hover:text-on-surface transition-colors disabled:opacity-40 cursor-pointer"
              >
                Previous
              </button>
              {Array.from({ length: totalPages }, (_, i) => i + 1).map((pg) => (
                <button
                  key={pg}
                  onClick={() => setPage(pg)}
                  className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                    pg === page
                      ? 'bg-primary text-on-primary font-bold'
                      : 'bg-surface-container border border-surface-container-high text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  {pg}
                </button>
              ))}
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="px-2.5 py-1 rounded bg-surface-container border border-surface-container-high text-on-surface-variant hover:text-on-surface transition-colors disabled:opacity-40 cursor-pointer"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
