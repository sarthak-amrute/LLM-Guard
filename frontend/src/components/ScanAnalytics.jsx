import { useEffect, useState } from 'react';
import { getAnalyticsCategories, getAnalyticsOverview, getAnalyticsTrends } from '../services/api';

function AnalyticsMetric({ label, value, tone = 'text-on-surface' }) {
  return (
    <div className="rounded-xl border border-surface-container-high/60 bg-surface-container-lowest p-4">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-outline">{label}</div>
      <div className={`mt-1 font-headline text-2xl font-bold ${tone}`}>{value ?? '—'}</div>
    </div>
  );
}

export default function ScanAnalytics() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    Promise.all([getAnalyticsOverview(), getAnalyticsTrends(), getAnalyticsCategories()])
      .then(([overview, trends, categories]) => {
        if (active) setData({ overview, trends, categories: categories.categories || {} });
      })
      .catch((cause) => { if (active) setError(cause.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  if (loading) return <div className="rounded-xl border border-surface-container-high/60 bg-surface-container-lowest p-6 text-sm text-outline">Loading historical analytics…</div>;
  if (error) return <div role="alert" className="rounded-xl border border-error/40 bg-error/10 p-4 text-sm text-error">Historical analytics unavailable: {error}</div>;

  const { overview, trends, categories } = data;
  const points = trends.scans || [];
  const maxFindings = Math.max(...points.map((point) => point.findings), 1);
  const coordinates = points.map((point, index) => {
    const x = points.length < 2 ? 300 : 24 + index * (552 / (points.length - 1));
    const y = 116 - (point.findings / maxFindings) * 96;
    return `${x},${y}`;
  }).join(' ');
  const categoryRows = Object.entries(categories).sort((a, b) => b[1].executions - a[1].executions);

  return (
    <section className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <AnalyticsMetric label="Saved scans" value={overview.total_scans} />
        <AnalyticsMetric label="Completed scans" value={overview.completed_scans} tone="text-tertiary" />
        <AnalyticsMetric label="Persisted executions" value={overview.total_executions} />
        <AnalyticsMetric label="Unique prompts per scan" value={overview.unique_prompt_executions} />
        <AnalyticsMetric label="Confirmed finding records" value={overview.confirmed_vulnerabilities} tone={overview.confirmed_vulnerabilities ? 'text-error' : 'text-on-surface'} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="rounded-xl border border-surface-container-high/60 bg-surface-container-lowest p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="font-headline text-base font-bold text-on-surface">Confirmed findings by scan</h2>
              <p className="mt-1 text-[11px] text-outline">Historical counts; not a remediation or posture score.</p>
            </div>
            <span className="text-[10px] text-outline">{points.length} completed</span>
          </div>
          {trends.trend_available ? (
            <div className="mt-4">
              <svg role="img" aria-label="Confirmed findings recorded across completed scans" viewBox="0 0 600 140" className="h-36 w-full overflow-visible">
                <line x1="20" y1="120" x2="580" y2="120" stroke="currentColor" className="text-surface-container-highest" />
                <polyline fill="none" stroke="currentColor" strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" className="text-primary" points={coordinates} />
                {points.map((point, index) => {
                  const x = points.length < 2 ? 300 : 24 + index * (552 / (points.length - 1));
                  const y = 116 - (point.findings / maxFindings) * 96;
                  return <circle key={point.scan_id} cx={x} cy={y} r="4" fill="currentColor" className="text-primary"><title>{point.scan_id}: {point.findings} findings</title></circle>;
                })}
              </svg>
              <div className="flex justify-between gap-2 text-[10px] text-outline">
                <span>{points[0]?.scan_id}</span><span>{points[points.length - 1]?.scan_id}</span>
              </div>
            </div>
          ) : (
            <p className="mt-5 rounded-lg bg-surface-container-low p-4 text-xs text-on-surface-variant">
              {trends.insufficient_data_message}
            </p>
          )}
        </div>

        <div className="rounded-xl border border-surface-container-high/60 bg-surface-container-lowest p-5">
          <h2 className="font-headline text-base font-bold text-on-surface">Coverage by category</h2>
          {categoryRows.length ? (
            <div className="mt-3 space-y-3">
              {categoryRows.slice(0, 6).map(([name, stats]) => (
                <div key={name}>
                  <div className="mb-1 flex justify-between gap-3 text-[11px]">
                    <span className="truncate text-on-surface-variant">{name}</span>
                    <span className="shrink-0 text-outline">{stats.executions} runs · {stats.vulnerable} vulnerable · {stats.errors} errors</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-surface-container-high">
                    <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, (stats.executions / Math.max(categoryRows[0][1].executions, 1)) * 100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-4 text-xs text-outline">No persisted category executions yet.</p>
          )}
          <div className="mt-4 grid grid-cols-3 gap-2 border-t border-surface-container-high/60 pt-4 text-center text-[10px] text-outline">
            <span>Safe <strong className="text-tertiary">{overview.outcomes.safe}</strong></span>
            <span>Vulnerable <strong className="text-error">{overview.outcomes.vulnerable}</strong></span>
            <span>Errors <strong className="text-amber-300">{overview.outcomes.errors}</strong></span>
          </div>
        </div>
      </div>
    </section>
  );
}
