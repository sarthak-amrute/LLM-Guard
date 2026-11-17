import { useEffect, useState } from 'react';
import { compareScanHistory, getScanHistory, getScanHistoryDetail } from '../services/api';

const PAGE_SIZE = 10;

function Metric({ label, value }) {
  return (
    <div className="rounded-xl border border-surface-container-high/60 bg-surface-container-lowest p-4 shadow-sm">
      <div className="text-[10px] uppercase tracking-wider text-outline font-semibold">{label}</div>
      <div className="mt-1 text-xl font-bold text-on-surface">{value}</div>
    </div>
  );
}

function ScanDetails({ scan }) {
  return (
    <section className="space-y-4 rounded-xl border border-surface-container-high/60 bg-surface-container-lowest p-5 shadow-sm">
      <div>
        <h2 className="font-headline text-lg font-bold text-on-surface">
          {scan.scan_name || scan.scan_id}
        </h2>
        <p className="mt-1 text-xs text-outline">
          {scan.target_name || scan.target_id || 'Target not recorded'} · {scan.provider || 'Provider unknown'} / {scan.model || 'Model unknown'}
        </p>
        {scan.error && <p className="mt-2 text-sm text-error font-medium">{scan.error}</p>}
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Metric label="Executed" value={scan.summary.total_executed ?? scan.results.length} />
        <Metric label="Expected" value={scan.summary.expected_executions ?? scan.results.length} />
        <Metric label="Findings" value={scan.findings.length} />
        <Metric label="Safe" value={scan.summary.SAFE ?? 0} />
        <Metric label="Vulnerable" value={scan.summary.VULNERABLE ?? 0} />
        <Metric label="Target errors" value={scan.summary.TARGET_ERROR ?? 0} />
        <Metric label="Incomplete" value={scan.summary.incomplete_executions ?? 0} />
        <Metric label="Unique prompts" value={scan.summary.unique_prompts_executed ?? '—'} />
      </div>
      <div className="text-xs text-outline">
        Mode: {scan.mode || '—'} · Target revision: {scan.configuration?.target_revision || 'not recorded'}
      </div>
      <div className="space-y-3">
        <h3 className="text-sm font-bold text-on-surface">Confirmed findings and evaluator evidence</h3>
        {scan.findings.map((finding) => (
          <article key={finding.finding_id} className="space-y-2 rounded-lg border border-red-200 bg-red-50 p-4 text-xs">
            <div className="font-bold text-red-800">{finding.finding_id} · {finding.test_id}</div>
            <div className="text-on-surface-variant">
              {finding.generation_method || 'predefined'}{finding.mutation_operator ? ` / ${finding.mutation_operator}` : ''}
              {' · '}parent {finding.parent_test_id || 'not recorded'}
              {' · '}baseline {finding.baseline_test_id || 'not recorded'}
            </div>
            <div className="text-on-surface-variant font-medium">Reason: {finding.reason || 'No evaluator reason recorded'}</div>
            <div className="text-on-surface-variant">Matched canary: {finding.matched_canary || '—'} · Rule: {finding.matched_rule || '—'}</div>
            <pre className="whitespace-pre-wrap break-words rounded bg-surface-container-lowest p-3 text-on-surface border border-red-200 font-mono text-xs">{finding.raw_response || finding.response_excerpt || 'No raw response recorded'}</pre>
          </article>
        ))}
        {!scan.findings.length && <p className="text-xs text-outline">No confirmed findings were persisted.</p>}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-[10px] uppercase tracking-wider text-outline font-semibold">
            <tr>
              <th className="py-2 pr-3">Test</th>
              <th className="py-2 pr-3">Generation / operator</th>
              <th className="py-2 pr-3">Verdict</th>
              <th className="py-2 pr-3">Parent</th>
              <th className="py-2">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-container-high/40">
            {scan.results.map((record) => (
              <tr key={record.test_id || record.id}>
                <td className="py-2 pr-3 font-mono text-primary font-semibold">{record.test_id || record.id}</td>
                <td className="py-2 pr-3">{record.generation_method || 'predefined'}{record.mutation_operator ? ` / ${record.mutation_operator}` : ''}</td>
                <td className={`py-2 pr-3 font-semibold ${record.verdict === 'VULNERABLE' ? 'text-red-800' : record.verdict === 'SAFE' ? 'text-emerald-800' : 'text-amber-800'}`}>
                  {record.verdict}
                </td>
                <td className="py-2 pr-3 font-mono text-outline">{record.parent_test_id || '—'}</td>
                <td className="max-w-sm py-2 text-on-surface-variant">{record.detail || 'No evaluator reason recorded'}</td>
              </tr>
            ))}
            {!scan.results.length && (
              <tr><td className="py-4 text-outline" colSpan="5">No execution records were saved for this scan.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function ScanHistory() {
  const [filters, setFilters] = useState({ scan_id_search: '', status: '', target_id: '', start_date: '', end_date: '' });
  const [page, setPage] = useState(1);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedIds, setSelectedIds] = useState([]);
  const [detail, setDetail] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [actionError, setActionError] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    let active = true;
    getScanHistory({ page, page_size: PAGE_SIZE, ...filters })
      .then((result) => {
        if (active) {
          setData(result);
          setError('');
        }
      })
      .catch((cause) => { if (active) setError(cause.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [page, filters]);

  const updateFilter = (key, value) => {
    setLoading(true);
    setPage(1);
    setSelectedIds([]);
    setComparison(null);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const changePage = (nextPage) => {
    setLoading(true);
    setPage(nextPage);
  };

  const toggleSelected = (scan) => {
    if (scan.status !== 'COMPLETED') return;
    setComparison(null);
    setSelectedIds((current) => (
      current.includes(scan.scan_id)
        ? current.filter((id) => id !== scan.scan_id)
        : current.length < 2 ? [...current, scan.scan_id] : [current[1], scan.scan_id]
    ));
  };

  const showDetails = async (scanId) => {
    setActionLoading(true);
    setActionError('');
    try {
      setDetail(await getScanHistoryDetail(scanId));
    } catch (cause) {
      setActionError(cause.message);
    } finally {
      setActionLoading(false);
    }
  };

  const runComparison = async () => {
    if (selectedIds.length !== 2) return;
    setActionLoading(true);
    setActionError('');
    setComparison(null);
    try {
      setComparison(await compareScanHistory(selectedIds[0], selectedIds[1]));
    } catch (cause) {
      setActionError(cause.message);
    } finally {
      setActionLoading(false);
    }
  };

  const scans = data?.scans || [];

  return (
    <div className="w-full space-y-6 p-space-xl max-w-7xl">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-surface-container-high/60 pb-5">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-primary">Persistent records</p>
          <h1 className="mt-1 font-headline text-2xl font-bold text-on-surface">Scan History & Comparisons</h1>
          <p className="mt-2 max-w-2xl text-xs text-on-surface-variant">
            Review saved executions and compare two completed scans. Comparisons evaluate equivalent test payloads across revisions.
          </p>
        </div>
        <Metric label="Matching Scans" value={data?.total ?? '—'} />
      </header>

      <section className="grid grid-cols-1 gap-3 rounded-xl border border-surface-container-high/60 bg-surface-container-low p-4 md:grid-cols-5">
        <label className="space-y-1 text-[10px] uppercase tracking-wider text-outline font-semibold">
          Scan ID
          <input value={filters.scan_id_search} onChange={(event) => updateFilter('scan_id_search', event.target.value)} placeholder="Search scan IDs" className="w-full rounded-lg border border-surface-container-high bg-surface-container-lowest px-3 py-2 text-xs text-on-surface outline-none focus:border-primary" />
        </label>
        <label className="space-y-1 text-[10px] uppercase tracking-wider text-outline font-semibold">
          Status
          <select value={filters.status} onChange={(event) => updateFilter('status', event.target.value)} className="w-full rounded-lg border border-surface-container-high bg-surface-container-lowest px-3 py-2 text-xs text-on-surface outline-none focus:border-primary">
            <option value="">All statuses</option>
            <option value="COMPLETED">Completed</option>
            <option value="FAILED">Failed</option>
            <option value="RUNNING">Running</option>
            <option value="CANCELLED">Cancelled</option>
          </select>
        </label>
        <label className="space-y-1 text-[10px] uppercase tracking-wider text-outline font-semibold">
          Target ID
          <input value={filters.target_id} onChange={(event) => updateFilter('target_id', event.target.value)} placeholder="Any target" className="w-full rounded-lg border border-surface-container-high bg-surface-container-lowest px-3 py-2 text-xs text-on-surface outline-none focus:border-primary" />
        </label>
        <label className="space-y-1 text-[10px] uppercase tracking-wider text-outline font-semibold">
          From
          <input type="date" value={filters.start_date} onChange={(event) => updateFilter('start_date', event.target.value)} className="w-full rounded-lg border border-surface-container-high bg-surface-container-lowest px-3 py-2 text-xs text-on-surface outline-none focus:border-primary" />
        </label>
        <label className="space-y-1 text-[10px] uppercase tracking-wider text-outline font-semibold">
          Through
          <input type="date" value={filters.end_date} onChange={(event) => updateFilter('end_date', event.target.value)} className="w-full rounded-lg border border-surface-container-high bg-surface-container-lowest px-3 py-2 text-xs text-on-surface outline-none focus:border-primary" />
        </label>
      </section>

      {error && <p role="alert" className="rounded-lg border border-error/40 bg-error/10 p-4 text-xs text-error font-medium">{error}</p>}
      {actionError && <p role="alert" className="rounded-lg border border-error/40 bg-error/10 p-4 text-xs text-error font-medium">{actionError}</p>}

      <section className="overflow-hidden rounded-xl border border-surface-container-high/60 bg-surface-container-lowest shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-surface-container-high/60 p-4">
          <div className="text-sm font-bold text-on-surface">Saved Audit Records</div>
          <button type="button" disabled={selectedIds.length !== 2 || actionLoading} onClick={runComparison} className="rounded-lg bg-primary px-4 py-2 text-xs font-bold text-on-primary disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer">
            {actionLoading ? 'Loading…' : selectedIds.length === 2 ? `Compare ${selectedIds[0]} → ${selectedIds[1]}` : 'Select two completed scans to compare'}
          </button>
        </div>
        {loading ? (
          <div className="p-8 text-center text-xs text-outline">Loading saved scans…</div>
        ) : !scans.length ? (
          <div className="p-8 text-center text-xs text-outline">No scans match these filters. Start a scan to create a history record.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface-container-low text-[10px] uppercase tracking-wider text-outline font-semibold">
                <tr>
                  <th className="px-4 py-3">Compare</th>
                  <th className="px-4 py-3">Scan</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Target / Model</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Tests</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container-high/40">
                {scans.map((scan) => (
                  <tr key={scan.scan_id} className="hover:bg-surface-container-low/70 transition-colors">
                    <td className="px-4 py-3">
                      <input aria-label={`Select ${scan.scan_id} for comparison`} type="checkbox" checked={selectedIds.includes(scan.scan_id)} disabled={scan.status !== 'COMPLETED'} onChange={() => toggleSelected(scan)} className="cursor-pointer" />
                    </td>
                    <td className="px-4 py-3 font-mono font-bold text-primary">{scan.scan_name || scan.scan_id}</td>
                    <td className="whitespace-nowrap px-4 py-3 text-on-surface-variant">{scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}</td>
                    <td className="px-4 py-3 text-on-surface-variant">{scan.target_name || scan.target_id || '—'}<div className="mt-0.5 text-[10px] text-outline">{scan.provider || '—'} / {scan.model || '—'}</div></td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        scan.status === 'COMPLETED'
                          ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                          : scan.status === 'FAILED'
                          ? 'bg-red-50 text-red-800 border border-red-200'
                          : 'bg-amber-50 text-amber-800 border border-amber-300'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-on-surface font-semibold">{scan.execution_count}</td>
                    <td className="px-4 py-3 font-semibold text-red-800">{scan.finding_count}</td>
                    <td className="px-4 py-3"><button type="button" onClick={() => showDetails(scan.scan_id)} className="text-primary font-semibold underline-offset-2 hover:underline cursor-pointer">View records</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex items-center justify-between border-t border-surface-container-high/60 px-4 py-3 text-xs text-outline">
          <span>{data?.total ?? 0} scans · page {data?.page ?? page} of {Math.max(data?.total_pages ?? 1, 1)}</span>
          <div className="flex gap-2">
            <button type="button" disabled={page <= 1 || loading} onClick={() => changePage(page - 1)} className="rounded border border-surface-container-high px-3 py-1.5 disabled:opacity-40 disabled:cursor-not-allowed hover:border-outline cursor-pointer transition-colors">Previous</button>
            <button type="button" disabled={page >= (data?.total_pages ?? 1) || loading} onClick={() => changePage(page + 1)} className="rounded border border-surface-container-high px-3 py-1.5 disabled:opacity-40 disabled:cursor-not-allowed hover:border-outline cursor-pointer transition-colors">Next</button>
          </div>
        </div>
      </section>

      {comparison && (
        <section className="space-y-4 rounded-xl border border-surface-container-high/60 bg-surface-container-low p-5 shadow-sm">
          <div>
            <h2 className="font-headline text-lg font-bold text-on-surface">Scan Comparison Analysis</h2>
            <p className="mt-1 text-xs text-outline">Baseline {comparison.baseline_id} → Current {comparison.current_id} · Matching Target Context: {comparison.target_context_matches ? 'Yes' : 'No'}</p>
            <p className="mt-2 text-xs text-on-surface-variant">{comparison.interpretation_note}</p>
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Metric label="Comparable executions" value={comparison.totals.comparable_executions} />
            <Metric label="Unique prompt coverage" value={comparison.coverage.comparable_unique_prompts} />
            <Metric label="New findings" value={comparison.new_findings.length} />
            <Metric label="Persistent findings" value={comparison.persistent_findings.length} />
            <Metric label="Not reproduced" value={comparison.not_reproduced_findings.length} />
          </div>
          <ul className="space-y-2 text-xs">
            {comparison.new_findings.map((item) => (
              <li key={item.finding.finding_id} className="rounded-lg border border-red-200 bg-red-50 p-3 text-on-surface">
                <strong className="text-red-800">New finding:</strong> {item.finding.finding_id} · parent {item.finding.parent_test_id || 'not recorded'} · {item.finding.reason}
              </li>
            ))}
            {comparison.persistent_findings.map((item) => (
              <li key={item.current_finding.finding_id} className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-on-surface">
                <strong className="text-amber-800">Persistent:</strong> {item.current_finding.finding_id} · parent {item.current_finding.parent_test_id || 'not recorded'}
              </li>
            ))}
            {comparison.not_reproduced_findings.map((item) => (
              <li key={item.finding.finding_id} className="rounded-lg border border-surface-container-high bg-surface-container-lowest p-3 text-on-surface-variant">
                Not reproduced: {item.finding.finding_id} · {item.reason}
              </li>
            ))}
            {!comparison.new_findings.length && !comparison.persistent_findings.length && !comparison.not_reproduced_findings.length && (
              <li className="text-outline">No comparable confirmed findings were reported.</li>
            )}
          </ul>
        </section>
      )}

      {detail && <ScanDetails scan={detail} />}
    </div>
  );
}
