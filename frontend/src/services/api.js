// Central API service layer — all backend communication goes through here.
// LLMGuard backend runs on port 8001; Vite proxies /api → http://127.0.0.1:8001

const BASE = '/api';

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Status & Health ───────────────────────────────────────────────────────────
/** Returns { llmguard, target_online, target_mode, active_target, scan_status } */
export const getStatus = () => request('/status');

// ── Multi-Provider Target Management ──────────────────────────────────────────
/** List all available AI providers: Gemini, OpenAI, Claude, OpenRouter, Custom, TechMart */
export const getProviders = () => request('/providers');

/** List all configured targets without disclosing credentials */
export const getTargets = () => request('/targets');

/** Retrieve active target details */
export const getActiveTarget = () => request('/targets/active');

/** Add a new target configuration */
export const createTarget = (payload) =>
  request('/targets', { method: 'POST', body: JSON.stringify(payload) });

/** Update an existing target */
export const updateTarget = (targetId, payload) =>
  request(`/targets/${targetId}`, { method: 'PUT', body: JSON.stringify(payload) });

/** Delete target by ID */
export const deleteTarget = (targetId) =>
  request(`/targets/${targetId}`, { method: 'DELETE' });

/** Test target connectivity and credentials */
export const testTarget = (targetId) =>
  request(`/targets/${targetId}/test`, { method: 'POST' });

/** Select target as active */
export const selectTarget = (targetId) =>
  request(`/targets/${targetId}/select`, { method: 'POST' });

// ── Target Mode (TechMart compatibility) ──────────────────────────────────────
/** Returns { mode, online } */
export const getTargetMode = () => request('/target/mode');

/** mode: "SECURE" | "VULNERABLE" → returns { mode } */
export const setTargetMode = (mode) =>
  request('/target/mode', { method: 'POST', body: JSON.stringify({ mode }) });

// ── Attacks ───────────────────────────────────────────────────────────────────
/** Returns { attacks: [...], total } */
export const getAttacks = () => request('/attacks');

// ── Scan ──────────────────────────────────────────────────────────────────────
/** Start a scan against active or specific target. target_id?: string, mode?: string, categories?: string[] */
export const startScan = (payload = {}) =>
  request('/scan/start', { method: 'POST', body: JSON.stringify(payload) });

/** Lightweight poll — returns progress + current attack + summary counts */
export const getScanStatus = () => request('/scan/status');

/** Request that the current scan stop after its in-flight target request. */
export const stopScan = () => request('/scan/stop', { method: 'POST' });

/** Full results — all test records, category_stats, vulnerable_cases */
export const getScanResults = () => request('/scan/results');

/** Persistent scan history with optional pagination and filters. */
export const getScanHistory = (filters = {}) => {
  const query = new URLSearchParams(
    Object.entries(filters).filter(([, value]) => value !== '' && value != null)
  );
  return request(`/scans${query.size ? `?${query}` : ''}`);
};

/** Full persisted scan record, including executions and findings. */
export const getScanHistoryDetail = (scanId) =>
  request(`/scans/${encodeURIComponent(scanId)}`);

/** Compare two persisted scans. */
export const compareScanHistory = (baselineId, currentId) => {
  const query = new URLSearchParams({ baseline_id: baselineId, current_id: currentId });
  return request(`/scans/compare?${query}`);
};

/** Historical overview and trend data. */
export const getAnalyticsOverview = () => request('/analytics/overview');
export const getAnalyticsTrends = () => request('/analytics/trends');
export const getAnalyticsCategories = () => request('/analytics/categories');
