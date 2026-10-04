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

// ── Status ────────────────────────────────────────────────────────────────────
/** Returns { llmguard, target_online, target_mode, scan_status } */
export const getStatus = () => request('/status');

// ── Target Mode ───────────────────────────────────────────────────────────────
/** Returns { mode, online } */
export const getTargetMode = () => request('/target/mode');

/** mode: "SECURE" | "VULNERABLE" → returns { mode } */
export const setTargetMode = (mode) =>
  request('/target/mode', { method: 'POST', body: JSON.stringify({ mode }) });

// ── Attacks ───────────────────────────────────────────────────────────────────
/** Returns { attacks: [...], total } */
export const getAttacks = () => request('/attacks');

// ── Scan ──────────────────────────────────────────────────────────────────────
/** Start a scan. mode?: "SECURE"|"VULNERABLE", categories?: string[] */
export const startScan = (payload = {}) =>
  request('/scan/start', { method: 'POST', body: JSON.stringify(payload) });

/** Lightweight poll — returns progress + summary counts */
export const getScanStatus = () => request('/scan/status');

/** Full results — all test records, category_stats, vulnerable_cases */
export const getScanResults = () => request('/scan/results');
