/* AGY Control Center — dashboard logic (plain JS, no dependencies) */
'use strict';

let STATE = {
  accounts: [],
  activeEmail: null,
  languageServer: {},
  instance: {},
  snapshots: [],
  settings: {},
  hub: {},
};

const UI = {
  expandedModels: new Set(),
  expandedWindows: new Set(),
  selected: new Set(),
  pending: new Set(),      // account ids with a refresh request in flight from this page
  busy: new Set(),         // account ids with a switch/remove in flight
  refreshingAll: false,
  connected: true,
  loadedOnce: false,
  privacy: localStorage.getItem('agy_privacy_mode') === '1' || new URLSearchParams(location.search).get('privacy') === '1',
  reqSeq: 0,
  appliedSeq: 0,
  htmlCache: new WeakMap(),    // element id -> last rendered HTML (skip untouched DOM)
};

const FAST_POLL_MS = 2000;   // while any account is syncing
const SLOW_POLL_MS = 10000;  // idle
const FULL_STATE_EVERY_MS = 60000;
const REFRESH_ICON = '<svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 2v6h-6"></path><path d="M3 12a9 9 0 0 1 15-6.7L21 8"></path><path d="M3 22v-6h6"></path><path d="M21 12a9 9 0 0 1-15 6.7L3 16"></path></svg>';
const SPINNER_ICON = '<svg aria-hidden="true" class="spin" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>';
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

const $ = (id) => document.getElementById(id);

/* ---------- Helpers ---------- */
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function maskEmail(email) {
  if (!email) return '—';
  if (!UI.privacy) return email;
  const idx = (STATE.accounts || []).findIndex(a => (a.email || '').toLowerCase() === String(email).toLowerCase());
  return `ag-node-${idx >= 0 ? String(idx + 1).padStart(2, '0') : 'xx'}@workspace.local`;
}

/* Mask every email inside free text (error messages, snapshot labels) while Privacy mode is on */
function maskText(text) {
  const s = String(text ?? '');
  return UI.privacy ? s.replace(EMAIL_RE, m => maskEmail(m)) : s;
}

function showToast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  if (isError) el.setAttribute('role', 'alert');
  el.textContent = maskText(msg);
  el.title = 'Click to dismiss';
  el.addEventListener('click', () => el.remove());
  $('toastWrap').appendChild(el);
  setTimeout(() => el.remove(), isError ? 8000 : 4000);
}

function timeAgo(iso) {
  const t = Date.parse(iso || '');
  if (!iso || Number.isNaN(t)) return 'never';
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 45) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${Math.max(1, min)}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ${min % 60}m ago`;
  return `${Math.floor(hr / 24)}d ${hr % 24}h ago`;
}

/* Live countdown from the reset timestamp, so cached rows never show a frozen "4h 54m" */
function countdownText(iso) {
  const t = Date.parse(iso || '');
  if (!iso || Number.isNaN(t)) return '';
  const diff = Math.floor((t - Date.now()) / 1000);
  if (diff <= 0) return 'reset due · refresh';
  const d = Math.floor(diff / 86400);
  const h = Math.floor((diff % 86400) / 3600);
  const m = Math.floor((diff % 3600) / 60);
  if (d > 0) return `resets ${d}d ${h}h`;
  if (h > 0) return `resets ${h}h ${m}m`;
  return `resets ${Math.max(1, m)}m`;
}

function updateDynamicTimes(root = document) {
  root.querySelectorAll('[data-rel]').forEach(el => {
    const txt = (el.dataset.prefix || '') + timeAgo(el.dataset.rel);
    if (el.textContent !== txt) el.textContent = txt;
  });
  root.querySelectorAll('[data-countdown]').forEach(el => {
    const txt = countdownText(el.dataset.countdown);
    if (el.textContent !== txt) el.textContent = txt;
  });
}

function colorClassForPct(pct) {
  if (pct <= 5) return 'red';
  if (pct <= 25) return 'amber';
  return 'green';
}

function formatPctDisplay(val) {
  const num = Number(val);
  if (val === undefined || val === null || Number.isNaN(num)) return '—';
  if (Number.isInteger(num) || num >= 100 || num <= 0) return `${Math.round(num)}%`;
  return `${num.toFixed(1)}%`;
}

function pctOf(obj) {
  const n = Number(obj.remainingExactPct !== undefined ? obj.remainingExactPct : (obj.remainingPct ?? 100));
  return Number.isNaN(n) ? 0 : Math.min(100, Math.max(0, n));
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    // Clipboard API can be blocked (permissions, non-focused app window): fall back to execCommand
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:-1000px;opacity:0;';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    ta.remove();
    return ok;
  }
}

/* Only touch the DOM when the markup really changed: keeps scroll position, focus and
   open drawers intact across background refreshes. */
function setHtml(el, html) {
  if (UI.htmlCache.get(el) === html) return false;
  const active = document.activeElement;
  let refocus = null;
  if (active && el.contains(active) && active.dataset && active.dataset.action) {
    refocus = `[data-action="${active.dataset.action}"]` + (active.dataset.id ? `[data-id="${active.dataset.id}"]` : '');
  }
  el.innerHTML = html;
  UI.htmlCache.set(el, html);
  updateDynamicTimes(el);
  if (refocus) {
    const again = el.querySelector(refocus);
    if (again) again.focus({ preventScroll: true });
  }
  return true;
}

/* ---------- API ---------- */
async function apiRequest(path, options) {
  let res;
  try {
    res = await fetch(path, { cache: 'no-store', ...options });
  } catch (e) {
    return { ok: false, networkError: true, error: 'Cannot reach the AGY hub backend' };
  }
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!data || typeof data !== 'object') {
    return { ok: false, error: `Unexpected response from hub (HTTP ${res.status})` };
  }
  if (!res.ok && data.ok === undefined) data.ok = false;
  if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
  return data;
}

const apiGet = (path) => apiRequest(path);
const apiPost = (path, body = {}) => apiRequest(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

function setConnected(ok) {
  if (UI.connected === ok) return;
  UI.connected = ok;
  $('connBanner').hidden = ok;
  renderHeader();
}

/* Apply an accounts payload unless a newer response has already been applied */
function applyAccounts(res, seq) {
  if (seq < UI.appliedSeq) return;
  UI.appliedSeq = seq;
  if (Array.isArray(res.accounts)) STATE.accounts = res.accounts;
  if ('activeEmail' in res) STATE.activeEmail = res.activeEmail;
  if (res.hub) STATE.hub = res.hub;
  renderAll();
}

async function loadState() {
  const seq = ++UI.reqSeq;
  const data = await apiGet('/api/state');
  if (data.networkError) { setConnected(false); return false; }
  if (!Array.isArray(data.accounts)) return false;
  setConnected(true);
  if (seq < UI.appliedSeq) return true;
  UI.appliedSeq = seq;
  STATE = { ...STATE, ...data };
  if (!UI.loadedOnce) {
    UI.loadedOnce = true;
    if (new URLSearchParams(location.search).get('expand') === '1' && STATE.accounts[0]) {
      UI.expandedModels.add(STATE.accounts[0].id);
    }
  }
  renderAll();
  return true;
}

async function loadAccounts() {
  const seq = ++UI.reqSeq;
  const data = await apiGet('/api/accounts');
  if (data.networkError) { setConnected(false); return false; }
  if (!Array.isArray(data.accounts)) return false;
  setConnected(true);
  applyAccounts(data, seq);
  return true;
}

/* ---------- Sync state model ---------- */
function syncInfo(acc) {
  const s = acc.sync || {};
  const flags = s.stale || {};
  const lastSuccess = s.lastSuccess || acc.last_synced || '';
  const syncing = !!acc.syncing || UI.pending.has(acc.id);
  let state = s.state || (acc.last_error ? 'failed' : (lastSuccess ? 'ok' : 'never'));
  const intervalMs = Number((STATE.hub || {}).autoRefreshIntervalSec || 0) * 1000;
  const staleAfterMs = Math.max(intervalMs * 3, 10 * 60 * 1000);
  const t = Date.parse(lastSuccess);
  const ageStale = !!lastSuccess && !Number.isNaN(t) && (Date.now() - t) > staleAfterMs;
  const message = (s.errors && s.errors.length)
    ? s.errors.map(e => `${e.step}: ${e.message}`).join(' · ')
    : (acc.last_error || '');
  if (state === 'ok' && ageStale) state = 'stale';
  return {
    state, syncing, lastSuccess, message: maskText(message),
    staleArgon: !!flags.argon, staleWindows: !!flags.windows, staleModels: !!flags.models,
    tokenError: acc.status === 'Token Error',
  };
}

function syncStateHtml(si) {
  const rel = (prefix) => `<span data-rel="${escapeHtml(si.lastSuccess)}" data-prefix="${prefix}"></span>`;
  if (si.syncing) return `<span class="sync-state s-busy">${SPINNER_ICON} Syncing…</span>`;
  switch (si.state) {
    case 'ok': return `<span class="sync-state s-ok"><span class="dot"></span>${rel('Synced ')}</span>`;
    case 'stale': return `<span class="sync-state s-warn"><span class="dot"></span>${rel('Stale · last synced ')}</span>`;
    case 'partial': return `<span class="sync-state s-warn"><span class="dot"></span>${rel('Partial sync · last full ')}</span>`;
    case 'failed': return `<span class="sync-state s-err"><span class="dot"></span>${rel(si.tokenError ? 'Token error · last synced ' : 'Sync failed · last synced ')}</span>`;
    default: return '<span class="sync-state"><span class="dot"></span>Not synced yet</span>';
  }
}

function statusBadgeHtml(acc, si) {
  const title = si.message ? ` title="${escapeHtml(si.message)}"` : '';
  if (si.syncing) return '<span class="badge badge-info">Syncing</span>';
  if (si.state === 'failed') return `<span class="badge badge-error"${title}>${si.tokenError ? 'Token Error' : 'Sync Error'}</span>`;
  if (si.state === 'partial') return `<span class="badge badge-warn"${title}>Degraded</span>`;
  if (si.state === 'stale') return '<span class="badge badge-warn" title="No successful sync recently">Stale</span>';
  if (si.state === 'never') return '<span class="badge badge-neutral">Pending</span>';
  return `<span class="badge badge-ok">${escapeHtml(acc.status || 'Enabled')}</span>`;
}

/* ---------- Rendering ---------- */
function renderAll() {
  renderHeader();
  renderAccountsTable();
  renderWorkspacesTab();
  renderSnapshotsTab();
}

function renderHeader() {
  const lsBadge = $('lsStatusBadge');
  if (!UI.loadedOnce) {
    lsBadge.textContent = UI.connected ? 'Connecting…' : 'Offline';
    lsBadge.className = 'badge ' + (UI.connected ? 'badge-neutral' : 'badge-error');
  } else if (!UI.connected) {
    lsBadge.textContent = 'Hub offline';
    lsBadge.className = 'badge badge-error';
  } else if (STATE.languageServer && STATE.languageServer.running) {
    lsBadge.textContent = `LS Active · PID ${STATE.languageServer.pid}`;
    lsBadge.className = 'badge badge-ok';
  } else {
    lsBadge.textContent = 'Direct CloudCode Mode';
    lsBadge.className = 'badge badge-plan';
  }

  const privBtn = $('privacyToggleBtn');
  privBtn.classList.toggle('btn-active-toggle', UI.privacy);
  privBtn.setAttribute('aria-pressed', UI.privacy ? 'true' : 'false');
  $('privacyToggleLabel').textContent = UI.privacy ? 'Privacy: ON' : 'Privacy';

  $('activeCredBanner').textContent =
    `Active WinCred (gemini:antigravity): ${STATE.activeEmail ? maskEmail(STATE.activeEmail) : 'None'}`;

  const settings = STATE.settings || {};
  const setChecked = (id, val) => { const el = $(id); if (document.activeElement !== el) el.checked = !!val; };
  setChecked('chkPinWorkspaces', settings.pinWorkspacesOnSwitch);
  setChecked('chkAutoSnap', settings.autoSnapshotBeforeSwitch);
  setChecked('chkHotReloadLS', settings.hotReloadLanguageServer);
  const sel = $('selAutoRefresh');
  if (document.activeElement !== sel) {
    const sec = String(settings.autoRefreshIntervalSec ?? 120);
    if (![...sel.options].some(o => o.value === sec)) {
      const opt = document.createElement('option');
      opt.value = sec;
      opt.textContent = `${sec}s`;
      sel.appendChild(opt);
    }
    sel.value = sec;
  }

  $('countAccounts').textContent = (STATE.accounts || []).length;
  $('countWorkspaces').textContent = ((STATE.instance && STATE.instance.projects) || []).length;
  $('countSnapshots').textContent = (STATE.snapshots || []).length;

  const anySyncing = UI.refreshingAll || (STATE.hub || {}).refreshingAll;
  const btn = $('refreshAllBtn');
  btn.disabled = !!anySyncing;
  btn.setAttribute('aria-busy', anySyncing ? 'true' : 'false');
  $('refreshAllIcon').classList.toggle('spin', !!anySyncing);
  $('refreshAllLabel').textContent = anySyncing ? 'Refreshing…' : 'Refresh All';

  const hub = STATE.hub || {};
  const interval = Number(hub.autoRefreshIntervalSec || 0);
  const autoTxt = interval > 0
    ? `Auto-refresh every ${interval >= 60 ? Math.round(interval / 60) + ' min' : interval + 's'}`
    : 'Auto-refresh off';
  let globalHtml;
  if (!UI.connected) globalHtml = 'Hub unreachable — showing last known data';
  else if (anySyncing) globalHtml = 'Refreshing all accounts…';
  else if (hub.lastRefreshAll) globalHtml = `${autoTxt} · <span data-rel="${escapeHtml(hub.lastRefreshAll)}" data-prefix="last full sync "></span>`;
  else globalHtml = autoTxt;
  setHtml($('globalSyncStatus'), globalHtml);
}

function windowHtml(w) {
  const pct = pctOf(w);
  const ccls = colorClassForPct(pct);
  const isArgon = w.bucketId === 'gemini-4-argon';
  const shortTitle = isArgon ? 'Gemini 4 Argon' : (w.shortLabel || w.label || w.bucketId);
  const leftSub = isArgon
    ? `H/M/L · 1M ctx · ${formatPctDisplay(w.usedExactPct ?? (100 - pct))} used`
    : (w.window ? `${w.window} window` : 'quota window');
  const staleChip = w.stale
    ? `<span class="chip chip-warn" title="Could not be refreshed on the last sync — showing the value from ${escapeHtml(timeAgo(w.asOf))}">stale</span>`
    : '';
  return `
    <div class="quota-window ${isArgon ? 'argon-featured' : ''} ${w.stale ? 'is-stale' : ''}">
      <div class="qw-top">
        <span class="qw-name" title="${escapeHtml(w.label || shortTitle)}">
          ${escapeHtml(shortTitle)}
          ${isArgon ? '<span class="chip chip-new">NEW</span>' : ''}
          ${staleChip}
        </span>
        <span class="qw-pct ${ccls}">${formatPctDisplay(pct)} left</span>
      </div>
      <div class="qw-bar-track" role="progressbar" aria-label="${escapeHtml(shortTitle)} remaining" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct)}">
        <div class="qw-bar-fill ${ccls}" style="width:${Math.max(pct, 2)}%;"></div>
      </div>
      <div class="qw-bottom">
        <span class="qw-bottom-left">${escapeHtml(leftSub)}</span>
        <span class="qw-bottom-right" data-countdown="${escapeHtml(w.resetTime || '')}"></span>
      </div>
    </div>`;
}

function usageHtml(acc, si, label) {
  const windows = acc.quota_windows || [];
  const visibleLimit = 4;
  const expanded = UI.expandedWindows.has(acc.id);
  const shown = expanded ? windows : windows.slice(0, visibleLimit);
  const hiddenCount = Math.max(0, windows.length - visibleLimit);
  const id = escapeHtml(acc.id);

  let html = `
    <div class="sync-row">
      ${syncStateHtml(si)}
      <button type="button" class="icon-btn" data-action="refresh-one" data-id="${id}" ${si.syncing ? 'disabled' : ''}
        title="Refresh this account's quotas now" aria-label="Refresh quotas for ${escapeHtml(label)}">${si.syncing ? SPINNER_ICON : REFRESH_ICON}</button>
    </div>`;

  if (si.message && !si.syncing && (si.state === 'failed' || si.state === 'partial')) {
    html += `<div class="sync-msg ${si.state === 'failed' ? 's-err' : 's-warn'}" title="${escapeHtml(si.message)}">${escapeHtml(si.message)}</div>`;
  }

  const hasArgon = windows.some(w => w.bucketId === 'gemini-4-argon');
  if (!hasArgon && (si.state === 'failed' || si.state === 'partial')) {
    html += '<div class="quota-window argon-featured is-missing">Gemini 4 Argon — no data yet (last sync did not complete)</div>';
  }

  if (windows.length === 0) {
    html += `<div class="usage-empty">${si.syncing ? 'Fetching quota windows…' : 'No quota data yet. Use the refresh button to fetch it.'}</div>`;
  } else {
    html += shown.map(windowHtml).join('');
    if (hiddenCount > 0) {
      html += `<button type="button" class="btn-link" data-action="toggle-windows" data-id="${id}" aria-expanded="${expanded}">${expanded ? 'Show less' : `+${hiddenCount} more window${hiddenCount > 1 ? 's' : ''}`}</button>`;
    }
  }
  return html;
}

function modelCardHtml(m, stale) {
  const pct = pctOf(m);
  const ccls = colorClassForPct(pct);
  const isArgon = `${m.modelId || ''} ${m.label || ''}`.toLowerCase().includes('argon');
  const ctxStr = m.maxTokens ? (m.maxTokens >= 1000000 ? '1M ctx' : `${Math.round(m.maxTokens / 1024)}K ctx`) : '';
  const outStr = m.maxOutputTokens ? `${Math.round(m.maxOutputTokens / 1024)}K out` : '';
  const caps = [ctxStr, outStr, m.supportsThinking ? 'Think' : '', m.supportsImages ? 'Vision' : ''].filter(Boolean).join(' · ');
  return `
    <div class="model-card ${isArgon ? 'argon-highlight' : ''} ${stale ? 'is-stale' : ''}">
      <div class="model-card-top">
        <span class="model-name" title="${escapeHtml(m.label)} (${escapeHtml(m.modelId)})">${escapeHtml(m.label)}</span>
        <span class="qw-pct ${ccls}">${formatPctDisplay(pct)}</span>
      </div>
      <div class="qw-bar-track" role="progressbar" aria-label="${escapeHtml(m.label)} remaining" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct)}">
        <div class="qw-bar-fill ${ccls}" style="width:${Math.max(pct, 2)}%;"></div>
      </div>
      <div class="qw-bottom">
        <span class="qw-bottom-left">${escapeHtml(m.modelId)}</span>
        <span class="qw-bottom-right" data-countdown="${escapeHtml(m.resetTime || '')}"></span>
      </div>
      ${caps ? `<div class="qw-bottom"><span class="qw-bottom-left">${escapeHtml(caps)}</span><span class="qw-bottom-right">${escapeHtml(m.resetFormatted && m.resetFormatted !== '—' ? m.resetFormatted : '')}</span></div>` : ''}
    </div>`;
}

function drawerHtml(acc, si, label) {
  const models = acc.models || [];
  const id = escapeHtml(acc.id);
  const modelsSynced = acc.models_synced || si.lastSuccess;
  let banner = '';
  if (si.syncing) {
    banner = `<div class="drawer-banner s-busy"><span>${SPINNER_ICON} Fetching live per-model quotas…</span></div>`;
  } else if (si.state === 'failed' || si.staleModels) {
    banner = `<div class="drawer-banner s-err" role="alert">
      <span>${models.length ? `Showing cached model data from ${escapeHtml(timeAgo(modelsSynced))}. ` : ''}Last sync failed${si.message ? `: ${escapeHtml(si.message)}` : '.'}</span>
      <button type="button" class="btn btn-sm" data-action="refresh-one" data-id="${id}">Retry</button>
    </div>`;
  } else if (si.state === 'partial' || si.state === 'stale') {
    banner = `<div class="drawer-banner s-warn">
      <span>${si.state === 'stale' ? `This data is ${escapeHtml(timeAgo(si.lastSuccess))} old.` : `Partial sync${si.message ? `: ${escapeHtml(si.message)}` : '.'}`}</span>
      <button type="button" class="btn btn-sm" data-action="refresh-one" data-id="${id}">Refresh</button>
    </div>`;
  }

  let grid;
  if (models.length) {
    grid = models.map(m => modelCardHtml(m, si.staleModels || si.state === 'failed')).join('');
  } else if (si.syncing) {
    grid = '<div class="skeleton"></div>'.repeat(6);
  } else {
    grid = '<div class="list-empty">No per-model data cached yet. Use Refresh to load it.</div>';
  }

  return `
    <tr class="models-drawer-row">
      <td colspan="7">
        <div class="models-drawer" id="drawer-${id}" role="region" aria-label="Per-model quotas for ${escapeHtml(label)}">
          <div class="models-drawer-title">
            <span>Per-model quotas · ${models.length} unique models — ${escapeHtml(label)}</span>
            <span class="models-drawer-meta">
              ${modelsSynced ? `<span data-rel="${escapeHtml(modelsSynced)}" data-prefix="models synced "></span>` : ''}
              <span title="OAuth access token expiry (refreshed automatically)">token exp ${escapeHtml(acc.tokenExpiry ? new Date(acc.tokenExpiry).toLocaleTimeString() : 'auto')}</span>
            </span>
          </div>
          ${banner}
          <div class="models-grid" aria-busy="${si.syncing}">${grid}</div>
        </div>
      </td>
    </tr>`;
}

function accountHtml(acc) {
  const si = syncInfo(acc);
  const id = escapeHtml(acc.id);
  const label = maskEmail(acc.email);
  const expanded = UI.expandedModels.has(acc.id);
  const totalModels = acc.models_count || (acc.models ? acc.models.length : 0);
  const activeModels = acc.active_models_count !== undefined ? acc.active_models_count : totalModels;
  const busy = UI.busy.has(acc.id);

  let creditsHtml;
  if (acc.prompt_credits_available !== undefined && acc.prompt_credits_available !== null) {
    creditsHtml = `
      <div class="credit-main">${Number(acc.prompt_credits_available).toLocaleString()} <span class="credit-sub">prompt</span></div>
      <div class="credit-sub">${Number(acc.flow_credits_available || 0).toLocaleString()} flow</div>
      <div class="credit-sub" title="${escapeHtml(acc.project_id || '')}">${escapeHtml(acc.project_id || 'aicode-consumers')}</div>`;
  } else {
    creditsHtml = `
      <div class="credit-main">${acc.has_ai_credits ? 'AI Credits' : 'Standard Pool'}</div>
      <div class="credit-sub" title="${escapeHtml(acc.project_id || '')}">${escapeHtml(acc.project_id || 'aicode-consumers')}</div>`;
  }

  return `
    <tr class="account-row ${acc.isActive ? 'active-account' : ''}">
      <td class="col-check">
        <input type="checkbox" class="row-checkbox" data-select-id="${id}" ${UI.selected.has(acc.id) ? 'checked' : ''} aria-label="Select ${escapeHtml(label)}">
      </td>
      <td class="col-account">
        <div class="acc-header">
          <button type="button" class="expand-arrow ${expanded ? 'open' : ''}" data-action="toggle-drawer" data-id="${id}"
            aria-expanded="${expanded}" aria-controls="drawer-${id}" aria-label="${expanded ? 'Hide' : 'Show'} per-model quotas for ${escapeHtml(label)}">
            <svg aria-hidden="true" width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5l11 7-11 7z"></path></svg>
          </button>
          <div class="acc-title-wrap">
            <div class="acc-title">
              <span>Antigravity OAuth</span>
              ${acc.isActive ? '<span class="badge-active-ide">ACTIVE</span>' : ''}
            </div>
            <div class="acc-email" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
            <div class="acc-sub">${totalModels ? `${activeModels}/${totalModels} models with quota left` : 'models not loaded yet'}</div>
          </div>
        </div>
      </td>
      <td class="col-status">${statusBadgeHtml(acc, si)}</td>
      <td class="col-plan"><span class="badge badge-plan">${escapeHtml(acc.plan_name || 'Google AI Pro')}</span></td>
      <td class="col-usage">${usageHtml(acc, si, label)}</td>
      <td class="col-credits">${creditsHtml}</td>
      <td class="col-actions">
        <div class="action-group">
          ${acc.isActive
            ? `<button type="button" class="btn btn-sm" data-action="switch" data-id="${id}" ${busy ? 'disabled' : ''} title="Re-write the active credential and preserve workspace state">Re-Sync</button>`
            : `<button type="button" class="btn btn-activate btn-sm" data-action="switch" data-id="${id}" ${busy ? 'disabled' : ''}>⚡ Activate</button>`}
          <button type="button" class="btn btn-danger-icon" data-action="remove" data-id="${id}" ${busy ? 'disabled' : ''} title="Remove account from Hub" aria-label="Remove ${escapeHtml(label)} from Hub">
            <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14H6L5 6"></path><path d="M10 11v6M14 11v6M9 6V3h6v3"></path></svg>
          </button>
        </div>
      </td>
    </tr>
    ${expanded ? drawerHtml(acc, si, label) : ''}`;
}

/* One <tbody> per account, patched individually: a background refresh only rewrites
   the accounts whose data changed, so open drawers and scroll position survive. */
function renderAccountsTable() {
  const table = $('accountsTable');
  const accounts = STATE.accounts || [];
  $('tableFooterCount').textContent = `${accounts.length} account${accounts.length === 1 ? '' : 's'}`;

  const placeholder = $('accountsPlaceholder');
  placeholder.hidden = accounts.length > 0;
  if (accounts.length === 0) {
    setHtml(placeholder, `<tr><td colspan="7" class="table-empty">${
      UI.loadedOnce
        ? 'No Google accounts connected yet. Choose <strong>Add Account</strong> above to sign in.'
        : (UI.connected ? 'Loading accounts and live model telemetry…' : 'Cannot reach the AGY hub backend.')
    }</td></tr>`);
  }

  const ids = new Set(accounts.map(a => a.id));
  for (const id of [...UI.selected]) if (!ids.has(id)) UI.selected.delete(id);
  table.querySelectorAll('tbody[data-acc-id]').forEach(tb => {
    if (!ids.has(tb.dataset.accId)) { UI.htmlCache.delete(tb); tb.remove(); }
  });

  let prev = placeholder;
  for (const acc of accounts) {
    let tb = [...table.tBodies].find(t => t.dataset.accId === acc.id);
    if (!tb) {
      tb = document.createElement('tbody');
      tb.dataset.accId = acc.id;
    }
    if (prev.nextElementSibling !== tb) prev.after(tb);
    setHtml(tb, accountHtml(acc));
    prev = tb;
  }
  renderBulkBar();
}

function renderBulkBar() {
  const n = UI.selected.size;
  const total = (STATE.accounts || []).length;
  $('bulkBar').hidden = n === 0;
  $('bulkCount').textContent = `${n} selected`;
  const all = $('selectAll');
  all.checked = total > 0 && n === total;
  all.indeterminate = n > 0 && n < total;
}

function listHtml(items, emptyText) {
  return items.join('') || `<div class="list-empty">${escapeHtml(emptyText)}</div>`;
}

function renderWorkspacesTab() {
  const inst = STATE.instance || {};
  const projects = inst.projects || [];
  const convs = inst.conversations || [];
  const mcps = inst.mcpServers || [];
  const uset = inst.userSettings || {};
  const appst = inst.appStorage || {};

  setHtml($('projectsList'), listHtml(projects.map(p => `
    <div class="list-item">
      <div>
        <div class="list-item-title">${escapeHtml(p.name)}</div>
        <div class="list-item-sub">${escapeHtml((p.folders || []).map(f => f.path).join(', ') || p.file)}</div>
      </div>
      <span class="badge badge-ok">Pinned</span>
    </div>`), 'No project definitions found.'));

  $('convTotalBadge').textContent = convs.length;
  setHtml($('conversationsList'), listHtml(convs.slice(0, 25).map(c => `
    <div class="list-item">
      <div>
        <div class="list-item-title">${escapeHtml(c.title)}</div>
        <div class="list-item-sub">${escapeHtml((c.workspaces || []).join(', ') || c.id)} · ${Number(c.steps) || 0} steps</div>
      </div>
      <span class="tab-count">${escapeHtml(c.status || 'IDLE')}</span>
    </div>`), 'No conversations found.'));

  $('mcpTotalBadge').textContent = mcps.length;
  setHtml($('mcpList'), listHtml(mcps.map(m => `
    <div class="list-item">
      <div>
        <div class="list-item-title">${escapeHtml(m.name)}</div>
        <div class="list-item-sub">${escapeHtml(m.command)}</div>
      </div>
      <span class="badge ${m.disabled ? 'badge-error' : 'badge-ok'}">${m.disabled ? 'Disabled' : 'Enabled'}</span>
    </div>`), 'No MCP servers configured.'));

  const settingsEntries = [
    ['lastLoginUsername (app_storage.json)', appst.lastLoginUsername ? maskEmail(appst.lastLoginUsername) : '—'],
    ['Saved Multi-Conversation Window Layouts', appst.savedWindowLayoutsCount ?? 0],
    ['Last Selected Project ID', appst.lastSelectedProject || '—'],
    ...Object.entries(uset).map(([k, v]) => [`userSettings.${k}`, maskText(JSON.stringify(v))]),
  ];
  setHtml($('settingsList'), settingsEntries.map(([k, v]) => `
    <div class="list-item">
      <div class="list-item-title mono">${escapeHtml(k)}</div>
      <div class="list-item-sub value">${escapeHtml(v)}</div>
    </div>`).join(''));
}

function renderSnapshotsTab() {
  const snaps = STATE.snapshots || [];
  setHtml($('snapshotsList'), listHtml(snaps.map(s => `
    <div class="list-item">
      <div>
        <div class="list-item-title">${escapeHtml(maskText(s.label))} <span class="tab-count">${escapeHtml(s.tag || 'snapshot')}</span></div>
        <div class="list-item-sub">${escapeHtml(s.id)} · Created ${escapeHtml(new Date(s.createdAt).toLocaleString())} · Files: ${escapeHtml((s.files || []).join(', '))}</div>
      </div>
      <button type="button" class="btn btn-activate btn-sm" data-action="restore-snapshot" data-id="${escapeHtml(s.id)}">Restore</button>
    </div>`), 'No snapshots created yet.'));
}

/* ---------- Actions ---------- */
function findAccount(id) {
  return (STATE.accounts || []).find(a => a.id === id);
}

function switchTab(tab, focus = false) {
  ['accounts', 'workspaces', 'snapshots'].forEach(t => {
    const on = t === tab;
    $(`view-${t}`).hidden = !on;
    const btn = $(`tabBtn-${t}`);
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
    btn.tabIndex = on ? 0 : -1;
    if (on && focus) btn.focus();
  });
  if (tab !== 'accounts') loadState();
}

function summarizeRefresh(accounts, ids) {
  const scope = accounts.filter(a => !ids || ids.includes(a.id));
  const failed = scope.filter(a => (a.sync || {}).state === 'failed');
  const partial = scope.filter(a => (a.sync || {}).state === 'partial');
  const running = scope.filter(a => a.syncing);
  if (failed.length || partial.length) {
    const first = failed[0] || partial[0];
    const why = ((first.sync || {}).errors || [])[0];
    showToast(
      `${scope.length - failed.length - partial.length}/${scope.length} synced · ${failed.length} failed` +
      (partial.length ? ` · ${partial.length} partial` : '') +
      (why ? ` — ${maskEmail(first.email)}: ${why.message}` : ''), true);
  } else if (running.length) {
    showToast(`${running.length} account${running.length > 1 ? 's are' : ' is'} still syncing in the background`);
  } else {
    showToast(scope.length === 1 ? `Synced live quotas for ${maskEmail(scope[0].email)}` : `Synced live quotas for ${scope.length} accounts`);
  }
}

async function refreshAccounts(ids) {
  const targets = ids.filter(id => !UI.pending.has(id));
  if (!targets.length) return;
  targets.forEach(id => UI.pending.add(id));
  renderAccountsTable();
  schedulePoll(FAST_POLL_MS);
  const seq = ++UI.reqSeq;
  try {
    const res = await apiPost('/api/accounts/refresh', { accountIds: targets });
    targets.forEach(id => UI.pending.delete(id));
    if (res.ok) {
      setConnected(true);
      applyAccounts(res, seq);
      summarizeRefresh(res.accounts, targets);
    } else {
      if (res.networkError) setConnected(false);
      showToast(`Refresh failed: ${res.error || 'unknown error'}`, true);
    }
  } finally {
    targets.forEach(id => UI.pending.delete(id));
    renderAccountsTable();
  }
}

async function refreshAllAccounts() {
  if (UI.refreshingAll) return;
  UI.refreshingAll = true;
  (STATE.accounts || []).forEach(a => UI.pending.add(a.id));
  renderAll();
  schedulePoll(FAST_POLL_MS);
  const seq = ++UI.reqSeq;
  try {
    const res = await apiPost('/api/accounts/refresh', {});
    UI.pending.clear();
    UI.refreshingAll = false;
    if (res.ok) {
      setConnected(true);
      applyAccounts(res, seq);
      if (res.accounts.length) summarizeRefresh(res.accounts, null);
    } else {
      if (res.networkError) setConnected(false);
      showToast(`Refresh failed: ${res.error || 'unknown error'}`, true);
    }
  } finally {
    UI.pending.clear();
    UI.refreshingAll = false;
    renderAll();
  }
}

async function switchAccount(accId) {
  if (UI.busy.has(accId)) return;
  UI.busy.add(accId);
  renderAccountsTable();
  const seq = ++UI.reqSeq;
  try {
    const res = await apiPost('/api/accounts/switch', {
      accountId: accId,
      reloadLanguageServer: $('chkHotReloadLS').checked,
    });
    if (res.ok) {
      applyAccounts(res, seq);
      showToast(`Activated ${maskEmail(res.switchedTo)} in WinCred (workspaces & sessions preserved)`);
    } else {
      showToast(`Switch failed: ${res.error || 'unknown error'}`, true);
    }
  } finally {
    UI.busy.delete(accId);
    renderAccountsTable();
  }
}

async function removeAccount(accId) {
  const acc = findAccount(accId);
  if (!acc || UI.busy.has(accId)) return;
  const label = maskEmail(acc.email);
  if (!confirm(`Remove ${label} from AGY Control Center?`)) return;
  UI.busy.add(accId);
  const seq = ++UI.reqSeq;
  try {
    const res = await apiPost('/api/accounts/remove', { accountId: accId });
    if (res.ok) {
      UI.expandedModels.delete(accId);
      UI.expandedWindows.delete(accId);
      showToast(`Removed ${label}`);
      applyAccounts(res, seq);
    } else {
      showToast(`Remove failed: ${res.error || 'account not found'}`, true);
    }
  } finally {
    UI.busy.delete(accId);
    renderAccountsTable();
  }
}

async function createManualSnapshot() {
  const res = await apiPost('/api/snapshots/create', {});
  if (res.ok) {
    STATE.snapshots = res.snapshots;
    renderAll();
    showToast(`Saved instance snapshot: ${res.snapshot.label}`);
  } else {
    showToast(`Snapshot failed: ${res.error || 'unknown error'}`, true);
  }
}

async function restoreSnapshot(snapId) {
  const snap = (STATE.snapshots || []).find(s => s.id === snapId);
  const label = maskText(snap ? snap.label : snapId);
  if (!confirm(`Restore "${label}"?\n\nThis overwrites the current Antigravity workspace, layout and settings files. Your signed-in account is kept.`)) return;
  const res = await apiPost('/api/snapshots/restore', { snapshotId: snapId });
  if (res.ok) {
    STATE.instance = res.instance;
    STATE.snapshots = res.snapshots;
    renderAll();
    showToast(`Restored "${label}"${STATE.activeEmail ? ` while keeping ${maskEmail(STATE.activeEmail)} logged in` : ''}`);
  } else {
    showToast(`Restore failed: ${res.error || 'snapshot not found'}`, true);
  }
}

async function saveSettings() {
  const body = {
    pinWorkspacesOnSwitch: $('chkPinWorkspaces').checked,
    autoSnapshotBeforeSwitch: $('chkAutoSnap').checked,
    hotReloadLanguageServer: $('chkHotReloadLS').checked,
    autoRefreshIntervalSec: Number($('selAutoRefresh').value),
  };
  const res = await apiPost('/api/settings/update', body);
  if (res.ok && res.settings) {
    STATE.settings = res.settings;
    STATE.hub = { ...(STATE.hub || {}), autoRefreshIntervalSec: res.settings.autoRefreshIntervalSec };
    renderAll();
  } else {
    showToast(`Could not save settings: ${res.error || 'unknown error'}`, true);
    renderHeader();
  }
}

function togglePrivacyMode() {
  UI.privacy = !UI.privacy;
  localStorage.setItem('agy_privacy_mode', UI.privacy ? '1' : '0');
  renderAll();
  showToast(UI.privacy ? 'Privacy Mode enabled: emails and personal names masked' : 'Privacy Mode disabled');
}

/* ---------- Modal (focus trap, Esc to close, focus restore) ---------- */
const Modal = {
  current: null,
  opener: null,
  onClose: null,
  open(id, { focus, onClose } = {}) {
    if (this.current) this.close();
    this.current = $(id);
    this.opener = document.activeElement;
    this.onClose = onClose || null;
    this.current.classList.add('open');
    const target = (focus && $(focus)) || this.focusables()[0];
    if (target) target.focus();
  },
  close() {
    if (!this.current) return;
    this.current.classList.remove('open');
    const cb = this.onClose;
    const opener = this.opener;
    this.current = this.opener = this.onClose = null;
    if (cb) cb();
    if (opener && document.contains(opener)) opener.focus();
  },
  focusables() {
    if (!this.current) return [];
    return [...this.current.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
      .filter(el => !el.disabled && el.offsetParent !== null);
  },
  handleKey(e) {
    if (!this.current) return;
    if (e.key === 'Escape') { e.preventDefault(); this.close(); return; }
    if (e.key !== 'Tab') return;
    const items = this.focusables();
    if (!items.length) { e.preventDefault(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    if (!this.current.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  },
};

function openImportModal() {
  $('importTokenInput').value = '';
  Modal.open('importModal', { focus: 'importTokenInput' });
}

async function submitImportToken() {
  let raw = $('importTokenInput').value.trim();
  if (!raw) { $('importTokenInput').focus(); return; }
  if (raw.startsWith('{')) {
    try {
      const parsed = JSON.parse(raw);
      raw = (parsed.token && parsed.token.refresh_token) || parsed.refresh_token || raw;
    } catch (e) { /* not JSON: send as-is */ }
  }
  const btn = $('importSubmitBtn');
  btn.disabled = true;
  const seq = ++UI.reqSeq;
  try {
    const res = await apiPost('/api/accounts/import-token', { refreshToken: raw });
    if (res.ok) {
      Modal.close();
      applyAccounts(res, seq);
      showToast('Account imported and quota windows synced');
    } else {
      showToast(`Import error: ${res.error || 'unknown error'}`, true);
    }
  } finally {
    btn.disabled = false;
  }
}

/* ---------- Direct Google OAuth flow ---------- */
const OAuth = { state: null, authUrl: '', timer: null, startedAt: 0 };
const OAUTH_WAIT_LIMIT_MS = 15 * 60 * 1000;

function stopOAuthWait() {
  if (OAuth.timer) clearInterval(OAuth.timer);
  OAuth.timer = null;
  OAuth.state = null;
  $('oauthBanner').hidden = true;
}

function watchOAuth(state, authUrl) {
  stopOAuthWait();
  OAuth.state = state;
  OAuth.authUrl = authUrl;
  OAuth.startedAt = Date.now();
  $('oauthBanner').hidden = false;
  OAuth.timer = setInterval(async () => {
    if (OAuth.state !== state) return;
    const st = await apiGet(`/api/oauth/status?state=${encodeURIComponent(state)}`);
    if (OAuth.state !== state || st.networkError) return;
    if (st.status === 'completed') {
      stopOAuthWait();
      await loadState();
      showToast(`Connected & verified ${maskEmail(st.email)}`);
    } else if (st.status === 'error' || st.error) {
      stopOAuthWait();
      showToast(`Sign-in failed: ${st.error || 'unknown error'}`, true);
    } else if (st.status === 'unknown' || st.status === 'expired' || Date.now() - OAuth.startedAt > OAUTH_WAIT_LIMIT_MS) {
      stopOAuthWait();
      showToast('The sign-in attempt expired. Choose Add Account to start again.', true);
    }
  }, 1500);
}

async function startGoogleOAuth() {
  const res = await apiPost('/api/accounts/add-oauth', { openBrowser: true });
  if (!res.ok) {
    showToast(`Failed to start sign-in: ${res.error || 'unknown error'}`, true);
    return;
  }
  watchOAuth(res.state, res.authUrl);
}

/* ---------- Event wiring (delegated, so re-rendered rows need no re-binding) ---------- */
const ACTIONS = {
  'add-account': () => startGoogleOAuth(),
  'open-import': () => openImportModal(),
  'import-submit': () => submitImportToken(),
  'close-modal': () => Modal.close(),
  'refresh-all': () => refreshAllAccounts(),
  'refresh-one': (el) => refreshAccounts([el.dataset.id]),
  'refresh-selected': () => refreshAccounts([...UI.selected]),
  'clear-selection': () => { UI.selected.clear(); renderAccountsTable(); },
  'snapshot': () => createManualSnapshot(),
  'restore-snapshot': (el) => restoreSnapshot(el.dataset.id),
  'toggle-privacy': () => togglePrivacyMode(),
  'tab': (el) => switchTab(el.dataset.tab),
  'switch': (el) => switchAccount(el.dataset.id),
  'remove': (el) => removeAccount(el.dataset.id),
  'retry-connection': () => loadState(),
  'oauth-copy': async () => showToast(await copyText(OAuth.authUrl) ? 'Copied Google sign-in URL' : 'Could not copy — select the URL manually', false),
  'oauth-cancel': () => stopOAuthWait(),
  'toggle-drawer': (el) => {
    const id = el.dataset.id;
    if (UI.expandedModels.has(id)) UI.expandedModels.delete(id); else UI.expandedModels.add(id);
    renderAccountsTable();
  },
  'toggle-windows': (el) => {
    const id = el.dataset.id;
    if (UI.expandedWindows.has(id)) UI.expandedWindows.delete(id); else UI.expandedWindows.add(id);
    renderAccountsTable();
  },
};

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (el && !el.disabled && ACTIONS[el.dataset.action]) {
    ACTIONS[el.dataset.action](el, e);
    return;
  }
  // Click on the dimmed backdrop (not inside the dialog) closes the modal
  if (Modal.current && e.target === Modal.current) Modal.close();
});

document.addEventListener('change', (e) => {
  const t = e.target;
  if (t.dataset.selectId) {
    if (t.checked) UI.selected.add(t.dataset.selectId); else UI.selected.delete(t.dataset.selectId);
    renderBulkBar();
  } else if (t.id === 'selectAll') {
    UI.selected = t.checked ? new Set((STATE.accounts || []).map(a => a.id)) : new Set();
    renderAccountsTable();
  } else if ('setting' in t.dataset) {
    saveSettings();
  }
});

document.addEventListener('keydown', (e) => {
  Modal.handleKey(e);
  // Arrow-key navigation between tabs (WAI-ARIA tabs pattern)
  if (e.target.getAttribute && e.target.getAttribute('role') === 'tab' && (e.key === 'ArrowRight' || e.key === 'ArrowLeft')) {
    const order = ['accounts', 'workspaces', 'snapshots'];
    const i = order.indexOf(e.target.dataset.tab);
    switchTab(order[(i + (e.key === 'ArrowRight' ? 1 : order.length - 1)) % order.length], true);
    e.preventDefault();
  }
  if (e.key === 'Enter' && e.target.id === 'importTokenInput') submitImportToken();
});

/* ---------- Auto-refresh loop (in place, no page reload) ---------- */
let pollTimer = null;
let lastFullState = 0;

function schedulePoll(delay) {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(pollTick, delay);
}

async function pollTick() {
  pollTimer = null;
  if (!document.hidden) {
    if (!UI.connected || !UI.loadedOnce || Date.now() - lastFullState > FULL_STATE_EVERY_MS) {
      if (await loadState()) lastFullState = Date.now();
    } else {
      await loadAccounts();
    }
  }
  const busy = UI.refreshingAll || UI.pending.size > 0 || (STATE.hub || {}).refreshingAll ||
    (STATE.accounts || []).some(a => a.syncing);
  schedulePoll(busy ? FAST_POLL_MS : (UI.connected ? SLOW_POLL_MS : 4000));
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) schedulePoll(0); });
// Keep relative times, countdowns and age-based "stale" flags current between fetches
setInterval(() => { updateDynamicTimes(); renderAccountsTable(); }, 20000);

renderHeader();
pollTick();
