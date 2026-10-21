const GROUP_WINDOW_MS = 5 * 60 * 1000; // collapse identical alerts within 5 minutes
const EXPLAIN_COOLDOWN_MS = 12000; // client-side cooldown after clicking Explain
const CURRENT_LOG_LIMIT = 7;
const OLDER_LOG_LIMIT = 50;
const COUNT_FORMATTER = new Intl.NumberFormat();
const HOUR_MS = 60 * 60 * 1000;
const CONTEXT_LINE_CHOICES = [10, 25, 50];
const PIPELINE_REFRESH_MS = 30000; // while the Pipeline tab is open
const BACKGROUND_STATUS_REFRESH_MS = 5 * 60 * 1000; // header / badge otherwise
const STATUS_STALE_MS = 90000; // status older than this is labelled as stale
const LOG_PANELS_DEBOUNCE_MS = 300; // field sidebar + histogram refresh after filter changes
const FIELD_EXCLUDE_MAX = 50; // values excluded per field (the server's limit)
// Filter fields with their exclusion parameter (API and URL): values listed
// there are left out, e.g. xns=kube-system,monitoring.
const FILTER_EXCLUDES = [
  ['scope', 'xscope'],
  ['namespace', 'xns'],
  ['pod', 'xpod'],
  ['container', 'xctr'],
  ['severity_bucket', 'xsev'],
];

const state = {
  filters: { scope: '', namespace: '', pod: '', container: '', severity_bucket: '', q: '', start: '', end: '' },
  facets: {},
  // Values left out per filter field (Alt/Shift-click in the field sidebar).
  exclude: { scope: [], namespace: [], pod: [], container: [], severity_bucket: [] },
  // Field sidebar + histogram above the log list.
  logPanels: {
    timer: null,
    abort: null, // AbortController of the in-flight refresh
    stale: false, // filters changed while the Logs tab was hidden
    histogram: null, // last /api/histogram response
    prevRange: null, // range before the first histogram zoom (for "Reset range")
    drag: null, // { from, to } bucket indexes while selecting
  },
  dashboard: {
    data: null,
    loading: false,
    error: '',
    loaded: false,
    requestId: 0,
  },
  items: [],
  nextCursor: null,
  hasMore: false,
  olderItems: [],
  olderCursor: null,
  olderHasMore: false,
  olderLoading: false,
  olderRequestId: 0,
  olderOverlayOpen: false,
  // Row id (ingest order) the live tail continues from; set by every reload.
  liveCursor: null,
  liveTimer: null,
  // True while the range ends "now" (Today, Last N, All time). Such a range
  // is sent without an end, so new rows keep matching; editing the End field
  // or picking a fixed day makes the end explicit.
  endIsLive: true,
  lastUpdatedAt: null,
  lastStatus: null,
  expandedRows: new Set(),
  expandedGroups: new Set(),
  groupByRule: false,
  aiConfigured: false,
  // Server capability from /api/status; the server enforces it (403) regardless.
  actionsEnabled: false,
  explainCooldownUntil: 0,
  anomalies: [],
  insightsLoaded: false,
  insightsLoading: false,
  insightsRequestId: 0,
  logsRequestId: 0,
  tailRequestId: 0,
  expandedAnomalies: new Set(),
  activeTab: 'logs',
  lineExplainState: new Map(), // rowId -> { status: 'idle'|'loading'|'done'|'error', summary, action, error }
  actionable: {
    sourceType: 'logs', // 'logs' | 'anomaly' | 'line'
    anomalyId: null,
    plan: null,
    // Keys are "plan:<i>" (suggested steps) or "check:<i>" (evidence checks):
    // { status, stdout, stderr, exit_code, duration_ms, error, output_truncated, ran_at }
    stepStates: new Map(),
    runningIndex: null, // key of the step being validated or executed; one at a time
    pendingMutation: null, // { key, structured, command, confirm_token } awaiting confirmation
    checks: [], // registered read-only evidence checks for the investigation's target
    validation: new Map(), // JSON(structured action) -> { status, command, error }
  },
  // Exact [start, before) bounds (ISO, UTC) set by a shared link or a
  // dashboard drilldown; the minute-precision inputs only display them.
  // Cleared as soon as the range is edited.
  rangeExact: null,
  context: { recordId: null, lines: 10, limitToRange: true, data: null, loading: false, error: '', requestId: 0, scrolled: false },
  pipeline: { fetchedAt: null, error: '', loading: false, requestId: 0, timer: null, backgroundTimer: null },
  focusAnomalyId: null,
  // Saved views (/api/views). currentId: the open view (URL view=<id>).
  views: {
    list: [],
    loaded: false,
    error: '',
    currentId: null,
    search: '',
    busy: false,
    dialog: null, // { mode: 'save' | 'edit', viewId }
    counts: new Map(), // id -> { total, errors } | { error } (dashboard strip, last hour)
    countsAt: 0,
    countsRequestId: 0,
  },
  urlApplying: false,
  insightsPromise: null,
};

const el = (id) => document.getElementById(id);

function formatCount(value) {
  const number = Number(value ?? 0);
  return COUNT_FORMATTER.format(Number.isFinite(number) ? number : 0);
}

function dashboardLabel(value) {
  return value ? String(value) : '—';
}

function dashboardContextText() {
  const parts = [];
  const filters = queryFromFilters();
  if (filters.scope) parts.push(`scope=${filters.scope}`);
  if (filters.namespace) parts.push(`namespace=${filters.namespace}`);
  if (filters.pod) parts.push(`pod=${filters.pod}`);
  if (filters.container) parts.push(`container=${filters.container}`);
  if (filters.severity_bucket) parts.push(`severity=${filters.severity_bucket}`);
  if (filters.q) parts.push(`search=${filters.q}`);
  if (FILTER_EXCLUDES.some(([, param]) => filters[param])) parts.push('exclusions applied');
  if (filters.start || filters.before) parts.push('time range applied');
  return parts.length ? `Overview for ${parts.join(', ')}` : 'Overview for the current filter set';
}

// ─── Tab switching ───────────────────────────────────────────────────────────

const TABS = ['dashboard', 'logs', 'insights', 'actionable', 'pipeline'];
const TAB_IDS = {
  dashboard: ['tabDashboard', 'panelDashboard'],
  logs: ['tabLogs', 'panelLogs'],
  insights: ['tabInsights', 'panelInsights'],
  actionable: ['tabActionable', 'panelActionable'],
  pipeline: ['tabPipeline', 'panelPipeline'],
};

// history: 'push' for a user navigation, 'replace' to update the current
// entry, null when the URL is being applied (initial load, back/forward).
function switchTab(name, { history = 'push' } = {}) {
  if (!TABS.includes(name)) name = 'logs';
  state.activeTab = name;
  for (const tab of TABS) {
    const [tabId, panelId] = TAB_IDS[tab];
    const active = tab === name;
    el(tabId).classList.toggle('active', active);
    el(tabId).setAttribute('aria-selected', active ? 'true' : 'false');
    el(panelId).hidden = !active;
  }

  // The dashboard only loads when it is shown and its data is out of date
  // (filters changed since the last load); switching tabs alone never reloads it.
  if (name === 'dashboard' && !state.dashboard.loaded && !state.dashboard.loading) {
    loadDashboard().catch(() => {});
  }
  if (name === 'dashboard') loadPinnedCounts();
  if (name === 'insights' && !state.insightsLoaded && !state.insightsLoading) {
    loadInsights().catch(() => {});
  }
  if (name === 'logs' && state.logPanels.stale) scheduleLogPanels();
  if (name === 'actionable') {
    updateActionableSourceOptions();
    renderActionableWorkspace();
  }
  if (name === 'pipeline') {
    startPipelinePolling();
  } else {
    stopPipelinePolling();
  }
  updateUrl(history);
}

for (const tab of TABS) {
  el(TAB_IDS[tab][0]).addEventListener('click', () => switchTab(tab));
}

// ─── Date helpers ────────────────────────────────────────────────────────────

function localDateParts(date = new Date()) {
  const pad = (value) => String(value).padStart(2, '0');
  return {
    year: date.getFullYear(),
    month: pad(date.getMonth() + 1),
    day: pad(date.getDate()),
    hour: pad(date.getHours()),
    minute: pad(date.getMinutes()),
  };
}

function setDefaultDateRange() {
  const now = new Date();
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  const startParts = localDateParts(start);
  const endParts = localDateParts(now);
  el('start').value = `${startParts.year}-${startParts.month}-${startParts.day}T00:00`;
  el('end').value = `${endParts.year}-${endParts.month}-${endParts.day}T${endParts.hour}:${endParts.minute}`;
  el('defaultWindowChip').textContent = `Today · ${start.toLocaleDateString()}`;
  state.endIsLive = true;
  state.rangeExact = null;
}

// An explicit [startIso, beforeIso) range, kept exactly (the inputs show it
// to the minute). Either bound may be empty; no end keeps the range open.
function setExactRange(startIso, beforeIso) {
  state.rangeExact = { start: startIso || '', before: beforeIso || '' };
  el('start').value = startIso ? toDatetimeLocal(new Date(startIso)) : '';
  el('end').value = toDatetimeLocal(beforeIso ? new Date(beforeIso) : new Date());
  state.endIsLive = !beforeIso;
  el('rangePreset').value = 'custom';
}

// The time bounds sent to the API: entries with start <= timestamp < before.
function currentRange() {
  if (state.rangeExact) return { start: state.rangeExact.start, before: state.rangeExact.before };
  return {
    start: localValueToIso(el('start').value),
    before: state.endIsLive ? '' : localValueToIso(el('end').value),
  };
}

// For an open-ended range the End field shows the current time; refresh it
// so the form matches what is being queried.
function refreshLiveEnd() {
  if (state.endIsLive && el('end').value) el('end').value = toDatetimeLocal(new Date());
}

function localValueToIso(value) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : '';
}

function formatTimestamp(value) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value));
}

function fmtFreshness(value) {
  if (!value) return 'Waiting for ingestion';
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ago`;
}

// Exclusions as API parameters, comma-separated (Kubernetes names, scopes
// and severities never contain commas).
function excludeParams() {
  const out = {};
  for (const [field, param] of FILTER_EXCLUDES) {
    if (state.exclude[field].length) out[param] = state.exclude[field].join(',');
  }
  return out;
}

function queryFromFilters(extra = {}) {
  const range = currentRange();
  const current = {
    scope: el('scope').value,
    namespace: el('namespace').value,
    pod: el('pod').value,
    container: el('container').value,
    severity_bucket: el('severity_bucket').value,
    q: el('q').value.trim(),
    start: range.start,
    // Exclusive end: the API's "before" (entries strictly earlier).
    before: range.before,
    ...excludeParams(),
    ...extra,
  };
  return Object.fromEntries(Object.entries(current).filter(([, v]) => v));
}

async function fetchJson(url, options = {}) {
  let res;
  try {
    res = await fetch(url, options);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Network error: ${msg}`);
  }

  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (data && typeof data.error === 'string' && data.error) {
        msg = data.error;
      } else if (data && typeof data.message === 'string' && data.message) {
        msg = data.message;
      }
    } catch (_) {}
    throw new Error(msg);
  }

  return res.json();
}

function optionList(items) {
  return ['<option value="">All</option>'].concat(items.map((item) => {
    const value = escapeHtml(item.value ?? '');
    const count = Number(item.count ?? 0);
    const safeCount = Number.isFinite(count) ? count : 0;
    return `<option value="${value}">${value} (${safeCount})</option>`;
  })).join('');
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function dashboardStateEls() {
  return {
    loading: el('dashboardLoading'),
    error: el('dashboardError'),
    empty: el('dashboardEmpty'),
    content: el('dashboardContent'),
  };
}

function dashboardChartRow(item, kind, maxCount) {
  const value = item.value ?? '';
  const count = Number(item.count ?? 0);
  const width = maxCount > 0 ? Math.max(4, Math.round((count / maxCount) * 100)) : 0;
  const clickable = value !== '' || kind === 'severity' || kind === 'security';
  const action = kind === 'severity' ? 'severity' : kind === 'namespace' ? 'namespace' : kind === 'search' ? 'search' : kind;
  const actionValue = kind === 'security' ? 'security' : value;
  const cls = clickable ? 'dashboard-bar-row dashboard-action' : 'dashboard-bar-row';
  return `
    <button type="button" class="${cls}" data-dashboard-action="${escapeHtml(action)}" data-dashboard-value="${escapeHtml(actionValue)}" ${clickable ? '' : 'disabled'}>
      <span class="dashboard-bar-label">${escapeHtml(dashboardLabel(value))}</span>
      <span class="dashboard-bar-track"><span class="dashboard-bar-fill" style="width:${width}%"></span></span>
      <span class="dashboard-bar-count">${formatCount(count)}</span>
    </button>
  `;
}

// One hourly bucket. Clicking opens Logs for exactly that hour, as the
// half-open interval [hour, hour + 1h) in UTC, keeping the other filters
// (and the severity of the error chart). Empty buckets are not clickable.
function dashboardTimelineRow(item, maxCount, severity, metricKey = 'total_logs') {
  const bucketStart = item.timestamp ? new Date(item.timestamp) : null;
  const valid = Boolean(bucketStart) && Number.isFinite(bucketStart.getTime());
  const label = valid ? formatTimestamp(item.timestamp) : '—';
  const count = Number(item[metricKey] ?? 0);
  const width = maxCount > 0 ? Math.max(4, Math.round((count / maxCount) * 100)) : 0;
  const startIso = valid ? bucketStart.toISOString() : '';
  const endIso = valid ? new Date(bucketStart.getTime() + HOUR_MS).toISOString() : '';
  const clickable = valid && count > 0;
  const title = valid
    ? `${startIso.slice(0, 16).replace('T', ' ')} – ${endIso.slice(11, 16)} UTC (end exclusive)${clickable ? ' · open these logs' : ' · no entries in this hour'}`
    : 'Unknown time bucket';
  return `
    <button type="button" class="dashboard-bar-row${clickable ? ' dashboard-action' : ''}" title="${escapeHtml(title)}" data-dashboard-action="hour" data-dashboard-value="${escapeHtml(startIso)}" data-dashboard-severity="${escapeHtml(severity)}" ${clickable ? '' : 'disabled'}>
      <span class="dashboard-bar-label dashboard-bar-label-wide">${escapeHtml(label)}</span>
      <span class="dashboard-bar-track dashboard-bar-track-timeline"><span class="dashboard-bar-fill dashboard-bar-fill-alt" style="width:${width}%"></span></span>
      <span class="dashboard-bar-count">${formatCount(count)}</span>
    </button>
  `;
}

function renderDashboardList(container, items, kind) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = '<div class="empty-state dashboard-empty-inline">No data for the selected filters.</div>';
    return;
  }
  const maxCount = Math.max(...items.map((item) => Number(item.count ?? 0)), 1);
  container.innerHTML = items.map((item) => dashboardChartRow(item, kind, maxCount)).join('');
}

function renderDashboardSummary(summary) {
  const cards = [
    { label: 'Total Logs', value: summary.total_logs, action: 'logs' },
    { label: 'Errors', value: summary.error_count, action: 'severity', actionValue: 'error' },
    { label: 'Warnings', value: summary.warning_count, action: 'severity', actionValue: 'warning' },
    { label: 'Info', value: summary.info_count, action: 'severity', actionValue: 'info' },
    { label: 'Security', value: summary.security_count, action: 'security', actionValue: 'security' },
    { label: 'Namespaces', value: summary.unique_namespaces },
    { label: 'Pods', value: summary.unique_pods },
  ];
  const container = el('dashboardSummaryCards');
  if (!container) return;
  container.innerHTML = cards.map((card) => {
    const clickable = Boolean(card.action);
    const tag = clickable ? 'button' : 'div';
    const attrs = clickable
      ? `type="button" class="dashboard-summary-card dashboard-action" data-dashboard-action="${escapeHtml(card.action)}" data-dashboard-value="${escapeHtml(card.actionValue || '')}"`
      : 'class="dashboard-summary-card"';
    return `<${tag} ${attrs}><span class="dashboard-summary-label">${escapeHtml(card.label)}</span><span class="dashboard-summary-value">${formatCount(card.value)}</span></${tag}>`;
  }).join('');
}

function renderDashboardContent(data) {
  const summary = data.summary || {};
  renderDashboardSummary(summary);
  renderDashboardList(el('dashboardSeverityChart'), data.severity || [], 'severity');
  renderDashboardList(el('dashboardNamespaceChart'), data.namespaces || [], 'namespace');
  renderDashboardList(el('dashboardTopErrors'), data.top_errors || [], 'search');
  renderDashboardList(el('dashboardErrorNamespaces'), data.error_namespaces || [], 'namespace');
  renderDashboardList(el('dashboardErrorPods'), data.error_pods || [], 'pod');

  const totalTimeline = el('dashboardTotalVolumeChart');
  if (totalTimeline) {
    const items = Array.isArray(data.timeline) ? data.timeline : [];
    if (!items.length) {
      totalTimeline.innerHTML = '<div class="empty-state dashboard-empty-inline">No timeline data available.</div>';
    } else {
      const maxCount = Math.max(...items.map((item) => Number(item.total_logs ?? 0)), 1);
      totalTimeline.innerHTML = items.map((item) => dashboardTimelineRow(item, maxCount, '', 'total_logs')).join('');
    }
  }

  const errorTimeline = el('dashboardErrorVolumeChart');
  if (errorTimeline) {
    const items = Array.isArray(data.timeline) ? data.timeline : [];
    if (!items.length) {
      errorTimeline.innerHTML = '<div class="empty-state dashboard-empty-inline">No timeline data available.</div>';
    } else {
      const maxCount = Math.max(...items.map((item) => Number(item.error_logs ?? 0)), 1);
      errorTimeline.innerHTML = items.map((item) => dashboardTimelineRow(item, maxCount, 'error', 'error_logs')).join('');
    }
  }
}

function renderDashboard() {
  const { loading, error, empty, content } = dashboardStateEls();
  const hasData = Boolean(state.dashboard.data);
  const totalLogs = Number(state.dashboard.data?.summary?.total_logs ?? 0);
  if (loading) loading.hidden = !state.dashboard.loading;
  if (error) {
    error.hidden = !state.dashboard.error;
    error.textContent = state.dashboard.error || '';
  }
  if (empty) empty.hidden = !(hasData && !state.dashboard.loading && !state.dashboard.error && totalLogs === 0);
  if (content) content.hidden = !hasData || state.dashboard.loading || totalLogs === 0;
  if (hasData) renderDashboardContent(state.dashboard.data);
  const ctx = el('dashboardContext');
  if (ctx) ctx.textContent = dashboardContextText();
}

async function drillDownFromDashboard(action, value, severity = '') {
  if (action === 'logs') {
    closeContext({ history: null });
    switchTab('logs');
    return;
  }
  if (action === 'hour') {
    const start = new Date(value);
    if (!Number.isFinite(start.getTime())) return;
    forgetHistogramZoom();
    setExactRange(start.toISOString(), new Date(start.getTime() + HOUR_MS).toISOString());
    if (severity) setSelectValue(el('severity_bucket'), severity);
  } else if (action === 'severity') {
    el('severity_bucket').value = value;
  } else if (action === 'namespace') {
    el('namespace').value = value;
  } else if (action === 'pod') {
    el('pod').value = value;
  } else if (action === 'security') {
    el('scope').value = 'security';
  } else if (action === 'search') {
    el('q').value = value;
  }
  syncFiltersFromUi();
  resetOlderLogsState();
  closeContext({ history: null });
  // One history entry for the whole drilldown (tab + filters + range).
  switchTab('logs', { history: null });
  updateUrl('push');
  await loadLogs(true);
}

async function loadDashboard() {
  const requestKey = JSON.stringify(queryFromFilters());
  if (state.dashboard.loading && state.dashboard.requestKey === requestKey) return;
  state.dashboard.requestKey = requestKey;
  const requestId = ++state.dashboard.requestId;
  state.dashboard.loading = true;
  state.dashboard.error = '';
  renderDashboard();
  try {
    const params = new URLSearchParams(queryFromFilters());
    const data = await fetchJson(`/api/dashboard?${params.toString()}`);
    if (requestId !== state.dashboard.requestId) return;
    state.dashboard.data = data;
    state.dashboard.loaded = true;
  } catch (err) {
    if (requestId !== state.dashboard.requestId) return;
    state.dashboard.error = `Failed to load dashboard: ${err.message}`;
  } finally {
    if (requestId === state.dashboard.requestId) {
      state.dashboard.loading = false;
      renderDashboard();
    }
  }
}

function renderFacets(facets) {
  state.facets = facets;
  el('scope').innerHTML = optionList(facets.scope || []);
  el('namespace').innerHTML = optionList(facets.namespace || []);
  el('severity_bucket').innerHTML = optionList(facets.severity_bucket || []);
  // pod / container use searchable comboboxes; their option lists refresh
  // the next time a combobox opens.
}

const RANGE_PRESETS = {
  today: { label: 'Today', apply: setDefaultDateRange },
  '1h': { label: 'Last hour', apply: () => applyRelativeWindow(60 * 60 * 1000) },
  '6h': { label: 'Last 6 hours', apply: () => applyRelativeWindow(6 * 60 * 60 * 1000) },
  '24h': { label: 'Last 24 hours', apply: () => applyRelativeWindow(24 * 60 * 60 * 1000) },
  '7d': { label: 'Last 7 days', apply: () => applyRelativeWindow(7 * 24 * 60 * 60 * 1000) },
  all: { label: 'All time', apply: () => { el('start').value = ''; el('end').value = ''; state.endIsLive = true; state.rangeExact = null; } },
};

function applyRelativeWindow(spanMs) {
  const now = new Date();
  const start = new Date(now.getTime() - spanMs);
  el('start').value = toDatetimeLocal(start);
  el('end').value = toDatetimeLocal(now);
  state.endIsLive = true;
  state.rangeExact = null;
}

function toDatetimeLocal(date) {
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function buildCombobox(inputId, facetKey) {
  const input = el(inputId);
  const wrapper = document.createElement('div');
  wrapper.className = 'combobox';
  input.parentNode.insertBefore(wrapper, input);
  wrapper.appendChild(input);
  const list = document.createElement('div');
  list.className = 'combobox-list';
  list.id = `${inputId}-list`;
  wrapper.appendChild(list);

  const close = () => { list.classList.remove('open'); };

  const renderList = () => {
    const needle = input.value.trim().toLowerCase();
    const values = (state.facets[facetKey] || [])
      .filter((item) => !needle || String(item.value).toLowerCase().includes(needle))
      .slice(0, 200);
    const parts = ['<button type="button" class="combobox-option" data-value="">All</button>'];
    for (const item of values) {
      const selected = item.value === input.value ? ' selected' : '';
      const value = escapeHtml(item.value ?? '');
      const count = Number(item.count ?? 0);
      const safeCount = Number.isFinite(count) ? String(count) : '0';
      parts.push(`<button type="button" class="combobox-option${selected}" data-value="${value}">${value} <span class="combobox-count">${safeCount}</span></button>`);
    }
    if (!values.length) parts.push('<div class="combobox-empty">No matches</div>');
    list.innerHTML = parts.join('');
  };

  const open = () => {
    renderList();
    list.classList.add('open');
  };

  input.addEventListener('focus', open);
  input.addEventListener('input', open);
  input.addEventListener('blur', () => window.setTimeout(close, 150));
  list.addEventListener('mousedown', (event) => {
    const option = event.target.closest('.combobox-option');
    if (!option) return;
    event.preventDefault();
    input.value = option.dataset.value || '';
    close();
    reloadLogs();
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') { event.preventDefault(); close(); input.blur(); }
    else if (event.key === 'Escape') { close(); }
  });
}

// ─── Logs row rendering ──────────────────────────────────────────────────────

// Normalize a Falco message to its rule-level text: the embedded per-event
// timestamp ("15:50:11.473402755: ") and the trailing field dump (" | k=v …")
// are stripped so repeated hits of the same rule collapse together.
function ruleKeyOf(item) {
  let message = String(item.message || '');
  message = message.replace(/\b\d{2}:\d{2}:\d{2}\.\d+:\s*/g, '');
  const detailIndex = message.indexOf(' | ');
  if (detailIndex > 0 && message.slice(detailIndex).includes('=')) {
    message = message.slice(0, detailIndex);
  }
  return message;
}

function groupKeyOf(item) {
  const message = ruleKeyOf(item);
  return [item.severity_bucket, item.namespace, item.pod, item.container, message].join('|');
}

function buildGroups(items) {
  const groups = [];
  const byKey = new Map();
  for (const item of items) {
    const key = groupKeyOf(item);
    const ts = Date.parse(item.timestamp) || 0;
    let group = byKey.get(key);
    if (group && !state.groupByRule && Math.abs(ts - group.lastTs) > GROUP_WINDOW_MS) {
      group = null;
    }
    if (!group) {
      group = { items: [], lastTs: ts };
      byKey.set(key, group);
      groups.push(group);
    }
    group.items.push(item);
    if (!state.groupByRule) group.lastTs = ts;
  }
  return groups;
}

function rowMarkup(item) {
  const tpl = el('rowTemplate');
  const node = tpl.content.firstElementChild.cloneNode(true);
  node.querySelector('.time').textContent = formatTimestamp(item.timestamp);
  node.title = item.timestamp;
  const sev = node.querySelector('.severity');
  sev.classList.add(item.severity_bucket);
  const badge = node.querySelector('.badge');
  badge.textContent = item.severity_bucket;
  badge.dataset.scope = item.scope;
  node.querySelector('.scope').textContent = item.scope;
  node.querySelector('.source').textContent = `${item.namespace} · ${item.pod}/${item.container}`;
  const messageButton = node.querySelector('.message-button');
  messageButton.textContent = item.message;
  messageButton.title = 'Click row to expand full details';
  if (state.aiConfigured) {
    const explainBlock = lineExplainMarkup(String(item.id), item);
    node.appendChild(explainBlock);
  }
  return node;
}

function addDetailBlock(wrap, label, text) {
  const block = document.createElement('div');
  block.className = 'detail-block';
  const labelNode = document.createElement('div');
  labelNode.className = 'detail-label';
  labelNode.textContent = label;
  const pre = document.createElement('pre');
  pre.className = 'detail-pre';
  pre.textContent = text;
  block.appendChild(labelNode);
  block.appendChild(pre);
  wrap.appendChild(block);
}

// ─── Per-line "Explain this log" ─────────────────────────────────────────────

function lineExplainMarkup(rowId, item) {
  const box = document.createElement('div');
  box.className = 'line-explain-row';

  const lineState = state.lineExplainState.get(rowId) || { status: 'idle' };

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'ghost line-explain-btn';
  btn.textContent = lineState.status === 'loading' ? '✦ Explaining…' : '✦ Explain this line';
  btn.disabled = lineState.status === 'loading';
  btn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (lineState.status === 'loading') return;
    explainLine(rowId, item);
  });
  box.appendChild(btn);

  if (lineState.status === 'done') {
    const result = document.createElement('div');
    result.className = 'line-explain-result';
    const summary = document.createElement('div');
    summary.className = 'line-explain-summary';
    summary.textContent = lineState.summary;
    result.appendChild(summary);
    if (lineState.action) {
      const action = document.createElement('div');
      action.className = 'line-explain-action';
      action.textContent = `→ ${lineState.action}`;
      result.appendChild(action);
    }
    if (lineState.steps && lineState.steps.length) {
      const tBtn = document.createElement('button');
      tBtn.type = 'button';
      tBtn.className = 'ghost line-explain-btn';
      tBtn.style.marginTop = '6px';
      tBtn.textContent = '⚡ Troubleshoot in Actionable';
      tBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        setPlanFromExplainResult(lineState.rawResult, 'line', null, item);
        switchTab('actionable');
      });
      result.appendChild(tBtn);
    }
    box.appendChild(result);
  } else if (lineState.status === 'error') {
    const errNode = document.createElement('div');
    errNode.className = 'line-explain-result line-explain-error-text';
    errNode.textContent = lineState.error;
    box.appendChild(errNode);
  }

  return box;
}

async function explainLine(rowId, item) {
  if (!state.aiConfigured) return;
  state.lineExplainState.set(rowId, { status: 'loading' });
  renderAll();
  try {
    const result = await fetchJson('/api/explain-line', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: item.id }),
    });
    if (result.error) {
      state.lineExplainState.set(rowId, { status: 'error', error: result.error });
    } else {
      state.lineExplainState.set(rowId, {
        status: 'done',
        summary: result.summary || 'No explanation returned.',
        action: result.suggested_action || '',
        steps: result.steps || [],
        rawResult: result,
      });
    }
  } catch (err) {
    state.lineExplainState.set(rowId, { status: 'error', error: err.message });
  }
  renderAll();
  if (state.context.recordId !== null) renderContext();
}

// Expandable detail: full (untruncated) message, raw_line, source_key,
// line_number, output_fields when present, and a per-line Explain action.
function detailMarkup(item, rowId, { inContext = false } = {}) {
  const wrap = document.createElement('div');
  wrap.className = 'row-detail';
  const tools = document.createElement('div');
  tools.className = 'row-detail-tools';
  if (!inContext || Number(item.id) !== state.context.recordId) {
    const contextBtn = document.createElement('button');
    contextBtn.type = 'button';
    contextBtn.className = 'ghost row-detail-btn';
    contextBtn.textContent = 'Show context';
    contextBtn.title = 'Entries just before and after this one from the same pod and container';
    contextBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openContext(Number(item.id));
    });
    tools.appendChild(contextBtn);
  }
  const investigateBtn = document.createElement('button');
  investigateBtn.type = 'button';
  investigateBtn.className = 'ghost row-detail-btn';
  investigateBtn.textContent = 'Investigate in Actionable';
  investigateBtn.title = 'Open the troubleshooting workspace for this pod (logs, describe, events)';
  investigateBtn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    openLineInActionable(item);
  });
  tools.appendChild(investigateBtn);
  wrap.appendChild(tools);
  addDetailBlock(wrap, 'Full message', item.message);
  if (item.raw_line) addDetailBlock(wrap, 'raw_line', item.raw_line);
  addDetailBlock(wrap, 'source_key', item.source_key);
  addDetailBlock(wrap, 'line_number', String(item.line_number));
  if (item.output_fields && Object.keys(item.output_fields).length) {
    addDetailBlock(wrap, 'output_fields', JSON.stringify(item.output_fields, null, 2));
  }
  return wrap;
}

function timestampsMarkup(group) {
  const wrap = document.createElement('div');
  wrap.className = 'row-detail group-timestamps';
  const label = document.createElement('div');
  label.className = 'detail-label';
  label.textContent = `${group.items.length} occurrences`;
  wrap.appendChild(label);
  for (const item of group.items) {
    const line = document.createElement('div');
    line.className = 'timestamp-line';
    line.textContent = formatTimestamp(item.timestamp);
    line.title = item.timestamp;
    wrap.appendChild(line);
  }
  return wrap;
}

function renderRows(items, append = false) {
  const rows = el('rows');
  if (!append) rows.innerHTML = '';
  if (!append && !items.length) {
    const latestCached = state.lastStatus?.latest_record_timestamp;
    const latestHint = latestCached
      ? ` Latest cached logs reach ${formatTimestamp(latestCached)}.`
      : '';
    rows.innerHTML = `<div class="empty-state">No logs found for the current filters.${latestHint} <button id="loadLatestCached" class="ghost empty-action">Load latest cached day</button></div>`;
    el('resultSummary').textContent = 'No rows match';
    return;
  }
  let collapsed = 0;
  const visible = items.slice(0, CURRENT_LOG_LIMIT);
  for (const group of buildGroups(visible)) {
    const representative = group.items[0];
    collapsed += group.items.length - 1;
    const node = rowMarkup(representative);
    const rowId = String(representative.id);
    node.dataset.rowId = rowId;
    if (group.items.length > 1) {
      const badge = node.querySelector('.badge');
      const count = document.createElement('span');
      count.className = 'count-badge';
      count.textContent = `×${group.items.length}`;
      count.title = `${group.items.length} identical alerts — click row to show individual timestamps`;
      badge.after(count);
      node.classList.add('grouped');
      node.dataset.groupKey = groupKeyOf(representative);
      if (state.expandedGroups.has(node.dataset.groupKey)) {
        node.classList.add('expanded');
        node.appendChild(timestampsMarkup(group));
      }
    }
    if (state.expandedRows.has(rowId)) {
      node.classList.add('expanded');
      node.appendChild(detailMarkup(representative, rowId));
    }
    node.addEventListener('click', () => {
      if (group.items.length > 1) {
        const key = node.dataset.groupKey;
        if (state.expandedRows.has(rowId)) {
          state.expandedRows.delete(rowId);
        }
        if (state.expandedGroups.has(key)) {
          state.expandedGroups.delete(key);
        } else {
          state.expandedGroups.add(key);
        }
      } else if (state.expandedRows.has(rowId)) {
        state.expandedRows.delete(rowId);
      } else {
        state.expandedRows.add(rowId);
      }
      renderAll();
    });
    rows.appendChild(node);
  }
  const total = append ? state.items.length : visible.length;
  const groupedNote = collapsed > 0 ? ` · ${collapsed} collapsed` : '';
  el('resultSummary').textContent = `${total} visible lines${groupedNote}`;
}

function renderAll() {
  renderRows(state.items, false);
}

// ─── Log context (entries around one selected entry) ─────────────────────────

async function openContext(recordId, { history = 'push' } = {}) {
  if (!Number.isSafeInteger(recordId) || recordId < 0) return;
  closeOlderLogsOverlay();
  const ctx = state.context;
  ctx.recordId = recordId;
  ctx.data = null;
  ctx.error = '';
  ctx.loading = true;
  ctx.scrolled = false;
  const requestId = ++ctx.requestId;
  renderContext();
  updateUrl(history);
  const params = new URLSearchParams({
    id: String(recordId), lines_before: String(ctx.lines), lines_after: String(ctx.lines),
  });
  if (ctx.limitToRange) {
    const range = currentRange();
    if (range.start) params.set('start', range.start);
    if (range.before) params.set('before', range.before);
  }
  try {
    const data = await fetchJson(`/api/logs/context?${params.toString()}`);
    if (requestId !== ctx.requestId) return;
    ctx.data = data;
  } catch (err) {
    if (requestId !== ctx.requestId) return;
    ctx.error = err.message;
  } finally {
    if (requestId === ctx.requestId) {
      ctx.loading = false;
      renderContext();
    }
  }
}

function closeContext({ history = 'push' } = {}) {
  const ctx = state.context;
  const wasOpen = ctx.recordId !== null;
  ctx.recordId = null;
  ctx.data = null;
  ctx.error = '';
  ctx.loading = false;
  ctx.requestId += 1;
  renderContext();
  if (wasOpen) updateUrl(history);
}

function contextBoundText(side, bounds, anchor) {
  if (!bounds) return '';
  const value = side === 'before' ? bounds.from : bounds.to;
  const fromRange = side === 'before' ? bounds.from_is_range : bounds.to_is_range;
  if (!value) return '';
  if (fromRange) {
    return side === 'before'
      ? `the active time range starts at ${formatTimestamp(value)}`
      : `the active time range ends at ${formatTimestamp(value)}`;
  }
  if (bounds.window_secs) {
    const hours = Math.round(bounds.window_secs / 3600);
    return `only ${hours}h ${side === 'before' ? 'before' : 'after'} the selected entry were searched`;
  }
  return '';
}

function contextMarker(text, { action = null, tone = '' } = {}) {
  const box = document.createElement('div');
  box.className = `context-marker${tone ? ` context-marker-${tone}` : ''}`;
  const span = document.createElement('span');
  span.textContent = text;
  box.appendChild(span);
  if (action) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ghost context-more-btn';
    btn.textContent = action.label;
    btn.addEventListener('click', action.run);
    box.appendChild(btn);
  }
  return box;
}

function contextRow(item, position) {
  const rowId = String(item.id);
  const node = rowMarkup(item);
  node.classList.add('context-row', `context-${position}`);
  node.dataset.rowId = rowId;
  const label = document.createElement('span');
  label.className = 'context-position';
  label.textContent = position === 'selected' ? 'Selected' : position === 'before' ? 'Before' : 'After';
  node.querySelector('.time').prepend(label);
  const expanded = position === 'selected' || state.expandedRows.has(rowId);
  if (expanded) {
    node.classList.add('expanded');
    node.appendChild(detailMarkup(item, rowId, { inContext: true }));
  }
  if (position !== 'selected') {
    node.addEventListener('click', () => {
      if (state.expandedRows.has(rowId)) state.expandedRows.delete(rowId);
      else state.expandedRows.add(rowId);
      renderContext();
    });
  }
  return node;
}

function nextContextLines(current) {
  return CONTEXT_LINE_CHOICES.find((n) => n > current) || null;
}

function renderContext() {
  const ctx = state.context;
  const open = ctx.recordId !== null;
  el('contextView').hidden = !open;
  el('resultsView').hidden = open;
  if (!open) return;
  el('contextLines').value = String(ctx.lines);
  el('contextLimitRange').checked = ctx.limitToRange;
  const list = el('contextList');
  list.innerHTML = '';
  const data = ctx.data;
  el('contextTitle').textContent = data
    ? `Context · ${data.group.namespace} · ${data.group.pod}/${data.group.container}`
    : `Context for log entry #${ctx.recordId}`;
  if (ctx.loading) {
    list.appendChild(contextMarker('Loading context…'));
    return;
  }
  if (ctx.error) {
    list.appendChild(contextMarker(`Context unavailable: ${ctx.error}`, { tone: 'error' }));
    return;
  }
  if (!data) return;

  const more = nextContextLines(ctx.lines);
  const showMore = more ? { label: `Show ${more} per side`, run: () => { ctx.lines = more; openContext(ctx.recordId, { history: 'replace' }); } } : null;

  // Earlier side
  if (data.more_before) {
    list.appendChild(contextMarker(`More earlier entries exist than the ${data.lines_before} shown.`, { action: showMore }));
  } else {
    const bound = contextBoundText('before', data.bounds, data.anchor);
    const what = data.before.length ? 'No further earlier entries' : 'No earlier entries from this pod/container';
    list.appendChild(contextMarker(`${what}${bound ? ` — ${bound}` : ''}.`, { tone: 'muted' }));
  }
  for (const item of data.before) list.appendChild(contextRow(item, 'before'));
  const selected = contextRow(data.anchor, 'selected');
  list.appendChild(selected);
  for (const item of data.after) list.appendChild(contextRow(item, 'after'));
  if (data.more_after) {
    list.appendChild(contextMarker(`More later entries exist than the ${data.lines_after} shown.`, { action: showMore }));
  } else {
    const bound = contextBoundText('after', data.bounds, data.anchor);
    const what = data.after.length ? 'No further later entries' : 'No later entries from this pod/container';
    list.appendChild(contextMarker(`${what}${bound ? ` — ${bound}` : ''}.`, { tone: 'muted' }));
  }

  const range = currentRange();
  const ts = String(data.anchor.timestamp || '');
  const outside = ctx.limitToRange && ((range.start && ts < range.start) || (range.before && ts >= range.before));
  el('contextNote').textContent = outside
    ? 'The selected entry is outside the active time range; untick "Within time range" to see its neighbours.'
    : 'Same namespace, pod and container · severity and search filters are not applied · ordered by event time, then ingest order';

  if (!ctx.scrolled) {
    ctx.scrolled = true;
    selected.scrollIntoView({ block: 'center' });
  }
}

el('contextBack').addEventListener('click', () => closeContext());
el('contextLines').addEventListener('change', () => {
  const lines = Number(el('contextLines').value);
  if (!CONTEXT_LINE_CHOICES.includes(lines) || state.context.recordId === null) return;
  state.context.lines = lines;
  openContext(state.context.recordId, { history: 'replace' });
});
el('contextLimitRange').addEventListener('change', () => {
  if (state.context.recordId === null) return;
  state.context.limitToRange = el('contextLimitRange').checked;
  openContext(state.context.recordId, { history: 'replace' });
});

// ─── Insights tab ────────────────────────────────────────────────────────────

const STATUS_LABELS = { new: 'New', reviewed: 'Reviewed', dismissed: 'Dismissed' };

function anomalyTypeLabel(type) {
  const map = {
    error_rate_spike: 'Error spike',
    message_frequency: 'Frequency spike',
    new_falco_rule: 'New Falco rule',
    severity_shift: 'Severity shift',
  };
  return map[type] || type;
}

function renderAnomalies() {
  const container = el('anomalyRows');
  container.innerHTML = '';
  const { anomalies } = state;
  const emptyEl = el('insightsEmpty');
  emptyEl.textContent = 'No anomalies found for the selected filter.';
  emptyEl.hidden = anomalies.length > 0;
  if (!anomalies.length) return;

  for (const anomaly of anomalies) {
    const tpl = el('anomalyRowTemplate');
    const node = tpl.content.firstElementChild.cloneNode(true);

    node.dataset.anomalyId = String(anomaly.id);

    const typeBadge = node.querySelector('.anomaly-type-badge');
    typeBadge.textContent = anomalyTypeLabel(anomaly.type);
    typeBadge.classList.add(`atype-${anomaly.type}`);

    node.querySelector('.anomaly-namespace').textContent = anomaly.namespace || '—';
    const podText = [anomaly.pod, anomaly.rule_key].filter(Boolean).join(' / ');
    node.querySelector('.anomaly-pod').textContent = podText || '—';

    // Severity badge — FIX: only add a class when severity is non-empty.
    // message_frequency anomalies have severity: "" by design; classList.add('')
    // throws a DOMException and previously crashed the whole render loop,
    // leaving every anomaly after (or including) the first empty-severity one
    // unrendered — the root cause of "badge shows a count but the list is blank".
    const sevBadge = node.querySelector('.badge');
    sevBadge.textContent = anomaly.severity || '—';
    if (anomaly.severity) {
      sevBadge.closest('.anomaly-col-severity').classList.add(anomaly.severity);
    }

    const summaryEl = node.querySelector('.anomaly-summary-text');
    const actionEl = node.querySelector('.anomaly-action-text');
    if (anomaly.ai_summary) {
      summaryEl.textContent = anomaly.ai_summary;
    } else {
      summaryEl.textContent = 'Awaiting AI summary…';
      summaryEl.classList.add('muted');
    }
    if (anomaly.ai_suggested_action) {
      actionEl.textContent = `→ ${anomaly.ai_suggested_action}`;
    } else {
      actionEl.hidden = true;
    }

    const statusBadge = node.querySelector('.anomaly-status-badge');
    statusBadge.textContent = STATUS_LABELS[anomaly.status] || anomaly.status;
    if (anomaly.status) {
      statusBadge.classList.add(`astatus-${anomaly.status}`);
    }

    node.querySelector('.anomaly-time').textContent = anomaly.detected_at
      ? formatTimestamp(anomaly.detected_at)
      : '—';

    const btnTroubleshoot = node.querySelector('.anomaly-btn-troubleshoot');
    const btnReviewed = node.querySelector('.anomaly-btn-reviewed');
    const btnDismissed = node.querySelector('.anomaly-btn-dismissed');
    if (anomaly.status === 'reviewed') {
      btnReviewed.disabled = true;
      btnReviewed.textContent = '✓ Reviewed';
    }
    if (anomaly.status === 'dismissed') {
      btnDismissed.disabled = true;
      btnDismissed.textContent = '✕ Dismissed';
    }
    if (btnTroubleshoot) {
      btnTroubleshoot.addEventListener('click', (ev) => {
        ev.stopPropagation();
        openAnomalyInActionable(anomaly);
      });
    }
    if (state.focusAnomalyId === anomaly.id) node.classList.add('anomaly-focused');
    btnReviewed.addEventListener('click', (ev) => {
      ev.stopPropagation();
      patchAnomalyStatus(anomaly.id, 'reviewed', node);
    });
    btnDismissed.addEventListener('click', (ev) => {
      ev.stopPropagation();
      patchAnomalyStatus(anomaly.id, 'dismissed', node);
    });

    const detail = node.querySelector('.anomaly-detail');
    const expandBtn = node.querySelector('.anomaly-expand-btn');
    const anomalyId = String(anomaly.id);
    if (state.expandedAnomalies.has(anomalyId)) {
      detail.hidden = false;
      expandBtn.textContent = '▴';
      fillAnomalyDetail(detail.querySelector('.anomaly-detail-inner'), anomaly);
    }
    node.querySelector('.anomaly-main').addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      if (state.expandedAnomalies.has(anomalyId)) {
        state.expandedAnomalies.delete(anomalyId);
        detail.hidden = true;
        expandBtn.textContent = '▾';
        if (state.focusAnomalyId === anomaly.id) state.focusAnomalyId = null;
      } else {
        state.expandedAnomalies.add(anomalyId);
        detail.hidden = false;
        expandBtn.textContent = '▴';
        fillAnomalyDetail(detail.querySelector('.anomaly-detail-inner'), anomaly);
        state.focusAnomalyId = anomaly.id;
      }
      updateUrl('replace');
    });

    container.appendChild(node);
  }
}

function fillAnomalyDetail(container, anomaly) {
  container.innerHTML = '';
  const evidence = anomaly.evidence || {};

  const msgs = evidence.sample_messages;
  if (msgs && msgs.length) {
    addDetailBlock(container, `Sample log messages (${msgs.length})`, msgs.join('\n'));
  }

  const evidenceClean = { ...evidence };
  delete evidenceClean.sample_messages;
  delete evidenceClean.ai_error;
  if (Object.keys(evidenceClean).length) {
    addDetailBlock(container, 'Evidence', JSON.stringify(evidenceClean, null, 2));
  }
  if (evidence.ai_error) {
    addDetailBlock(container, 'AI error', evidence.ai_error);
  }
  const windowRange = anomalyWindow(anomaly);
  if (windowRange) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ghost row-detail-btn';
    btn.textContent = 'View logs for this window';
    btn.title = `${windowRange.start} – ${windowRange.before} UTC (end exclusive)`;
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openAnomalyLogs(anomaly);
    });
    container.appendChild(btn);
  }
}

// The hourly window an anomaly was detected in, as [start, before).
function anomalyWindow(anomaly) {
  const ev = anomaly?.evidence || {};
  const start = new Date(ev.window_start || '');
  const end = new Date(ev.window_end || '');
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start) return null;
  return { start: start.toISOString(), before: end.toISOString() };
}

// Logs for an anomaly: its namespace (and pod), the detector's severity or
// security scope, and its detection window. Other filters are cleared so
// the view matches what the detector counted.
function openAnomalyLogs(anomaly) {
  const windowRange = anomalyWindow(anomaly);
  setSelectValue(el('scope'), anomaly.type === 'new_falco_rule' ? 'security' : '');
  setSelectValue(el('namespace'), anomaly.namespace || '');
  el('pod').value = anomaly.pod || '';
  el('container').value = '';
  const severity = anomaly.type === 'error_rate_spike' ? 'error'
    : anomaly.type === 'severity_shift' ? (anomaly.severity || '') : '';
  setSelectValue(el('severity_bucket'), severity);
  el('q').value = '';
  if (windowRange) setExactRange(windowRange.start, windowRange.before);
  syncFiltersFromUi();
  resetOlderLogsState();
  closeContext({ history: null });
  switchTab('logs', { history: null });
  updateUrl('push');
  loadLogs(true);
}

async function patchAnomalyStatus(id, status, rowNode) {
  try {
    await fetchJson(`/api/anomalies/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    const anomaly = state.anomalies.find((a) => a.id === id);
    if (anomaly) anomaly.status = status;
    renderAnomalies();
  } catch (err) {
    el('health').textContent = `Failed to update anomaly: ${err.message}`;
  }
}

function showInsightsError(message) {
  const emptyEl = el('insightsEmpty');
  const container = el('anomalyRows');
  container.innerHTML = '';
  emptyEl.textContent = message;
  emptyEl.hidden = false;
}

// Returns the in-flight load when one is running, so callers can await it.
function loadInsights() {
  if (state.insightsLoading && state.insightsPromise) return state.insightsPromise;
  state.insightsPromise = fetchInsights();
  return state.insightsPromise;
}

async function fetchInsights() {
  const requestId = ++state.insightsRequestId;
  state.insightsLoading = true;
  state.insightsLoaded = false;
  const statusValue = el('insightsStatusFilter').value;
  const params = new URLSearchParams();
  if (statusValue) params.set('status', statusValue);
  params.set('limit', '200');

  try {
    const data = await fetchJson(`/api/anomalies?${params.toString()}`);
    if (requestId !== state.insightsRequestId) return;
    state.anomalies = data.items || [];
    state.insightsLoaded = true;
    const newCount = state.anomalies.filter((a) => a.status === 'new').length;
    const badge = el('insightsBadge');
    if (newCount > 0) {
      badge.textContent = String(newCount);
      badge.hidden = false;
    } else {
      badge.hidden = true;
    }
    renderAnomalies();
  } catch (err) {
    if (requestId !== state.insightsRequestId) return;
    state.anomalies = [];
    const badge = el('insightsBadge');
    badge.hidden = true;
    showInsightsError(`Failed to load anomalies: ${err.message}`);
  } finally {
    if (requestId === state.insightsRequestId) {
      state.insightsLoading = false;
    }
  }
}

// Open one anomaly from a link (?anomaly=<id>): widen the status filter if
// it is not in the current list, then expand, highlight and scroll to it.
async function focusAnomaly(id, { openInActionable = false } = {}) {
  state.focusAnomalyId = id;
  await loadInsights();
  let anomaly = state.anomalies.find((a) => a.id === id);
  if (!anomaly && el('insightsStatusFilter').value !== '') {
    el('insightsStatusFilter').value = '';
    await loadInsights();
    anomaly = state.anomalies.find((a) => a.id === id);
  }
  if (!anomaly) {
    // Keep the list; say why the linked anomaly is not in it.
    renderAnomalies();
    const notice = el('insightsEmpty');
    notice.textContent = `Anomaly #${id} from the link is not among the ${state.anomalies.length} most recent anomalies (it may have been removed).`;
    notice.hidden = false;
    return;
  }
  if (openInActionable) {
    // Already investigating it (e.g. back/forward): keep the collected results.
    if (state.actionable.sourceType === 'anomaly' && state.actionable.plan?.anomaly?.id === id) {
      switchTab('actionable', { history: null });
    } else {
      openAnomalyInActionable(anomaly, { history: null });
    }
    return;
  }
  state.expandedAnomalies.add(String(id));
  renderAnomalies();
  const node = el('anomalyRows').querySelector(`[data-anomaly-id="${id}"]`);
  if (node) {
    node.classList.add('anomaly-focused');
    node.scrollIntoView({ block: 'center' });
  }
}

// ─── Explain these logs (bulk, filtered view) ────────────────────────────────

function updateExplainButton() {
  const btn = el('explainBtn');
  if (!state.aiConfigured) {
    btn.disabled = true;
    btn.title = 'AI provider not configured — set ai.provider in config.yaml';
    return;
  }
  const coolingDown = Date.now() < state.explainCooldownUntil;
  btn.disabled = coolingDown;
  if (coolingDown) {
    const remaining = Math.ceil((state.explainCooldownUntil - Date.now()) / 1000);
    btn.title = `Please wait ${remaining}s before explaining again`;
  } else {
    btn.title = 'Summarize the currently filtered logs with AI';
  }
}

function startExplainCooldown() {
  state.explainCooldownUntil = Date.now() + EXPLAIN_COOLDOWN_MS;
  updateExplainButton();
  window.setTimeout(() => {
    updateExplainButton();
  }, EXPLAIN_COOLDOWN_MS + 50);
}

async function runExplain() {
  if (!state.aiConfigured) return;
  if (Date.now() < state.explainCooldownUntil) return;
  startExplainCooldown();

  const panel = el('explainPanel');
  const summaryEl = el('explainSummary');
  const actionEl = el('explainAction');
  const cachedBadge = el('explainCachedBadge');

  panel.hidden = false;
  summaryEl.textContent = 'Thinking…';
  summaryEl.classList.add('thinking');
  actionEl.hidden = true;
  cachedBadge.hidden = true;

  try {
    const params = new URLSearchParams(queryFromFilters());
    const result = await fetchJson(`/api/explain?${params.toString()}`, { method: 'POST' });
    summaryEl.classList.remove('thinking');
    if (result.error) {
      summaryEl.textContent = `Error: ${result.error}`;
      summaryEl.classList.add('explain-error');
    } else {
      summaryEl.classList.remove('explain-error');
      summaryEl.textContent = result.summary || 'No summary returned.';
      if (result.suggested_action) {
        actionEl.textContent = `→ ${result.suggested_action}`;
        actionEl.hidden = false;
      }
      if (result.cached) {
        cachedBadge.hidden = false;
      }
      setPlanFromExplainResult(result, 'logs');
    }
  } catch (err) {
    summaryEl.classList.remove('thinking');
    summaryEl.textContent = `Failed: ${err.message}`;
    summaryEl.classList.add('explain-error');
  }
}

el('explainBtn').addEventListener('click', () => {
  runExplain().catch((err) => { el('health').textContent = err.message; });
});

el('explainDismiss').addEventListener('click', () => {
  el('explainPanel').hidden = true;
  el('explainSummary').textContent = '';
  el('explainSummary').classList.remove('explain-error', 'thinking');
  el('explainAction').hidden = true;
  el('explainCachedBadge').hidden = true;
});

// ─── Actionable Troubleshooting Workspace ────────────────────────────────────

// Names as the server's validator accepts them; anything else (e.g. "-" for
// a missing pod) is left out instead of producing a doomed command.
const K8S_NAME_RE = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/;
const K8S_NAMESPACE_RE = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const K8S_CONTAINER_RE = /^[A-Za-z0-9_.-]+$/;
const EVIDENCE_LOG_TAIL = 200;

function k8sValue(value, re, maxLength) {
  const text = String(value || '').trim();
  return text && text !== '-' && text.length <= maxLength && re.test(text) ? text : '';
}

// Namespace / pod / container the investigation is about.
function actionableTarget(plan) {
  let source = {};
  if (plan?.anomaly) source = { namespace: plan.anomaly.namespace, pod: plan.anomaly.pod };
  else if (plan?.lineItem) source = plan.lineItem;
  else if (plan?.filters) source = plan.filters;
  return {
    namespace: k8sValue(source.namespace, K8S_NAMESPACE_RE, 63),
    pod: k8sValue(source.pod, K8S_NAME_RE, 253),
    container: k8sValue(source.container, K8S_CONTAINER_RE, 63),
  };
}

// Registered read-only actions for the target. They are offered, never run
// automatically; each still goes through /api/actions/validate and execute.
function buildEvidenceChecks(target) {
  const checks = [];
  const ns = target.namespace;
  if (ns && target.pod) {
    const where = target.container ? `${target.pod}/${target.container}` : target.pod;
    const logs = { action: 'get_pod_logs', namespace: ns, resource: target.pod, tail: EVIDENCE_LOG_TAIL };
    if (target.container) logs.container = target.container;
    checks.push({
      title: 'Recent pod logs',
      explanation: `The last ${EVIDENCE_LOG_TAIL} lines from ${where} straight from the cluster, including lines not yet in the S3 cache.`,
      action: logs,
    });
    checks.push({
      title: 'Logs before the last restart',
      explanation: `Output of the previous ${where} container; fails if it has not restarted.`,
      action: { ...logs, previous: true },
    });
    checks.push({
      title: 'Describe pod',
      explanation: `Status, conditions, restart counts and recent events of ${target.pod}.`,
      action: { action: 'describe_pod', namespace: ns, resource: target.pod },
    });
  }
  if (ns) {
    checks.push({
      title: 'Namespace events',
      explanation: `Recent Kubernetes events in ${ns}, oldest first.`,
      action: { action: 'get_events', namespace: ns },
    });
    checks.push({
      title: 'Pods in namespace',
      explanation: `Status, restarts and nodes of every pod in ${ns}.`,
      action: { action: 'get_pods', namespace: ns, output: 'wide' },
    });
  }
  return checks.map((check) => ({ ...check, command: '', risk: 'read-only', is_supported: true }));
}

function resetInvestigation(plan) {
  state.actionable.plan = plan;
  state.actionable.stepStates.clear();
  state.actionable.pendingMutation = null;
  state.actionable.checks = buildEvidenceChecks(actionableTarget(plan));
  // Results of a step still running for the previous plan are dropped.
  state.actionable.planVersion = (state.actionable.planVersion || 0) + 1;
}

function setPlanFromExplainResult(result, sourceType, anomaly = null, lineItem = null) {
  state.actionable.sourceType = sourceType;
  state.actionable.anomalyId = anomaly ? anomaly.id : null;
  state.actionable.lineItem = lineItem;
  resetInvestigation({
    summary: result.summary || '',
    steps: result.steps || [],
    suggested_action: result.suggested_action || '',
    filters: result.filters || (sourceType === 'logs' ? queryFromFilters() : null),
    sample_count: result.sample_count,
    anomaly: anomaly,
    lineItem: lineItem,
  });
  renderActionableWorkspace();
}

function openAnomalyInActionable(anomaly, { history = 'push' } = {}) {
  state.actionable.sourceType = 'anomaly';
  state.actionable.anomalyId = anomaly.id;
  state.actionable.lineItem = null;
  state.focusAnomalyId = anomaly.id;

  let steps = anomaly.ai_steps || [];
  if (!steps.length && anomaly.ai_suggested_action) {
    steps = [
      {
        title: 'Suggested Action',
        command: '',
        explanation: anomaly.ai_suggested_action,
        risk: 'read-only',
        action: null,
        is_supported: false,
      },
    ];
  }

  resetInvestigation({
    summary: anomaly.ai_summary || `Detected anomaly: ${anomalyTypeLabel(anomaly.type)} in ${anomaly.namespace || 'cluster'}. No AI summary yet; use the evidence checks below.`,
    steps: steps,
    suggested_action: anomaly.ai_suggested_action || '',
    evidence: anomaly.evidence,
    anomaly: anomaly,
  });
  switchTab('actionable', { history });
}

// A single log entry, without needing AI: the evidence checks for its pod.
function openLineInActionable(item, { history = 'push' } = {}) {
  state.actionable.sourceType = 'line';
  state.actionable.anomalyId = null;
  state.actionable.lineItem = item;
  state.focusAnomalyId = null;
  const where = `${item.namespace} · ${item.pod}/${item.container}`;
  resetInvestigation({
    summary: `Log entry from ${where} at ${formatTimestamp(item.timestamp)} (${item.severity_bucket}). `
      + 'Use the evidence checks below, or "Explain this line" in Logs for AI-suggested steps.',
    steps: [],
    suggested_action: '',
    lineItem: item,
  });
  switchTab('actionable', { history });
}

function updateActionableSourceOptions() {
  const sel = el('actionableSourceSelect');
  if (!sel) return;
  const currentVal = sel.value;
  sel.innerHTML = '<option value="logs">Current Filtered Logs</option>';

  for (const anom of state.anomalies) {
    const opt = document.createElement('option');
    opt.value = `anomaly-${anom.id}`;
    const desc = anom.pod ? `${anom.namespace}/${anom.pod}` : (anom.namespace || 'cluster');
    opt.textContent = `Anomaly #${anom.id}: ${anomalyTypeLabel(anom.type)} (${desc})`;
    sel.appendChild(opt);
  }

  if (state.actionable.sourceType === 'anomaly' && state.actionable.anomalyId) {
    if (!sel.querySelector(`option[value="anomaly-${state.actionable.anomalyId}"]`)) {
      const opt = document.createElement('option');
      opt.value = `anomaly-${state.actionable.anomalyId}`;
      opt.textContent = `Anomaly #${state.actionable.anomalyId}`;
      sel.appendChild(opt);
    }
    sel.value = `anomaly-${state.actionable.anomalyId}`;
  } else if (state.actionable.sourceType === 'logs') {
    sel.value = 'logs';
  } else if (currentVal) {
    sel.value = currentVal;
  }
}

function copyToClipboard(text, btnEl) {
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btnEl.textContent;
    btnEl.textContent = 'Copied!';
    setTimeout(() => { btnEl.textContent = orig; }, 1500);
  }).catch(() => {});
}

// The exact command for an evidence check, resolved once by the server's
// validator (works even while running actions is disabled).
function checkValidation(step) {
  const key = JSON.stringify(step.action);
  const cache = state.actionable.validation;
  if (cache.has(key)) return cache.get(key);
  if (cache.size > 200) cache.clear();
  const entry = { status: 'pending', command: '', error: '' };
  cache.set(key, entry);
  postJson('/api/actions/validate', { action: step.action })
    .then((res) => { entry.status = 'ok'; entry.command = res.command || ''; })
    .catch((err) => { entry.status = 'error'; entry.error = err.message; })
    .finally(() => { if (state.activeTab === 'actionable') renderActionableWorkspace(); });
  return entry;
}

function getActionableStep(key) {
  const [kind, raw] = String(key).split(':');
  const index = Number(raw);
  if (kind === 'check') {
    const step = state.actionable.checks[index];
    if (!step) return null;
    const v = checkValidation(step);
    return { ...step, command: v.command, is_supported: v.status === 'ok', unsupported_reason: v.error };
  }
  return state.actionable.plan?.steps?.[index] || null;
}

function stepCardId(key) {
  return `step-card-${String(key).replace(':', '-')}`;
}

const STEP_STATUS_LABELS = {
  ready: 'Ready', validating: 'Validating…', running: 'Running…', success: 'Success', failed: 'Failed',
};

function renderStepCard(step, key, number) {
  const stepState = state.actionable.stepStates.get(key) || { status: 'ready' };
  const busy = stepState.status === 'running' || stepState.status === 'validating';
  const pendingCommand = String(key).startsWith('check:') && !step.command && step.is_supported !== false
    && !step.unsupported_reason;

  const card = document.createElement('div');
  card.className = `troubleshoot-step-card ${busy ? 'active-step' : ''}`;
  card.id = stepCardId(key);

  const head = document.createElement('div');
  head.className = 'step-card-header';
  const titleGroup = document.createElement('div');
  titleGroup.className = 'step-title-group';
  const indexBadge = document.createElement('span');
  indexBadge.className = 'step-index-badge';
  indexBadge.textContent = String(number);
  titleGroup.appendChild(indexBadge);
  const titleText = document.createElement('span');
  titleText.textContent = step.title || `Step ${number}`;
  titleGroup.appendChild(titleText);

  const badges = document.createElement('div');
  badges.className = 'step-badges';
  const risk = step.risk || 'read-only';
  const riskBadge = document.createElement('span');
  riskBadge.className = `badge-risk badge-risk-${risk}`;
  riskBadge.textContent = risk;
  const statusBadge = document.createElement('span');
  statusBadge.className = `badge-status badge-status-${busy ? 'running' : stepState.status}`;
  statusBadge.textContent = STEP_STATUS_LABELS[stepState.status] || stepState.status;
  badges.appendChild(riskBadge);
  badges.appendChild(statusBadge);
  head.appendChild(titleGroup);
  head.appendChild(badges);
  card.appendChild(head);

  const body = document.createElement('div');
  body.className = 'step-card-body';

  if (step.explanation) {
    const exp = document.createElement('div');
    exp.className = 'step-explanation';
    const prefix = document.createElement('span');
    prefix.className = 'step-explanation-prefix';
    prefix.textContent = 'Checks:';
    exp.appendChild(prefix);
    const text = document.createElement('span');
    text.textContent = ` ${step.explanation}`;
    exp.appendChild(text);
    body.appendChild(exp);
  }

  if (step.command || pendingCommand || step.unsupported_reason) {
    const cmdBox = document.createElement('div');
    cmdBox.className = 'step-command-box';
    const code = document.createElement('code');
    code.className = 'step-command-code';
    code.textContent = step.command || (pendingCommand ? 'Resolving the exact command…' : '(no runnable command)');
    const tools = document.createElement('div');
    tools.className = 'step-command-tools';

    if (step.command) {
      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'ghost step-copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyToClipboard(step.command, copyBtn));
      tools.appendChild(copyBtn);
    }

    if (!state.actionsEnabled) {
      const note = document.createElement('span');
      note.className = 'subtle';
      note.textContent = 'Running commands is disabled on this server — copy and run it yourself.';
      tools.appendChild(note);
    } else if (pendingCommand) {
      const note = document.createElement('span');
      note.className = 'subtle';
      note.textContent = 'Checking with the server…';
      tools.appendChild(note);
    } else if (!isRunnableStep(step)) {
      const note = document.createElement('span');
      note.className = 'subtle';
      note.textContent = step.unsupported_reason
        ? `Cannot be run from here: ${step.unsupported_reason}`
        : 'Not a supported diagnostic action — it cannot be run from here.';
      tools.appendChild(note);
    } else {
      const runBtn = document.createElement('button');
      runBtn.type = 'button';
      runBtn.className = `step-btn-run ${risk !== 'read-only' ? 'mutating' : ''}`;
      // One step at a time: also stops a double click from running it twice.
      runBtn.disabled = state.actionable.runningIndex !== null;
      if (busy || state.actionable.runningIndex === key) {
        runBtn.textContent = stepState.status === 'validating' ? 'Validating…' : 'Running…';
      } else if (stepState.status === 'success' || stepState.status === 'failed') {
        runBtn.textContent = 'Re-run';
      } else if (risk !== 'read-only') {
        runBtn.textContent = 'Confirm & Run';
      } else {
        runBtn.textContent = 'Run';
      }
      runBtn.addEventListener('click', () => executeActionableStep(key));
      tools.appendChild(runBtn);
    }
    cmdBox.appendChild(code);
    cmdBox.appendChild(tools);
    body.appendChild(cmdBox);

    // What the server will actually run, when it differs from the suggestion.
    if (step.exec_command && step.exec_command !== step.command) {
      const runsAs = document.createElement('div');
      runsAs.className = 'subtle';
      runsAs.textContent = `Runs as: ${step.exec_command}`;
      body.appendChild(runsAs);
    }
    if (Array.isArray(step.ignored_args) && step.ignored_args.length) {
      const ignored = document.createElement('div');
      ignored.className = 'subtle';
      ignored.textContent = `Not supported, left out: ${step.ignored_args.join(' ')}`;
      body.appendChild(ignored);
    }
  }

  if (stepState.status !== 'ready') body.appendChild(stepOutputMarkup(step, stepState));
  card.appendChild(body);
  return card;
}

function stepOutputMarkup(step, stepState) {
  const outContainer = document.createElement('div');
  outContainer.className = 'step-output-container';
  const outHead = document.createElement('div');
  outHead.className = 'step-output-head';
  const outTitle = document.createElement('span');
  outTitle.textContent = stepState.command || step.command || 'Output';
  const outMeta = document.createElement('div');
  outMeta.className = 'step-output-meta';
  if (stepState.ran_at) {
    const at = document.createElement('span');
    at.textContent = new Date(stepState.ran_at).toLocaleTimeString();
    outMeta.appendChild(at);
  }
  if (stepState.duration_ms !== undefined) {
    const duration = document.createElement('span');
    duration.textContent = `${stepState.duration_ms}ms`;
    outMeta.appendChild(duration);
  }
  if (stepState.exit_code !== undefined) {
    const exitCode = document.createElement('span');
    exitCode.className = stepState.exit_code === 0 ? 'step-exit-ok' : 'step-exit-error';
    exitCode.textContent = `Exit ${stepState.exit_code}`;
    outMeta.appendChild(exitCode);
  }
  if (stepState.output_truncated) {
    const cut = document.createElement('span');
    cut.className = 'step-output-truncated';
    cut.textContent = 'Output truncated';
    cut.title = 'The server keeps at most 256K characters per stream (1 MiB read); the command was stopped past that.';
    outMeta.appendChild(cut);
  }
  outHead.appendChild(outTitle);
  outHead.appendChild(outMeta);
  outContainer.appendChild(outHead);

  const outBody = document.createElement('pre');
  outBody.className = 'step-output-body';
  if (stepState.status === 'validating') {
    outBody.textContent = 'Validating the command with the server…';
    outBody.classList.add('empty-output');
  } else if (stepState.status === 'running') {
    outBody.textContent = 'Executing Kubernetes diagnostic action…';
    outBody.classList.add('empty-output');
  } else {
    const text = [stepState.stdout, stepState.stderr, stepState.error].filter(Boolean).join('\n\n');
    if (text) {
      outBody.textContent = text;
      if (stepState.status === 'failed') outBody.classList.add('step-output-error');
    } else {
      outBody.textContent = '(Command completed with no output)';
      outBody.classList.add('empty-output');
    }
  }
  outContainer.appendChild(outBody);
  return outContainer;
}

function actionableLinkButton(container, label, title, onClick) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'ghost row-detail-btn';
  btn.textContent = label;
  if (title) btn.title = title;
  btn.addEventListener('click', onClick);
  container.appendChild(btn);
}

function renderEvidenceLog(plan) {
  const log = el('actionableEvidenceLog');
  log.innerHTML = '';
  const entries = [...state.actionable.stepStates.entries()]
    .filter(([, st]) => st.ran_at)
    .sort((a, b) => a[1].ran_at - b[1].ran_at);
  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'subtle evidence-log-empty';
    empty.textContent = 'Nothing has been run yet. Results of suggested steps and evidence checks appear here in the order they ran.';
    log.appendChild(empty);
    return 0;
  }
  for (const [key, st] of entries) {
    const step = getActionableStep(key) || {};
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'evidence-log-row';
    row.title = 'Show this result';
    row.addEventListener('click', () => {
      const card = el(stepCardId(key));
      if (card) card.scrollIntoView({ block: 'center' });
    });
    const time = document.createElement('span');
    time.className = 'evidence-log-time';
    time.textContent = new Date(st.ran_at).toLocaleTimeString();
    const origin = document.createElement('span');
    origin.className = 'evidence-log-origin';
    origin.textContent = String(key).startsWith('check:') ? 'Check' : `Step ${Number(String(key).split(':')[1]) + 1}`;
    const title = document.createElement('span');
    title.className = 'evidence-log-title';
    title.textContent = `${step.title || ''} · ${st.command || ''}`;
    const outcome = document.createElement('span');
    outcome.className = `evidence-log-outcome ${st.status === 'success' ? 'ok' : 'failed'}`;
    outcome.textContent = st.status === 'success'
      ? (st.output_truncated ? 'ok · truncated' : 'ok')
      : (st.exit_code !== undefined ? `exit ${st.exit_code}` : 'error');
    row.append(time, origin, title, outcome);
    log.appendChild(row);
  }
  return entries.length;
}

function renderActionableWorkspace() {
  const emptyEl = el('actionableEmpty');
  const wsEl = el('actionableWorkspace');
  const descEl = el('actionableContextDesc');
  const plan = state.actionable.plan;

  if (!plan || !plan.summary) {
    emptyEl.hidden = false;
    wsEl.hidden = true;
    el('actionableRefreshLabel').textContent = 'Generate Plan';
    descEl.textContent = 'Ready to investigate';
    return;
  }

  emptyEl.hidden = true;
  wsEl.hidden = false;
  el('actionableRefreshLabel').textContent = 'Refresh Plan';
  const steps = plan.steps || [];

  // Context description and the investigation's origin
  let origin = '';
  if (state.actionable.sourceType === 'anomaly' && plan.anomaly) {
    const anom = plan.anomaly;
    origin = `Anomaly #${anom.id} · ${anomalyTypeLabel(anom.type)} in ${anom.namespace || 'cluster'}${anom.pod ? `/${anom.pod}` : ''}`;
    descEl.textContent = `Investigating ${origin}`;
    el('actionableSummaryTitle').textContent = `Anomaly Investigation: ${anomalyTypeLabel(anom.type)}`;
  } else if (state.actionable.sourceType === 'line' && plan.lineItem) {
    const item = plan.lineItem;
    origin = `Log entry #${item.id} · ${item.namespace} · ${item.pod}/${item.container}`;
    descEl.textContent = 'Investigating single log record';
    el('actionableSummaryTitle').textContent = 'Log Record Investigation';
  } else {
    origin = `Filtered logs${plan.sample_count ? ` (${plan.sample_count} lines sampled)` : ''}`;
    descEl.textContent = 'Investigating Filtered Logs';
    el('actionableSummaryTitle').textContent = 'Filtered Logs Investigation';
  }

  // Tags
  const tagsEl = el('actionableTags');
  tagsEl.innerHTML = '';
  const addTag = (text) => {
    const tag = document.createElement('span');
    tag.className = 'troubleshoot-tag';
    tag.textContent = text;
    tagsEl.appendChild(tag);
  };
  const target = actionableTarget(plan);
  if (state.actionable.sourceType === 'anomaly' && plan.anomaly) {
    addTag(`type: ${plan.anomaly.type}`);
    if (plan.anomaly.severity) addTag(`sev: ${plan.anomaly.severity}`);
  } else if (plan.filters) {
    if (plan.filters.severity_bucket) addTag(`sev: ${plan.filters.severity_bucket}`);
    if (plan.sample_count) addTag(`sample: ${plan.sample_count} lines`);
  }
  if (target.namespace) addTag(`ns: ${target.namespace}`);
  if (target.pod) addTag(`pod: ${target.pod}`);
  if (target.container) addTag(`container: ${target.container}`);
  addTag(`${steps.length} steps`);

  el('actionableSummary').textContent = plan.summary;

  // Evidence Block (if anomaly)
  const evidenceEl = el('actionableEvidence');
  if (plan.anomaly?.evidence) {
    evidenceEl.hidden = false;
    const ev = { ...plan.anomaly.evidence };
    const sampleMsgs = ev.sample_messages || [];
    delete ev.sample_messages;
    delete ev.ai_error;
    let text = '';
    if (sampleMsgs.length) {
      text += `Sample messages:\n${sampleMsgs.map(m => '• ' + m).join('\n')}\n\n`;
    }
    if (Object.keys(ev).length) {
      text += `Evidence: ${JSON.stringify(ev, null, 2)}`;
    }
    evidenceEl.textContent = text.trim();
  } else {
    evidenceEl.hidden = true;
  }

  // Ways back to the data the investigation came from.
  const links = el('actionableLinks');
  links.innerHTML = '';
  if (plan.anomaly) {
    const anom = plan.anomaly;
    if (anomalyWindow(anom)) {
      actionableLinkButton(links, 'View logs for this window', 'The anomaly\'s namespace, pod and detection hour in Logs', () => openAnomalyLogs(anom));
    }
    actionableLinkButton(links, 'Show in Insights', '', () => {
      switchTab('insights', { history: null });
      updateUrl('push');
      focusAnomaly(anom.id).catch(() => {});
    });
  } else if (plan.lineItem) {
    const id = Number(plan.lineItem.id);
    actionableLinkButton(links, 'Show log context', 'Entries around this one from the same pod and container', () => {
      switchTab('logs', { history: null });
      openContext(id);
    });
  } else {
    actionableLinkButton(links, 'Back to logs', '', () => switchTab('logs'));
  }

  // Suggested steps
  const stepsList = el('actionableStepsList');
  stepsList.innerHTML = '';
  let successCount = 0;
  steps.forEach((step, index) => {
    const key = `plan:${index}`;
    if (state.actionable.stepStates.get(key)?.status === 'success') successCount++;
    stepsList.appendChild(renderStepCard(step, key, index + 1));
  });
  if (!steps.length) {
    const none = document.createElement('div');
    none.className = 'subtle';
    none.textContent = 'No suggested steps for this investigation. Use the evidence checks below.';
    stepsList.appendChild(none);
  }
  el('actionableStepsCount').textContent = `${successCount} of ${steps.length} steps completed`;
  el('actionableRunNextBtn').disabled = !steps.some((step) => isRunnableStep(step));

  // Evidence checks for the target pod / namespace
  const checksSection = el('actionableChecksSection');
  const checks = state.actionable.checks || [];
  checksSection.hidden = !checks.length;
  const checksList = el('actionableChecksList');
  checksList.innerHTML = '';
  if (checks.length) {
    const parts = [target.namespace && `namespace ${target.namespace}`, target.pod && `pod ${target.pod}`,
      target.container && `container ${target.container}`].filter(Boolean);
    el('actionableChecksTarget').textContent = `Registered read-only actions for ${parts.join(', ')}. Nothing runs until you click Run.`;
    checks.forEach((_, index) => {
      const key = `check:${index}`;
      checksList.appendChild(renderStepCard(getActionableStep(key), key, index + 1));
    });
  }

  const collected = renderEvidenceLog(plan);
  el('actionableFlow').textContent = `${origin} → ${steps.length} suggested step${steps.length === 1 ? '' : 's'}`
    + `${checks.length ? ` + ${checks.length} evidence checks` : ''} → ${collected} result${collected === 1 ? '' : 's'} collected`;
}

// A step can be run when it has a command the server's allowlist accepts.
// Plans saved before is_supported existed are left to the server to decide.
function isRunnableStep(step) {
  return Boolean(step && step.command) && step.is_supported !== false;
}

function postJson(url, payload) {
  return fetchJson(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

function askToConfirm(key, step, resolved, risk) {
  state.actionable.pendingMutation = {
    key, structured: resolved.structured, command: resolved.command, confirm_token: resolved.confirm_token,
  };
  el('confirmModalCommand').textContent = resolved.command;
  el('confirmModalText').textContent =
    `"${step.title || 'This step'}" (risk: ${risk}) may change cluster state. Exactly this command will run:`;
  el('actionConfirmModal').showModal();
}

// Validate first, then execute the exact structured action the server
// resolved; the command shown to the user is the server's, not the model's.
// `confirmed` is the pendingMutation the user approved in the dialog.
async function executeActionableStep(key, confirmed = null) {
  if (!state.actionsEnabled) return;
  if (state.actionable.runningIndex !== null) return;
  const step = getActionableStep(key);
  if (!step || !isRunnableStep(step)) return;
  const version = state.actionable.planVersion;
  const current = () => version === state.actionable.planVersion;
  const states = state.actionable.stepStates;

  state.actionable.runningIndex = key;
  let shownCommand = step.exec_command || step.command;
  try {
    let resolved = confirmed;
    if (!resolved) {
      states.set(key, { status: 'validating', command: shownCommand });
      renderActionableWorkspace();
      const check = await postJson('/api/actions/validate', { action: step.action || undefined, command: step.command });
      if (!current()) return;
      resolved = { structured: check.structured, command: check.command, confirm_token: check.confirm_token };
      shownCommand = check.command;
      const risk = [check.risk, step.risk].includes('high') ? 'high' : (check.risk !== 'read-only' ? check.risk : (step.risk || 'read-only'));
      if (check.is_mutating || risk !== 'read-only') {
        states.set(key, { status: 'ready' });
        askToConfirm(key, step, resolved, risk);
        return;
      }
    }

    shownCommand = resolved.command;
    states.set(key, { status: 'running', command: resolved.command });
    renderActionableWorkspace();
    // The server only runs a state-changing action with the single-use token
    // it issued for exactly this command.
    const res = await postJson('/api/actions/execute', {
      action: resolved.structured,
      confirmed: Boolean(confirmed),
      confirm_token: confirmed ? resolved.confirm_token : undefined,
    });
    if (!current()) return;

    if (res.requires_confirmation) {
      states.set(key, { status: 'ready' });
      askToConfirm(key, step, {
        structured: res.structured, command: res.command, confirm_token: res.confirm_token,
      }, res.risk || 'medium');
      return;
    }

    states.set(key, {
      status: res.success ? 'success' : 'failed',
      exit_code: res.exit_code,
      stdout: res.stdout || '',
      stderr: res.stderr || '',
      duration_ms: res.duration_ms || 0,
      command: res.command || resolved.command,
      output_truncated: Boolean(res.output_truncated),
      ran_at: Date.now(),
    });
  } catch (err) {
    if (!current()) return;
    states.set(key, {
      status: 'failed',
      stdout: '',
      stderr: '',
      error: `Not run: ${err.message}`,
      command: shownCommand,
      ran_at: Date.now(),
    });
  } finally {
    state.actionable.runningIndex = null;
    renderActionableWorkspace();
  }
}

// Runs the first suggested step that has not been attempted yet, on click.
// Evidence checks are never included; failed steps are not retried
// automatically (use Re-run on the step).
function runNextActionableStep() {
  const plan = state.actionable.plan;
  if (!plan || !plan.steps || state.actionable.runningIndex !== null) return;
  for (let i = 0; i < plan.steps.length; i++) {
    const key = `plan:${i}`;
    const st = state.actionable.stepStates.get(key);
    if (isRunnableStep(plan.steps[i]) && (!st || st.status === 'ready')) {
      executeActionableStep(key);
      return;
    }
  }
}

function resetActionableSteps() {
  state.actionable.stepStates.clear();
  renderActionableWorkspace();
}

// ─── Data loading ────────────────────────────────────────────────────────────

async function loadFacets() {
  renderFacets(await fetchJson('/api/facets'));
}

function updateHealthFromStatus(status) {
  if (status.database_error) {
    el('health').textContent = `Database error: ${status.database_error}`;
    return;
  }
  el('health').textContent = status.total_records
    ? `Cached ${status.total_records} rows from ${status.total_objects} objects`
    : 'Waiting for ingestion';
  if (!status.total_records && status.last_error) {
    el('health').textContent = `Ingestion error: ${status.last_error}`;
  }
  const ingest = status.ingest || {};
  if (ingest.state === 'stale' || ingest.state === 'stalled') {
    const since = ingest.seconds_since_last_success;
    const age = Number.isFinite(since) ? ` for ${Math.round(since / 60)}m` : '';
    el('health').textContent = ingest.state === 'stalled'
      ? 'Ingestion stalled: the S3 poll loop has not completed recently'
      : `Ingestion stale: no successful S3 poll${age}${status.last_error ? ` (${status.last_error})` : ''}`;
  } else if (ingest.failing_objects) {
    el('health').textContent += ` · ${ingest.failing_objects} S3 object(s) failing, retrying`;
  }
}

function resetOlderLogsState() {
  state.olderItems = [];
  state.olderCursor = null;
  state.olderHasMore = false;
  state.olderLoading = false;
  state.olderRequestId += 1;
  closeOlderLogsOverlay();
  const loadMore = el('loadMore');
  if (loadMore) {
    loadMore.disabled = !(state.nextCursor || state.olderCursor || state.olderHasMore);
    loadMore.textContent = state.nextCursor ? 'Load older' : 'End of results';
  }
}

function openOlderLogsOverlay(explicitUserAction = false) {
  if (!explicitUserAction) {
    closeOlderLogsOverlay();
    return;
  }
  const hasOlder = Boolean(state.nextCursor || state.olderCursor || state.olderItems.length);
  if (!hasOlder) {
    closeOlderLogsOverlay();
    return;
  }
  state.olderOverlayOpen = true;
  const overlay = el('olderLogsOverlay');
  if (overlay) {
    overlay.hidden = false;
    overlay.style.display = 'flex';
  }
  if (!state.olderItems.length) {
    loadOlderLogsPage().catch((err) => {
      el('health').textContent = err.message;
    });
  } else {
    renderOlderLogs();
  }
}

function closeOlderLogsOverlay() {
  state.olderOverlayOpen = false;
  const overlay = el('olderLogsOverlay');
  if (overlay) {
    overlay.hidden = true;
    overlay.style.display = 'none';
  }
}

function ensureOlderLogsClosed() {
  closeOlderLogsOverlay();
  const olderLoadMore = el('olderLogsLoadMore');
  if (olderLoadMore) {
    olderLoadMore.disabled = true;
  }
}

function handleOlderOverlayOutsideClick(event) {
  const overlay = el('olderLogsOverlay');
  if (!overlay || overlay.hidden) return;
  if (event.target === overlay) {
    closeOlderLogsOverlay();
  }
}

async function loadOlderLogsPage() {
  if (state.olderLoading) return;
  const cursor = state.olderCursor || state.nextCursor;
  if (!cursor && !state.olderItems.length) {
    closeOlderLogsOverlay();
    return;
  }

  const requestId = ++state.olderRequestId;
  state.olderLoading = true;
  renderOlderLogs();

  try {
    const params = new URLSearchParams(queryFromFilters({ limit: String(OLDER_LOG_LIMIT), cursor }));
    const data = await fetchJson(`/api/logs?${params.toString()}`);
    if (requestId !== state.olderRequestId) return;

    const items = Array.isArray(data.items) ? data.items : [];
    if (items.length) {
      state.olderItems = state.olderItems.concat(items);
    }
    state.olderCursor = data.next_cursor || null;
    state.olderHasMore = Boolean(data.has_more);
    if (!state.olderCursor && !state.olderHasMore && state.olderItems.length) {
      state.nextCursor = null;
    }
  } catch (err) {
    if (requestId === state.olderRequestId) {
      closeOlderLogsOverlay();
      el('health').textContent = err.message;
    }
    return;
  } finally {
    if (requestId === state.olderRequestId) {
      state.olderLoading = false;
      renderOlderLogs();
    }
  }
}

function renderOlderLogs() {
  const container = el('olderLogsList');
  if (!container) return;
  container.innerHTML = '';

  if (!state.olderItems.length) {
    container.innerHTML = '<div class="empty-state">No older logs available for this filter.</div>';
  } else {
    for (const item of state.olderItems) {
      const node = rowMarkup(item);
      node.classList.add('older-log-row');
      if (state.expandedRows.has(String(item.id))) {
        node.classList.add('expanded');
        node.appendChild(detailMarkup(item, String(item.id)));
      }
      container.appendChild(node);
    }
  }

  const olderLoadMore = el('olderLogsLoadMore');
  if (olderLoadMore) {
    const hasMore = state.olderHasMore || Boolean(state.nextCursor && !state.olderItems.length);
    olderLoadMore.disabled = state.olderLoading || !hasMore;
    olderLoadMore.hidden = !hasMore && !state.olderItems.length;
    olderLoadMore.textContent = state.olderLoading ? 'Loading…' : (hasMore ? 'Load older' : 'No more older logs');
  }
}

function showLogsError(message) {
  const box = el('logsError');
  box.textContent = message || '';
  box.hidden = !message;
}

function setLogsLoading(loading) {
  el('rows').setAttribute('aria-busy', loading ? 'true' : 'false');
  if (loading) el('resultSummary').textContent = 'Loading…';
}

// Never rejects: a failed load is shown above the rows (the previous rows stay,
// labelled as such), so callers need no error handling of their own.
async function loadLogs(reset = true) {
  const requestId = ++state.logsRequestId;
  state.tailRequestId += 1; // a tail response for the previous query must not land on this one
  refreshLiveEnd();
  setLogsLoading(true);
  let data;
  try {
    const params = new URLSearchParams(queryFromFilters({ limit: String(CURRENT_LOG_LIMIT) }));
    if (!reset && state.nextCursor) params.set('cursor', state.nextCursor);
    data = await fetchJson(`/api/logs?${params.toString()}`);
  } catch (err) {
    if (requestId === state.logsRequestId) {
      setLogsLoading(false);
      el('resultSummary').textContent = 'Load failed';
      showLogsError(`Could not load logs: ${err.message}. The rows below are from the previous query.`);
    }
    return false;
  }
  if (requestId !== state.logsRequestId) return false;
  setLogsLoading(false);
  showLogsError('');
  state.nextCursor = data.next_cursor || null;
  state.hasMore = Boolean(data.has_more);
  state.lastUpdatedAt = data.last_updated_at;
  if (reset) {
    state.items = Array.isArray(data.items) ? data.items.slice(0, CURRENT_LOG_LIMIT) : [];
    state.olderItems = [];
    state.olderCursor = null;
    state.olderHasMore = false;
    closeOlderLogsOverlay();
  } else {
    state.items = (Array.isArray(data.items) ? data.items : []).slice(0, CURRENT_LOG_LIMIT);
  }
  state.expandedRows.clear();
  state.expandedGroups.clear();
  renderAll();
  renderOlderLogs();
  el('freshness').textContent = fmtFreshness(state.lastUpdatedAt);
  const loadMore = el('loadMore');
  if (loadMore) {
    loadMore.disabled = !(state.nextCursor || state.olderCursor || state.olderHasMore);
    loadMore.textContent = state.nextCursor ? 'Load older' : 'End of results';
  }
  if (!el('health').textContent || !el('health').textContent.startsWith('Ingestion')) {
    el('health').textContent = state.hasMore ? 'More older rows available' : 'End of current page';
  }
  // Tail from the newest row that existed when this query ran, whether or not
  // Live is on yet and whether or not the page matched anything.
  if (reset) state.liveCursor = Number.isFinite(data.max_id) ? data.max_id : null;
  if (reset) {
    // Filters may have changed: refresh the dashboard now only if it is on
    // screen; otherwise mark it out of date so it reloads when opened.
    if (state.activeTab === 'dashboard') {
      loadDashboard().catch((err) => {
        el('health').textContent = err.message;
      });
    } else {
      state.dashboard.loaded = false;
    }
    scheduleLogPanels();
  }
  return true;
}

function compareNewestFirst(a, b) {
  if (a.timestamp !== b.timestamp) return a.timestamp < b.timestamp ? 1 : -1;
  return Number(b.id) - Number(a.id);
}

// New tail rows merged into the visible rows: newest first by event time,
// each row once, capped to the view size (older rows drop off the bottom).
function mergeNewestItems(incoming, current, limit) {
  const byId = new Map();
  for (const item of incoming.concat(current)) {
    if (!byId.has(item.id)) byId.set(item.id, item);
  }
  return Array.from(byId.values()).sort(compareNewestFirst).slice(0, limit);
}

function flashNewRows(count, truncated = false) {
  const banner = el('newRowsBanner');
  el('newRowsCount').textContent = truncated ? `${count}+` : String(count);
  banner.classList.add('show');
  window.clearTimeout(flashNewRows.timer);
  flashNewRows.timer = window.setTimeout(() => banner.classList.remove('show'), 6000);
}

// Rows ingested since the last poll (by row id, so objects that arrive late
// with older timestamps are not skipped). The server returns the newest
// matches first; they are merged into the view in event-time order.
async function pollTail() {
  if (!el('live').checked) return;
  const requestId = ++state.tailRequestId;
  const extra = { limit: '200' };
  if (state.liveCursor !== null) extra.after_id = String(state.liveCursor);
  const params = new URLSearchParams(queryFromFilters(extra));
  const data = await fetchJson(`/api/tail?${params.toString()}`);
  if (requestId !== state.tailRequestId || !el('live').checked) return;
  const hadCursor = state.liveCursor !== null;
  state.liveCursor = Number.isFinite(data.last_id) ? data.last_id : state.liveCursor;
  const items = Array.isArray(data.items) ? data.items : [];
  if (hadCursor && items.length) {
    state.items = mergeNewestItems(items, state.items, CURRENT_LOG_LIMIT);
    state.expandedRows.clear();
    state.expandedGroups.clear();
    refreshLiveEnd();
    renderAll();
    flashNewRows(items.length, Boolean(data.truncated));
    scheduleLogPanels();
  }
  state.lastUpdatedAt = data.last_updated_at;
  el('freshness').textContent = fmtFreshness(state.lastUpdatedAt);
}

function syncFiltersFromUi() {
  state.filters = queryFromFilters();
}

function startTailPolling() {
  stopTailPolling();
  state.tailRequestId += 1;
  state.liveTimer = window.setInterval(() => {
    pollTail().catch((err) => {
      el('health').textContent = err.message;
    });
    el('freshness').textContent = fmtFreshness(state.lastUpdatedAt);
  }, 10000);
}

function stopTailPolling() {
  if (state.liveTimer) window.clearInterval(state.liveTimer);
  state.liveTimer = null;
  state.tailRequestId += 1;
}

// ─── Field sidebar + histogram (Logs tab) ────────────────────────────────────
// Both follow the applied filters: every Logs reload schedules one refresh
// (debounced), and a newer refresh aborts the request still in flight.

const FIELD_SIDEBAR = [
  ['scope', 'Scope'],
  ['namespace', 'Namespace'],
  ['pod', 'Pod'],
  ['container', 'Container'],
  ['severity_bucket', 'Severity'],
];
const SEVERITY_NAMES = ['error', 'warning', 'info', 'debug', 'metrics'];
const HISTOGRAM_SEVERITIES = ['error', 'warning', 'info', 'debug'];

function scheduleLogPanels() {
  const panels = state.logPanels;
  window.clearTimeout(panels.timer);
  if (state.activeTab !== 'logs') {
    panels.stale = true; // refreshed when the Logs tab opens
    return;
  }
  panels.stale = false;
  panels.timer = window.setTimeout(() => {
    loadLogPanels();
  }, LOG_PANELS_DEBOUNCE_MS);
}

// Never rejects: each panel shows its own error.
async function loadLogPanels() {
  const panels = state.logPanels;
  if (panels.abort) panels.abort.abort();
  const controller = new AbortController();
  panels.abort = controller;
  refreshLiveEnd();
  const qs = new URLSearchParams(queryFromFilters()).toString();
  const [fields, histogram] = await Promise.allSettled([
    fetchJson(`/api/fields?${qs}`, { signal: controller.signal }),
    fetchJson(`/api/histogram?${qs}`, { signal: controller.signal }),
  ]);
  if (controller.signal.aborted) return; // superseded by a newer refresh
  panels.abort = null;
  if (fields.status === 'fulfilled') renderFieldSidebar(fields.value);
  else el('fieldList').innerHTML = `<div class="field-error">Could not load fields: ${escapeHtml(fields.reason.message)}</div>`;
  if (histogram.status === 'fulfilled') {
    renderHistogram(histogram.value);
  } else {
    panels.histogram = null;
    el('histogramBars').innerHTML = '';
    el('histogramSummary').textContent = `Could not load the histogram: ${histogram.reason.message}`;
  }
}

function currentFilterValue(field) {
  return el(field).value.trim();
}

function renderFieldSidebar(data) {
  const fields = (data && data.fields) || {};
  const html = FIELD_SIDEBAR.map(([field, label]) => {
    const info = fields[field] || { values: [] };
    const excluded = state.exclude[field];
    const active = currentFilterValue(field);
    const total = Number(info.total) || 0;
    const meta = info.partial
      ? 'timed out'
      : `${formatCount(info.distinct)} value${Number(info.distinct) === 1 ? '' : 's'} · ${formatCount(total)}`;
    const chips = excluded.map((value) => `
      <button type="button" class="field-chip" data-field-unexclude="${escapeHtml(field)}" data-value="${escapeHtml(value)}" title="Excluded — click to include again">
        ≠ ${escapeHtml(dashboardLabel(value))} <span aria-hidden="true">✕</span>
      </button>`).join('');
    const rows = (info.values || []).map((item) => {
      const value = String(item.value ?? '');
      const count = Number(item.count) || 0;
      const width = total > 0 ? Math.max(2, Math.round((count / total) * 100)) : 0;
      const isActive = active !== '' && active === value;
      const sevClass = field === 'severity_bucket' && SEVERITY_NAMES.includes(value) ? ` field-fill-${value}` : '';
      return `
        <button type="button" class="field-value${isActive ? ' active' : ''}" data-field="${escapeHtml(field)}" data-value="${escapeHtml(value)}" aria-pressed="${isActive ? 'true' : 'false'}"
          title="${escapeHtml(isActive ? 'Click to clear this filter' : 'Click to filter · Alt/Shift-click to exclude')}">
          <span class="field-value-label">${escapeHtml(dashboardLabel(value))}</span>
          <span class="field-value-count">${formatCount(count)}</span>
          <span class="field-value-track"><span class="field-value-fill${sevClass}" style="width:${width}%"></span></span>
        </button>`;
    }).join('');
    const empty = !rows && !info.partial ? '<div class="field-empty">No values</div>' : '';
    const partial = info.partial ? '<div class="field-empty">Took too long; narrow the filters to see values.</div>' : '';
    return `
      <section class="field-group">
        <div class="field-group-head"><span class="field-name">${escapeHtml(label)}</span><span class="field-meta">${escapeHtml(meta)}</span></div>
        ${chips ? `<div class="field-chips">${chips}</div>` : ''}
        ${rows}${empty}${partial}
      </section>`;
  }).join('');
  el('fieldList').innerHTML = html;
  updateExcludedCount();
}

function updateExcludedCount() {
  const count = FILTER_EXCLUDES.reduce((sum, [field]) => sum + state.exclude[field].length, 0);
  const badge = el('fieldExcludedCount');
  badge.hidden = count === 0;
  badge.textContent = count ? `· ${count} excluded` : '';
}

function setFilterValue(field, value) {
  if (field === 'pod' || field === 'container') el(field).value = value;
  else setSelectValue(el(field), value);
}

// Click: filter on the value (again: clear that filter). Alt/Shift-click:
// exclude it (and drop the filter if it was the selected value).
function applyFieldValue(field, value, exclude) {
  const excluded = state.exclude[field];
  if (exclude) {
    if (!excluded.includes(value) && excluded.length < FIELD_EXCLUDE_MAX) excluded.push(value);
    if (currentFilterValue(field) === value) setFilterValue(field, '');
  } else {
    state.exclude[field] = excluded.filter((v) => v !== value);
    setFilterValue(field, currentFilterValue(field) === value ? '' : value);
  }
  reloadLogs();
}

function renderHistogram(data) {
  const panels = state.logPanels;
  const buckets = Array.isArray(data?.buckets) ? data.buckets : [];
  const bucketMs = (Number(data?.bucket_secs) || 60) * 1000;
  panels.histogram = { buckets, bucketMs };
  panels.drag = null;
  hideHistogramTooltip();
  const total = buckets.reduce((sum, b) => sum + (Number(b.total) || 0), 0);
  const max = buckets.reduce((m, b) => Math.max(m, Number(b.total) || 0), 0);
  el('histogramSummary').textContent = buckets.length
    ? `${formatCount(total)} entries · ${formatBucketSize(bucketMs)} buckets${data.truncated ? ' · oldest buckets omitted' : ''}`
    : 'No entries in this range';
  el('histogramBars').innerHTML = buckets.map((b, index) => {
    const count = Number(b.total) || 0;
    const height = max > 0 && count > 0 ? Math.max(3, Math.round((count / max) * 100)) : 0;
    const known = HISTOGRAM_SEVERITIES.reduce((sum, sev) => sum + (Number(b[sev]) || 0), 0);
    const segments = HISTOGRAM_SEVERITIES
      .concat('other')
      .map((sev) => [sev, sev === 'other' ? Math.max(0, count - known) : Number(b[sev]) || 0])
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => `<span class="hist-seg hist-${sev}" style="flex-grow:${n}"></span>`)
      .join('');
    return `<div class="hist-col" data-i="${index}"><div class="hist-stack" style="height:${height}%">${segments}</div></div>`;
  }).join('');
  el('histogramFrom').textContent = buckets.length ? formatTimestamp(buckets[0].t) : '';
  el('histogramTo').textContent = buckets.length
    ? formatTimestamp(new Date(Date.parse(buckets[buckets.length - 1].t) + bucketMs).toISOString())
    : '';
  updateHistogramReset();
}

function formatBucketSize(ms) {
  const minutes = Math.round(ms / 60000);
  return minutes >= 60 ? `${minutes / 60}h` : `${minutes}m`;
}

function histogramIndexAt(clientX) {
  const hist = state.logPanels.histogram;
  if (!hist || !hist.buckets.length) return null;
  const rect = el('histogramBars').getBoundingClientRect();
  if (rect.width <= 0) return null;
  const index = Math.floor(((clientX - rect.left) / rect.width) * hist.buckets.length);
  return Math.min(hist.buckets.length - 1, Math.max(0, index));
}

function markHistogramSelection() {
  const drag = state.logPanels.drag;
  const lo = drag ? Math.min(drag.from, drag.to) : -1;
  const hi = drag ? Math.max(drag.from, drag.to) : -1;
  for (const col of el('histogramBars').children) {
    const index = Number(col.dataset.i);
    col.classList.toggle('selected', index >= lo && index <= hi);
  }
}

function showHistogramTooltip(index, clientX) {
  const hist = state.logPanels.histogram;
  const bucket = hist?.buckets[index];
  if (!bucket) return;
  const tip = el('histogramTooltip');
  const end = new Date(Date.parse(bucket.t) + hist.bucketMs).toISOString();
  const lines = HISTOGRAM_SEVERITIES
    .filter((sev) => Number(bucket[sev]) > 0)
    .map((sev) => `<div class="hist-tip-row"><span class="hist-tip-dot hist-${sev}"></span>${escapeHtml(sev)} <b>${formatCount(bucket[sev])}</b></div>`)
    .join('');
  tip.innerHTML = `
    <div class="hist-tip-time">${escapeHtml(formatTimestamp(bucket.t))} – ${escapeHtml(formatTimestamp(end))}</div>
    <div class="hist-tip-row"><b>${formatCount(bucket.total)}</b> entries</div>${lines}`;
  tip.hidden = false;
  const box = el('histogram').getBoundingClientRect();
  const x = Math.min(Math.max(clientX - box.left + 12, 0), Math.max(0, box.width - tip.offsetWidth));
  tip.style.left = `${x}px`;
}

function hideHistogramTooltip() {
  el('histogramTooltip').hidden = true;
}

// A drag selects [first bucket, last bucket + size); a click zooms to one bucket.
function applyHistogramSelection(from, to) {
  const hist = state.logPanels.histogram;
  if (!hist) return;
  const lo = hist.buckets[Math.min(from, to)];
  const hi = hist.buckets[Math.max(from, to)];
  if (!lo || !hi) return;
  if (!state.logPanels.prevRange) state.logPanels.prevRange = snapshotRange();
  setExactRange(new Date(lo.t).toISOString(), new Date(Date.parse(hi.t) + hist.bucketMs).toISOString());
  reloadLogs();
}

function snapshotRange() {
  return {
    preset: el('rangePreset').value,
    rangeExact: state.rangeExact ? { ...state.rangeExact } : null,
    start: el('start').value,
    end: el('end').value,
    endIsLive: state.endIsLive,
  };
}

// Back to the range before the first zoom (relative presets re-anchor to
// now); without one, back to Today.
function resetHistogramRange() {
  const prev = state.logPanels.prevRange;
  state.logPanels.prevRange = null;
  if (prev && RANGE_PRESETS[prev.preset]) {
    el('rangePreset').value = prev.preset;
    RANGE_PRESETS[prev.preset].apply();
  } else if (prev) {
    el('rangePreset').value = prev.preset;
    el('start').value = prev.start;
    el('end').value = prev.end;
    state.endIsLive = prev.endIsLive;
    state.rangeExact = prev.rangeExact;
  } else {
    el('rangePreset').value = 'today';
    setDefaultDateRange();
  }
  reloadLogs();
}

function updateHistogramReset() {
  el('histogramReset').hidden = !(state.logPanels.prevRange || state.rangeExact);
}

// A range picked outside the histogram ends any zoom.
function forgetHistogramZoom() {
  state.logPanels.prevRange = null;
}

// ─── Pipeline health (from /api/status) ──────────────────────────────────────

const TONE_RANK = { ok: 0, info: 0, unknown: 1, warn: 2, error: 3 };

function worstTone(...tones) {
  return tones.reduce((a, b) => (TONE_RANK[b] > TONE_RANK[a] ? b : a), 'ok');
}

function formatDuration(totalSeconds) {
  if (!Number.isFinite(totalSeconds)) return '—';
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

// Seconds since an ISO time (negative when it lies in the future), or null.
function secondsSince(iso) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? (Date.now() - t) / 1000 : null;
}

function describeAge(iso) {
  const age = secondsSince(iso);
  if (age === null) return 'never';
  if (age < -60) return `${formatDuration(-age)} ahead of this browser's clock`;
  return `${formatDuration(Math.max(0, age))} ago`;
}

function formatBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function pipelineCard(title, tone, stateLabel) {
  const card = document.createElement('section');
  card.className = `pipeline-card tone-${tone}`;
  const head = document.createElement('div');
  head.className = 'pipeline-card-head';
  const h = document.createElement('h3');
  h.textContent = title;
  const pill = document.createElement('span');
  pill.className = `pipeline-state tone-${tone}`;
  pill.textContent = stateLabel;
  head.append(h, pill);
  const body = document.createElement('dl');
  body.className = 'pipeline-kv';
  card.append(head, body);
  return { card, body };
}

function kvRow(body, label, value, tone = '') {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
  if (tone) dd.className = `tone-${tone}`;
  body.append(dt, dd);
}

function kvBlock(card, label, text, tone = '') {
  const wrap = document.createElement('div');
  wrap.className = 'pipeline-block';
  const l = document.createElement('div');
  l.className = 'detail-label';
  l.textContent = label;
  const pre = document.createElement('pre');
  pre.className = `pipeline-pre${tone ? ` tone-${tone}` : ''}`;
  pre.textContent = String(text).slice(0, 2000);
  wrap.append(l, pre);
  card.appendChild(wrap);
}

function kvTable(card, label, headers, rows) {
  const wrap = document.createElement('div');
  wrap.className = 'pipeline-block';
  const l = document.createElement('div');
  l.className = 'detail-label';
  l.textContent = label;
  const table = document.createElement('table');
  table.className = 'pipeline-table';
  const thead = document.createElement('tr');
  for (const h of headers) {
    const th = document.createElement('th');
    th.textContent = h;
    thead.appendChild(th);
  }
  table.appendChild(thead);
  for (const row of rows) {
    const tr = document.createElement('tr');
    for (const cell of row) {
      const td = document.createElement('td');
      td.textContent = cell === null || cell === undefined ? '—' : String(cell);
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }
  wrap.append(l, table);
  card.appendChild(wrap);
}

const INGEST_STATES = {
  ok: ['ok', 'Healthy'],
  degraded: ['warn', 'Degraded'],
  stale: ['error', 'Stale'],
  stalled: ['error', 'Stalled'],
  stopped: ['error', 'Stopped'],
  starting: ['unknown', 'Starting'],
  unknown: ['unknown', 'Unknown'],
};

function renderIngestCard(status) {
  const ingest = status.ingest || {};
  const [tone, label] = INGEST_STATES[ingest.state] || ['unknown', ingest.state ? String(ingest.state) : 'Unknown'];
  const { card, body } = pipelineCard('Ingestion (S3 → cache)', tone, label);
  kvRow(body, 'Last successful poll', status.last_successful_ingest_at
    ? describeAge(status.last_successful_ingest_at) : 'never', status.last_successful_ingest_at ? '' : 'warn');
  kvRow(body, 'Last poll finished', Number.isFinite(ingest.seconds_since_last_poll)
    ? `${formatDuration(ingest.seconds_since_last_poll)} ago` : 'not yet');
  kvRow(body, 'Poll interval / stale after', ingest.poll_interval_secs
    ? `${ingest.poll_interval_secs}s / ${formatDuration(ingest.stale_after_secs)}` : '—');
  // Ingestion lag: how far the newest cached data trails the clock.
  const eventAge = secondsSince(status.latest_record_timestamp);
  const lagTone = eventAge === null ? 'unknown'
    : eventAge > (ingest.stale_after_secs || 300) * 2 ? 'warn' : '';
  kvRow(body, 'Newest cached event', status.latest_record_timestamp
    ? `${describeAge(status.latest_record_timestamp)} (${formatTimestamp(status.latest_record_timestamp)})` : 'no records', lagTone);
  kvRow(body, 'Newest S3 object ingested', status.last_object_last_modified
    ? describeAge(status.last_object_last_modified) : 'unknown');
  kvRow(body, 'Cached', status.total_records !== undefined
    ? `${formatCount(status.total_records)} records from ${formatCount(status.total_objects)} objects` : '—');
  const failing = Number(ingest.failing_objects || 0);
  kvRow(body, 'Objects failing (retrying)', ingest.failing_objects === undefined ? '—' : formatCount(failing), failing ? 'warn' : '');
  const latest = ingest.latest_failure;
  if (latest) {
    const next = secondsSince(latest.next_attempt_at);
    const nextText = next === null ? 'unknown' : next >= 0 ? 'due now' : `in ${formatDuration(-next)}`;
    kvRow(body, 'Latest failing object', `${latest.key} · attempt ${latest.attempts} · next retry ${nextText}`, 'warn');
  }
  const byPrefix = Array.isArray(ingest.failures_by_prefix) ? ingest.failures_by_prefix : [];
  const prefixErrors = Array.isArray(status.prefix_errors) ? status.prefix_errors : [];
  if (prefixErrors.length) {
    kvTable(card, 'Listing errors in the last poll', ['Prefix', 'Error'],
      prefixErrors.map((p) => [p.prefix === '*' ? '(whole poll)' : p.prefix, p.error]));
  }
  if (byPrefix.length) {
    kvTable(card, 'Failing objects by prefix', ['Prefix', 'Objects', 'Max attempts', 'Next retry'],
      byPrefix.map((p) => [p.prefix, p.count, p.max_attempts, p.next_attempt_at ? formatTimestamp(p.next_attempt_at) : '—']));
  }
  if (status.last_error) kvBlock(card, 'Last poll error', status.last_error, tone === 'ok' ? 'warn' : tone);
  return { card, tone };
}

function renderInsightsCard(status) {
  const ins = status.insights;
  if (!ins) {
    const { card } = pipelineCard('Insights', 'unknown', 'Unknown');
    return { card, tone: 'unknown' };
  }
  let tone = 'ok';
  let label = 'Healthy';
  const runAge = secondsSince(ins.last_run_at);
  const interval = Number(ins.detect_interval_secs) || 300;
  if (!ins.enabled) { tone = 'unknown'; label = 'Disabled'; }
  else if (!ins.running) { tone = 'error'; label = 'Not running'; }
  else if (ins.consecutive_failures > 0) { tone = 'error'; label = `Failing (${ins.consecutive_failures}×)`; }
  else if (runAge === null) { tone = 'unknown'; label = 'Not run yet'; }
  else if (runAge > interval * 3) { tone = 'warn'; label = 'Late'; }
  else if (ins.learning) { tone = 'info'; label = 'Learning'; }
  const { card, body } = pipelineCard('Insights (anomaly detection)', tone, label);
  if (ins.enabled) {
    kvRow(body, 'Last run', ins.last_run_at ? `${describeAge(ins.last_run_at)} · every ${formatDuration(interval)}` : 'not yet');
    kvRow(body, 'Duration', Number.isFinite(ins.last_duration_ms) ? `${formatCount(ins.last_duration_ms)} ms` : '—');
    const counts = ins.last_counts || {};
    const countText = Object.keys(counts).length
      ? Object.entries(counts).map(([k, v]) => `${k.replace('anomalies_', '')} ${v}`).join(' · ')
      : '—';
    kvRow(body, 'Last run results', countText);
    if (ins.learning) {
      const have = Number.isFinite(ins.history_hours) ? `${ins.history_hours}h` : 'no';
      const need = Number.isFinite(ins.min_baseline_hours) ? ` of the ${ins.min_baseline_hours}h needed` : '';
      kvRow(body, 'Baseline history', `${have} of history${need}; rate-based detectors wait until then`, 'info');
    } else if (Number.isFinite(ins.history_hours)) {
      kvRow(body, 'Baseline history', `${ins.history_hours}h available`);
    }
    kvRow(body, 'Consecutive failures', String(ins.consecutive_failures || 0), ins.consecutive_failures ? 'error' : '');
    if (Number(ins.future_dated_records) > 0) {
      kvRow(body, 'Future-dated records', `${formatCount(ins.future_dated_records)} (clock skew? never evaluated)`, 'warn');
    }
  }
  if (ins.last_error) kvBlock(card, `Last detection error${ins.last_error_at ? ` (${describeAge(ins.last_error_at)})` : ''}`, ins.last_error, 'error');
  if (ins.last_ai_error) {
    kvBlock(card, `Last AI summary error${ins.last_ai_error_at ? ` (${describeAge(ins.last_ai_error_at)})` : ''}`, ins.last_ai_error, 'warn');
    tone = worstTone(tone, 'warn');
  }
  return { card, tone };
}

function renderStorageCard(status) {
  const st = status.storage || {};
  let tone = 'ok';
  let label = 'Healthy';
  if (status.database_error) { tone = 'error'; label = 'Database error'; }
  else if (st.disk_low) { tone = 'error'; label = 'Low disk'; }
  else if (st.fts_migration?.last_error) { tone = 'warn'; label = 'Migration paused'; }
  else if (st.db_bytes === undefined) { tone = 'unknown'; label = 'Unknown'; }
  const { card, body } = pipelineCard('Storage (SQLite cache)', tone, label);
  if (status.database_error) kvBlock(card, 'Database error', status.database_error, 'error');
  kvRow(body, 'Database size', formatBytes(st.db_bytes));
  const walTone = Number(st.wal_bytes) > 64 * 1024 * 1024 && Number(st.wal_bytes) > Number(st.db_bytes) * 0.25 ? 'warn' : '';
  kvRow(body, 'WAL size', formatBytes(st.wal_bytes), walTone);
  kvRow(body, 'Reusable free space in file', formatBytes(st.free_page_bytes));
  if (st.disk_free_bytes !== undefined) {
    const pct = st.disk_total_bytes ? ` (${Math.round((st.disk_free_bytes / st.disk_total_bytes) * 100)}%)` : '';
    kvRow(body, 'Volume free', `${formatBytes(st.disk_free_bytes)} of ${formatBytes(st.disk_total_bytes)}${pct}`, st.disk_low ? 'error' : '');
  } else {
    kvRow(body, 'Volume free', 'unknown', 'unknown');
  }
  kvRow(body, 'Journal mode', st.journal_mode);
  const layouts = { external: 'Current', migrating: 'Migrating from an older layout', '': 'Unavailable (substring search)' };
  kvRow(body, 'Search index', st.fts_layout !== undefined ? (layouts[st.fts_layout] || st.fts_layout) : '—',
    st.fts_layout === 'migrating' ? 'info' : '');
  if (st.fts_migration) {
    kvRow(body, 'Index migration', `${formatCount(st.fts_migration.rows_remaining)} rows remaining`, 'info');
    if (st.fts_migration.last_error) kvBlock(card, 'Index migration error (retrying)', st.fts_migration.last_error, 'warn');
  }
  if (st.disk_low) {
    kvBlock(card, 'Low disk', 'Less than 256 MiB or 5% free on the database volume. Writes fail when it fills: ingest stops advancing (nothing is skipped) until space is freed.', 'error');
  }
  return { card, tone };
}

function renderNotificationsCard(status) {
  const n = status.notifications;
  if (!n) return null;
  let tone = 'ok';
  let label = 'Delivering';
  if (n.status_error) { tone = 'unknown'; label = 'Unknown'; }
  else if (!n.enabled) { tone = 'unknown'; label = 'Off'; }
  else if (!n.configured) { tone = 'error'; label = 'Webhook missing'; }
  else if (!n.running) { tone = 'error'; label = 'Not running'; }
  else if (n.last_problem?.status === 'failed') { tone = 'warn'; label = 'Some failed'; }
  else if (n.last_problem) { tone = 'warn'; label = 'Retrying'; }
  const { card, body } = pipelineCard('Mattermost notifications', tone, label);
  if (!n.enabled) {
    kvRow(body, 'Status', 'Disabled in configuration (webapp.mattermost.enabled)');
    return { card, tone: 'ok' }; // off by choice is not a fault
  }
  if (!n.configured) {
    kvRow(body, 'Status', 'Enabled, but the webhook URL environment variable is empty or not an http(s) URL; nothing is sent', 'error');
  }
  kvRow(body, 'Minimum urgency', n.min_urgency);
  kvRow(body, 'Investigation links', n.links ? 'included' : 'not included (link_base_url not set)', n.links ? '' : 'info');
  const c = n.counts || {};
  kvRow(body, 'Sent / pending / failed', `${c.sent || 0} / ${c.pending || 0} / ${c.failed || 0}`, c.failed ? 'warn' : '');
  kvRow(body, 'Suppressed recurrences', String(c.suppressed || 0));
  kvRow(body, 'Last sent', n.last_sent_at ? describeAge(n.last_sent_at) : 'never');
  kvRow(body, 'Last check', n.last_run_at ? describeAge(n.last_run_at) : 'not yet');
  if (n.last_run_error) kvBlock(card, 'Last run error', n.last_run_error, 'warn');
  if (n.last_problem) {
    const p = n.last_problem;
    kvBlock(card, `Delivery problem (anomaly #${p.anomaly_id}, ${p.status}, ${p.attempts} attempts${p.last_attempt_at ? `, ${describeAge(p.last_attempt_at)}` : ''})`,
      p.last_error || '', p.status === 'failed' ? 'warn' : 'info');
  }
  return { card, tone };
}

function pipelineOverall(status) {
  if (!status) return 'unknown';
  const ingestTone = (INGEST_STATES[status.ingest?.state] || ['unknown'])[0];
  const tones = [ingestTone];
  if (status.database_error || status.storage?.disk_low) tones.push('error');
  const ins = status.insights;
  if (ins?.enabled && (!ins.running || ins.consecutive_failures > 0)) tones.push('error');
  const n = status.notifications;
  if (n?.enabled && (!n.configured || !n.running)) tones.push('error');
  return worstTone(...tones);
}

function updatePipelineBadge() {
  const badge = el('pipelineBadge');
  const fetchAge = state.pipeline.fetchedAt ? Date.now() - state.pipeline.fetchedAt : Infinity;
  const tone = state.lastStatus ? pipelineOverall(state.lastStatus) : 'unknown';
  const show = tone === 'error' || tone === 'warn' || Boolean(state.pipeline.error) || fetchAge > BACKGROUND_STATUS_REFRESH_MS * 2;
  badge.hidden = !show;
  badge.textContent = '!';
  badge.title = state.pipeline.error ? 'Status could not be loaded' : `Pipeline ${tone}`;
}

function renderPipeline() {
  const content = el('pipelineContent');
  const banner = el('pipelineBanner');
  const status = state.lastStatus;
  const fetchedAt = state.pipeline.fetchedAt;
  const fetchAge = fetchedAt ? Date.now() - fetchedAt : null;
  const stale = fetchAge === null || fetchAge > STATUS_STALE_MS;

  el('pipelineFetched').textContent = state.pipeline.loading
    ? 'Checking…'
    : fetchedAt
      ? `Checked ${formatDuration(fetchAge / 1000)} ago · refreshes every ${PIPELINE_REFRESH_MS / 1000}s while open`
      : 'Not checked yet';

  if (!status) {
    content.innerHTML = '';
    banner.hidden = false;
    banner.className = `pipeline-banner tone-${state.pipeline.error ? 'error' : 'unknown'}`;
    banner.textContent = state.pipeline.error
      ? `Status unavailable: ${state.pipeline.error}`
      : 'Loading pipeline status…';
    return;
  }

  content.innerHTML = '';
  const cards = [renderIngestCard(status), renderInsightsCard(status), renderStorageCard(status)];
  const notifications = renderNotificationsCard(status);
  if (notifications) cards.push(notifications);
  for (const c of cards) content.appendChild(c.card);

  const overall = worstTone(...cards.map((c) => c.tone));
  const problems = [];
  if (state.pipeline.error) problems.push(`the last refresh failed (${state.pipeline.error}); showing data from ${formatDuration(fetchAge / 1000)} ago`);
  else if (stale) problems.push(`this data is ${formatDuration(fetchAge / 1000)} old`);
  const tone = problems.length ? worstTone(overall, 'warn') : overall;
  const summary = {
    ok: 'All pipeline stages report healthy.',
    info: 'Pipeline healthy; see the notes below.',
    unknown: 'Some stages have not reported yet — not confirmed healthy.',
    warn: 'Pipeline running with warnings.',
    error: 'Pipeline problem: see the red items below.',
  }[overall];
  banner.hidden = false;
  banner.className = `pipeline-banner tone-${tone}`;
  banner.textContent = problems.length ? `${summary} Note: ${problems.join('; ')}.` : summary;
}

async function refreshStatus() {
  const requestId = ++state.pipeline.requestId;
  state.pipeline.loading = true;
  if (state.activeTab === 'pipeline') renderPipeline();
  try {
    const status = await fetchJson('/api/status');
    if (requestId !== state.pipeline.requestId) return status;
    state.lastStatus = status;
    state.pipeline.fetchedAt = Date.now();
    state.pipeline.error = '';
    updateHealthFromStatus(status);
    return status;
  } catch (err) {
    if (requestId === state.pipeline.requestId) state.pipeline.error = err.message;
    throw err;
  } finally {
    if (requestId === state.pipeline.requestId) {
      state.pipeline.loading = false;
      if (state.activeTab === 'pipeline') renderPipeline();
      updatePipelineBadge();
    }
  }
}

function startPipelinePolling() {
  stopPipelinePolling();
  const fresh = state.pipeline.fetchedAt && Date.now() - state.pipeline.fetchedAt < 10000;
  if (fresh) renderPipeline();
  else refreshStatus().catch(() => {});
  state.pipeline.timer = window.setInterval(() => {
    if (document.hidden) return; // no polling in a background browser tab
    refreshStatus().catch(() => {});
  }, PIPELINE_REFRESH_MS);
}

function stopPipelinePolling() {
  if (state.pipeline.timer) window.clearInterval(state.pipeline.timer);
  state.pipeline.timer = null;
}

// Keeps the header and the Pipeline badge roughly current without the
// Pipeline tab open; /api/status counts rows, so this stays infrequent.
function startBackgroundStatusRefresh() {
  if (state.pipeline.backgroundTimer) return;
  state.pipeline.backgroundTimer = window.setInterval(() => {
    if (document.hidden || state.activeTab === 'pipeline') return;
    refreshStatus().catch(() => {});
  }, BACKGROUND_STATUS_REFRESH_MS);
}

el('refreshPipeline').addEventListener('click', () => {
  refreshStatus().catch(() => {});
});

// ─── Shareable URL state ─────────────────────────────────────────────────────
// The address bar holds the investigation: tab, filters, time range and the
// selected entry or anomaly, so a copied link reopens the same view. Only
// identifiers and the operator's own filter values are stored, never log
// content. The URL is the single persisted source (no local storage); it is
// applied on load and on back/forward. Navigations (tab, applied filters,
// drilldowns, opening context) add a history entry; refinements (context
// size, expanding an anomaly) replace the current one.
//
//   tab     dashboard | insights | actionable | pipeline   (logs when absent)
//   scope, ns, pod, ctr, sev, q                             filters
//   xscope, xns, xpod, xctr, xsev   values left out, comma-separated
//   range   1h | 6h | 24h | 7d | all   (today when absent; relative to "now")
//   from, to   ISO-8601 UTC, [from, to) — an exact range (either may be absent)
//   rec     log entry id whose context is open (Logs)
//   ctx     10 | 25 | 50 lines each side;  ctxall=1: context ignores the range
//   anomaly anomaly id (expanded in Insights, or investigated in Actionable)
//   line    log entry id investigated in Actionable
//   view    open saved view id (its filters are the ones above; a difference
//           marks the view as modified)

const URL_RANGES = ['today', '1h', '6h', '24h', '7d', 'all'];
const URL_FILTERS = [
  ['scope', 'scope', 100],
  ['ns', 'namespace', 253],
  ['pod', 'pod', 253],
  ['ctr', 'container', 253],
  ['sev', 'severity_bucket', 64],
];
const URL_EXCLUDE_MAX_LENGTH = { scope: 100, namespace: 253, pod: 253, container: 253, severity_bucket: 64 };
const URL_ID_RE = /^\d{1,15}$/;

function cleanParam(value, maxLength) {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  if (!text || text.length > maxLength || /[\u0000-\u001f\u007f]/.test(text)) return '';
  return text;
}

function cleanTime(value) {
  const text = cleanParam(value, 40);
  if (!text) return '';
  const date = new Date(text);
  const ms = date.getTime();
  if (!Number.isFinite(ms) || date.getUTCFullYear() < 2000 || date.getUTCFullYear() > 2100) return '';
  return date.toISOString();
}

function cleanId(value) {
  const text = cleanParam(value, 15);
  return URL_ID_RE.test(text) ? Number(text) : null;
}

function parseUrlState(search) {
  let params;
  try {
    params = new URLSearchParams(search);
  } catch (_) {
    params = new URLSearchParams();
  }
  const out = { tab: 'logs', filters: {}, exclude: {}, q: '', range: null, from: '', to: '', rec: null, ctx: 10, ctxAll: false, anomaly: null, line: null, view: null };
  const tab = params.get('tab');
  if (TABS.includes(tab)) out.tab = tab;
  for (const [key, field, max] of URL_FILTERS) {
    const value = cleanParam(params.get(key), max);
    if (value) out.filters[field] = value;
  }
  for (const [field, param] of FILTER_EXCLUDES) {
    const raw = params.get(param);
    const values = typeof raw === 'string' && raw.length <= 20000 ? raw.split(',') : [];
    const kept = values.map((v) => cleanParam(v, URL_EXCLUDE_MAX_LENGTH[field])).filter(Boolean);
    out.exclude[field] = Array.from(new Set(kept)).slice(0, FIELD_EXCLUDE_MAX);
  }
  out.q = cleanParam(params.get('q'), 500);
  const range = params.get('range');
  if (URL_RANGES.includes(range)) out.range = range;
  out.from = cleanTime(params.get('from'));
  out.to = cleanTime(params.get('to'));
  if (out.from && out.to && out.to <= out.from) out.to = ''; // inverted: keep the start only
  if (out.from || out.to) out.range = null; // an explicit range wins
  out.rec = cleanId(params.get('rec'));
  const ctx = Number(params.get('ctx'));
  if (CONTEXT_LINE_CHOICES.includes(ctx)) out.ctx = ctx;
  out.ctxAll = params.get('ctxall') === '1';
  out.anomaly = cleanId(params.get('anomaly'));
  out.line = cleanId(params.get('line'));
  out.view = cleanId(params.get('view'));
  return out;
}

function buildUrlParams() {
  const params = new URLSearchParams();
  if (state.activeTab !== 'logs') params.set('tab', state.activeTab);
  for (const [key, field] of URL_FILTERS) {
    const value = el(field).value.trim();
    if (value) params.set(key, value);
  }
  for (const [field, param] of FILTER_EXCLUDES) {
    if (state.exclude[field].length) params.set(param, state.exclude[field].join(','));
  }
  const q = el('q').value.trim();
  if (q) params.set('q', q);
  const preset = el('rangePreset').value;
  if (!state.rangeExact && URL_RANGES.includes(preset)) {
    if (preset !== 'today') params.set('range', preset);
  } else {
    const range = currentRange();
    if (range.start) params.set('from', range.start);
    if (range.before) params.set('to', range.before);
    if (!range.start && !range.before) params.set('range', 'all');
  }
  if (state.views.currentId !== null) params.set('view', String(state.views.currentId));
  if (state.activeTab === 'logs' && state.context.recordId !== null) {
    params.set('rec', String(state.context.recordId));
    if (state.context.lines !== 10) params.set('ctx', String(state.context.lines));
    if (!state.context.limitToRange) params.set('ctxall', '1');
  }
  if ((state.activeTab === 'insights' || state.activeTab === 'actionable') && state.focusAnomalyId !== null
    && (state.activeTab === 'insights' || state.actionable.sourceType === 'anomaly')) {
    params.set('anomaly', String(state.focusAnomalyId));
  }
  if (state.activeTab === 'actionable' && state.actionable.sourceType === 'line' && state.actionable.lineItem) {
    params.set('line', String(state.actionable.lineItem.id));
  }
  return params;
}

function updateUrl(mode = 'replace') {
  if (!state.urlApplying) renderViewBar();
  if (!mode || state.urlApplying) return;
  const qs = buildUrlParams().toString();
  const next = `${window.location.pathname}${qs ? `?${qs}` : ''}`;
  if (next === `${window.location.pathname}${window.location.search}`) return;
  try {
    if (mode === 'push') window.history.pushState(null, '', next);
    else window.history.replaceState(null, '', next);
  } catch (_) {
    // e.g. too many history updates; the view still works without the URL.
  }
}

// Sets a <select>, adding the value as an option when the cached facets do
// not list it (e.g. a namespace from a shared link that has aged out).
function setSelectValue(select, value) {
  if (!value) {
    select.value = '';
    return;
  }
  const exists = Array.from(select.options).some((opt) => opt.value === value);
  if (!exists) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = `${value} (not in cached facets)`;
    select.appendChild(opt);
  }
  select.value = value;
}

async function fetchLogEntry(id) {
  const params = new URLSearchParams({ id: String(id), lines_before: '0', lines_after: '0' });
  const data = await fetchJson(`/api/logs/context?${params.toString()}`);
  return data.anchor;
}

// Apply a parsed URL to the page: filters, range, tab, then the selected
// entry / anomaly. Adds a history entry only with history: 'push' (opening
// a saved view); otherwise it replaces the current one.
async function applyUrlState(parsed, { history = 'replace' } = {}) {
  state.urlApplying = true;
  try {
    state.views.currentId = parsed.view;
    if (state.views.loaded && !currentView()) state.views.currentId = null; // deleted since
    for (const field of ['scope', 'namespace', 'severity_bucket']) {
      setSelectValue(el(field), parsed.filters[field] || '');
    }
    el('pod').value = parsed.filters.pod || '';
    el('container').value = parsed.filters.container || '';
    for (const [field] of FILTER_EXCLUDES) state.exclude[field] = [...(parsed.exclude[field] || [])];
    forgetHistogramZoom();
    el('q').value = parsed.q || '';
    if (parsed.from || parsed.to) {
      setExactRange(parsed.from, parsed.to);
    } else {
      const preset = parsed.range || 'today';
      el('rangePreset').value = preset;
      RANGE_PRESETS[preset].apply();
    }
    state.context.lines = parsed.ctx;
    state.context.limitToRange = !parsed.ctxAll;
    state.focusAnomalyId = parsed.anomaly;
    syncFiltersFromUi();
    resetOlderLogsState();
    if (parsed.tab !== 'logs' || parsed.rec === null) closeContext({ history: null });
    switchTab(parsed.tab, { history: null });
    await loadLogs(true);
    if (parsed.tab === 'logs' && parsed.rec !== null) openContext(parsed.rec, { history: null });
    if (parsed.anomaly !== null && (parsed.tab === 'insights' || parsed.tab === 'actionable')) {
      await focusAnomaly(parsed.anomaly, { openInActionable: parsed.tab === 'actionable' });
    } else if (parsed.tab === 'actionable' && parsed.line !== null) {
      try {
        const same = state.actionable.sourceType === 'line' && Number(state.actionable.lineItem?.id) === parsed.line;
        if (!same) openLineInActionable(await fetchLogEntry(parsed.line), { history: null });
      } catch (err) {
        el('actionableContextDesc').textContent = `Log entry #${parsed.line} from the link is unavailable: ${err.message}`;
      }
    }
  } finally {
    state.urlApplying = false;
  }
  // Normalise the address bar (drops invalid or redundant parameters).
  updateUrl(history);
}

window.addEventListener('popstate', () => {
  applyUrlState(parseUrlState(window.location.search)).catch((err) => {
    el('health').textContent = err.message;
  });
});

el('copyLinkBtn').addEventListener('click', () => {
  updateUrl('replace');
  copyToClipboard(window.location.href, el('copyLinkBtn'));
});

// ─── Saved views ─────────────────────────────────────────────────────────────
// Named filter sets stored server-side (/api/views) in the URL's own keys.
// A relative range (range=1h) stays relative, so a view reopens relative to
// now; only an absolute range is stored as from/to. Opening a view applies
// it like a link and adds view=<id> to the URL.

const VIEW_FILTER_KEYS = ['scope', 'ns', 'pod', 'ctr', 'sev', 'q', 'qmode', 'xscope', 'xns', 'xpod', 'xctr', 'xsev', 'range', 'from', 'to'];
const VIEW_EXCLUDE_KEYS = new Set(FILTER_EXCLUDES.map(([, param]) => param));
// URL key -> API parameter (exclusion keys are the same in both).
const VIEW_API_PARAMS = { scope: 'scope', ns: 'namespace', pod: 'pod', ctr: 'container', sev: 'severity_bucket', q: 'q', qmode: 'qmode' };
const PINNED_CARDS_MAX = 12;
const PINNED_COUNTS_TTL_MS = 60000;

function currentView() {
  return state.views.list.find((view) => view.id === state.views.currentId) || null;
}

// The filters on screen, in the URL form a view stores.
function currentViewFilters() {
  const params = buildUrlParams();
  const out = {};
  for (const key of VIEW_FILTER_KEYS) {
    const value = params.get(key);
    if (value) out[key] = value;
  }
  return out;
}

// Comparable form: fixed key order, exclusion lists order-insensitive.
function viewFiltersKey(filters) {
  return JSON.stringify(VIEW_FILTER_KEYS.filter((key) => filters?.[key]).map((key) => {
    const value = String(filters[key]);
    return [key, VIEW_EXCLUDE_KEYS.has(key) ? value.split(',').sort().join(',') : value];
  }));
}

function viewRequest(method, url, payload) {
  const options = { method };
  if (payload !== undefined) {
    options.headers = { 'Content-Type': 'application/json' };
    options.body = JSON.stringify(payload);
  }
  return fetchJson(url, options);
}

// Never rejects: a failure is shown in the Views menu.
async function loadViews() {
  try {
    const data = await fetchJson('/api/views');
    state.views.list = Array.isArray(data.views) ? data.views : [];
    state.views.loaded = true;
    state.views.error = '';
  } catch (err) {
    state.views.error = `Could not load saved views: ${err.message}`;
  }
  state.views.countsAt = 0; // filters or pins may have changed
  if (state.views.loaded && state.views.currentId !== null && !currentView()) {
    state.views.currentId = null;
    updateUrl('replace');
  }
  renderViews();
  loadPinnedCounts();
}

function renderViews() {
  el('viewsCount').textContent = state.views.loaded ? `(${state.views.list.length})` : '';
  renderViewBar();
  renderViewsMenu();
  renderPinnedViews();
}

function renderViewBar() {
  const view = currentView();
  el('viewBar').hidden = !view;
  if (!view) return;
  el('viewBarName').textContent = view.name;
  el('viewBar').title = view.description || view.name;
  const modified = viewFiltersKey(currentViewFilters()) !== viewFiltersKey(view.filters);
  el('viewModifiedDot').hidden = !modified;
  el('viewRevertBtn').hidden = !modified;
  el('viewUpdateBtn').hidden = !modified;
}

function renderViewsMenu() {
  const errorBox = el('viewsError');
  errorBox.hidden = !state.views.error;
  errorBox.textContent = state.views.error;
  const list = el('viewsList');
  const search = state.views.search.trim().toLowerCase();
  const all = state.views.list;
  const shown = all.filter((view) => !search
    || view.name.toLowerCase().includes(search)
    || (view.description || '').toLowerCase().includes(search));
  if (!shown.length) {
    const text = all.length ? 'No views match.' : 'No saved views yet. Set filters, then “Save view”.';
    list.innerHTML = `<div class="views-empty">${escapeHtml(text)}</div>`;
    return;
  }
  list.innerHTML = shown.map((view) => {
    const index = all.indexOf(view);
    // Reorder within the pinned / unpinned group; not while filtering the list.
    const canUp = !search && index > 0 && all[index - 1].pinned === view.pinned;
    const canDown = !search && index < all.length - 1 && all[index + 1].pinned === view.pinned;
    const id = Number(view.id);
    const name = escapeHtml(view.name);
    const description = view.description ? escapeHtml(view.description) : '';
    const pinLabel = view.pinned ? 'Unpin from the dashboard' : 'Pin to the dashboard';
    return `<div class="view-item${id === state.views.currentId ? ' current' : ''}" data-view-id="${id}">
      <button type="button" class="view-item-open" data-view-action="open" title="${description || name}">
        <span class="view-item-name">${name}</span>
        ${description ? `<span class="view-item-desc">${description}</span>` : ''}
      </button>
      <button type="button" class="view-item-btn${view.pinned ? ' pinned' : ''}" data-view-action="pin" aria-pressed="${view.pinned ? 'true' : 'false'}" title="${pinLabel}" aria-label="${pinLabel}: ${name}">${view.pinned ? '★' : '☆'}</button>
      <button type="button" class="view-item-btn" data-view-action="up" title="Move up" aria-label="Move ${name} up"${canUp ? '' : ' disabled'}>↑</button>
      <button type="button" class="view-item-btn" data-view-action="down" title="Move down" aria-label="Move ${name} down"${canDown ? '' : ' disabled'}>↓</button>
      <button type="button" class="view-item-btn" data-view-action="edit" title="Rename or edit" aria-label="Rename ${name}">✎</button>
      <button type="button" class="view-item-btn" data-view-action="delete" title="Delete" aria-label="Delete ${name}">✕</button>
    </div>`;
  }).join('');
}

function showViewsError(err) {
  state.views.error = err instanceof Error ? err.message : String(err);
  renderViewsMenu();
}

// One mutation at a time; the list is reloaded afterwards (server order).
async function runViewChange(change) {
  if (state.views.busy) return;
  state.views.busy = true;
  try {
    await change();
    state.views.error = '';
  } catch (err) {
    showViewsError(err);
  } finally {
    state.views.busy = false;
    await loadViews();
  }
}

async function openView(view, { tab = state.activeTab } = {}) {
  const params = new URLSearchParams(view.filters || {});
  if (tab !== 'logs') params.set('tab', tab);
  params.set('view', String(view.id));
  await applyUrlState(parseUrlState(params.toString()), { history: 'push' });
  viewRequest('POST', `/api/views/${Number(view.id)}/use`).then((data) => {
    if (data?.view) view.last_used_at = data.view.last_used_at;
  }).catch(() => {});
}

function moveView(view, delta) {
  const group = state.views.list.filter((item) => item.pinned === view.pinned);
  const from = group.indexOf(view);
  const to = from + delta;
  if (from < 0 || to < 0 || to >= group.length) return Promise.resolve();
  group.splice(from, 1);
  group.splice(to, 0, view);
  return runViewChange(async () => {
    for (const [order, item] of group.entries()) {
      if (item.sort_order !== order) await viewRequest('PATCH', `/api/views/${Number(item.id)}`, { sort_order: order });
    }
  });
}

function setViewsMenuOpen(open) {
  el('viewsMenu').hidden = !open;
  el('viewsMenuBtn').setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) {
    renderViewsMenu();
    el('viewsSearch').focus();
  }
}

// mode 'save': save the current filters (update the open view, or a new
// one); 'edit': rename / describe / pin `view` without touching its filters.
function openSaveViewDialog(mode, view = null) {
  const target = mode === 'edit' ? view : currentView();
  state.views.dialog = { mode, viewId: target ? target.id : null };
  el('saveViewTitle').textContent = mode === 'edit' ? 'Edit view' : 'Save view';
  el('saveViewName').value = target?.name || '';
  el('saveViewDescription').value = target?.description || '';
  el('saveViewPinned').checked = Boolean(target?.pinned);
  el('saveViewSubmit').textContent = mode === 'save' && target ? 'Update' : 'Save';
  el('saveViewSubmit').title = mode === 'save' && target ? 'Save the current filters into the open view' : '';
  el('saveViewAsNew').hidden = !(mode === 'save' && target);
  el('saveViewError').hidden = true;
  el('saveViewModal').showModal();
  el('saveViewName').focus();
  el('saveViewName').select();
}

async function submitSaveView(asNew) {
  const dialog = state.views.dialog;
  if (!dialog || state.views.busy) return;
  const body = {
    name: el('saveViewName').value.trim(),
    description: el('saveViewDescription').value.trim(),
    pinned: el('saveViewPinned').checked,
  };
  if (dialog.mode === 'save') body.filters = currentViewFilters();
  const errorBox = el('saveViewError');
  if (!body.name) {
    errorBox.textContent = 'Enter a name.';
    errorBox.hidden = false;
    return;
  }
  state.views.busy = true;
  try {
    let saved;
    if (asNew || dialog.viewId === null) {
      saved = (await viewRequest('POST', '/api/views', body)).view;
    } else {
      saved = (await viewRequest('PATCH', `/api/views/${Number(dialog.viewId)}`, body)).view;
    }
    el('saveViewModal').close();
    state.views.dialog = null;
    if (dialog.mode === 'save' && saved) {
      state.views.currentId = saved.id;
      updateUrl('replace');
    }
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.hidden = false;
    return;
  } finally {
    state.views.busy = false;
  }
  await loadViews();
}

function openDeleteViewDialog(view) {
  state.views.dialog = { mode: 'delete', viewId: view.id };
  el('deleteViewText').textContent = `Delete the saved view “${view.name}”? This cannot be undone.`;
  el('deleteViewModal').showModal();
}

// ── Dashboard strip: pinned views with their last-hour counts ──

function viewApiParams(filters, extra = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters || {})) {
    if (VIEW_API_PARAMS[key]) params.set(VIEW_API_PARAMS[key], value);
    else if (VIEW_EXCLUDE_KEYS.has(key)) params.set(key, value);
  }
  for (const [key, value] of Object.entries(extra)) params.set(key, value);
  return params;
}

function renderPinnedViews() {
  const pinned = state.views.list.filter((view) => view.pinned);
  el('pinnedViews').hidden = !pinned.length;
  if (!pinned.length) {
    el('pinnedViewsCards').innerHTML = '';
    return;
  }
  const cards = pinned.slice(0, PINNED_CARDS_MAX).map((view) => {
    const counts = state.views.counts.get(view.id);
    let body;
    if (!counts) {
      body = '<span>…</span>';
    } else if (counts.error) {
      body = `<span class="pinned-view-note">Counts unavailable: ${escapeHtml(counts.error)}</span>`;
    } else {
      body = `<span>${formatCount(counts.total)} logs</span><span class="pinned-view-errors">${formatCount(counts.errors)} errors</span>`;
    }
    const title = view.description ? `${view.description}\n\nOpen in Logs` : 'Open in Logs';
    return `<button type="button" class="pinned-view-card" data-pinned-view-id="${Number(view.id)}" title="${escapeHtml(title)}">
      <span class="pinned-view-name">${escapeHtml(view.name)}</span>
      <span class="pinned-view-counts">${body}</span>
    </button>`;
  });
  if (pinned.length > PINNED_CARDS_MAX) {
    cards.push(`<div class="pinned-view-note">${pinned.length - PINNED_CARDS_MAX} more pinned views in the Views menu</div>`);
  }
  el('pinnedViewsCards').innerHTML = cards.join('');
}

// Last-hour total and error count per pinned card (the view's own range is
// not used). Only while the dashboard is shown; never rejects.
async function loadPinnedCounts({ force = false } = {}) {
  if (state.activeTab !== 'dashboard' || !state.views.loaded) return;
  if (!force && state.views.countsAt && Date.now() - state.views.countsAt < PINNED_COUNTS_TTL_MS) return;
  state.views.countsAt = Date.now();
  const requestId = ++state.views.countsRequestId;
  const pinned = state.views.list.filter((view) => view.pinned).slice(0, PINNED_CARDS_MAX);
  if (!pinned.length) return;
  const start = new Date(Date.now() - HOUR_MS).toISOString();
  const results = await Promise.allSettled(pinned.map((view) => (
    fetchJson(`/api/histogram?${viewApiParams(view.filters, { start }).toString()}`)
  )));
  if (requestId !== state.views.countsRequestId) return;
  const counts = new Map();
  pinned.forEach((view, index) => {
    const result = results[index];
    if (result.status !== 'fulfilled') {
      counts.set(view.id, { error: result.reason?.message || 'request failed' });
      return;
    }
    const buckets = Array.isArray(result.value?.buckets) ? result.value.buckets : [];
    counts.set(view.id, {
      total: buckets.reduce((sum, bucket) => sum + Number(bucket.total || 0), 0),
      errors: buckets.reduce((sum, bucket) => sum + Number(bucket.error || 0), 0),
    });
  });
  state.views.counts = counts;
  renderPinnedViews();
}

el('saveViewBtn').addEventListener('click', () => openSaveViewDialog('save'));
el('viewsMenuBtn').addEventListener('click', () => setViewsMenuOpen(el('viewsMenu').hidden));
el('viewsSearch').addEventListener('input', () => {
  state.views.search = el('viewsSearch').value;
  renderViewsMenu();
});
el('viewsList').addEventListener('click', (event) => {
  const button = event.target instanceof Element ? event.target.closest('[data-view-action]') : null;
  if (!(button instanceof HTMLButtonElement) || button.disabled) return;
  const id = Number(button.closest('[data-view-id]')?.dataset.viewId);
  const view = state.views.list.find((item) => item.id === id);
  if (!view) return;
  const action = button.dataset.viewAction;
  if (action === 'open') {
    setViewsMenuOpen(false);
    openView(view).catch(showViewsError);
  } else if (action === 'pin') {
    runViewChange(() => viewRequest('PATCH', `/api/views/${id}`, { pinned: !view.pinned }));
  } else if (action === 'up' || action === 'down') {
    moveView(view, action === 'up' ? -1 : 1);
  } else if (action === 'edit') {
    openSaveViewDialog('edit', view);
  } else if (action === 'delete') {
    openDeleteViewDialog(view);
  }
});
document.addEventListener('click', (event) => {
  if (el('viewsMenu').hidden || !(event.target instanceof Node)) return;
  if (el('viewsMenu').contains(event.target) || el('viewsMenuBtn').contains(event.target)) return;
  if (el('saveViewModal').open || el('deleteViewModal').open) return;
  setViewsMenuOpen(false);
});
window.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape' || el('viewsMenu').hidden) return;
  if (el('saveViewModal').open || el('deleteViewModal').open) return;
  setViewsMenuOpen(false);
  el('viewsMenuBtn').focus();
});
// Typing in the filters marks the open view as modified right away.
for (const type of ['input', 'change']) {
  document.querySelector('.filters').addEventListener(type, (event) => {
    if (event.target instanceof Element && !event.target.closest('#viewsMenu')) renderViewBar();
  });
}
el('viewRevertBtn').addEventListener('click', () => {
  const view = currentView();
  if (view) openView(view).catch(showViewsError);
});
el('viewUpdateBtn').addEventListener('click', () => {
  const view = currentView();
  if (view) runViewChange(() => viewRequest('PATCH', `/api/views/${Number(view.id)}`, { filters: currentViewFilters() }));
});
el('viewCloseBtn').addEventListener('click', () => {
  state.views.currentId = null;
  updateUrl('replace');
  renderViews();
});
el('saveViewSubmit').addEventListener('click', () => submitSaveView(false));
el('saveViewAsNew').addEventListener('click', () => submitSaveView(true));
el('saveViewModal').querySelector('form').addEventListener('submit', (event) => {
  event.preventDefault(); // Enter in the name field
  submitSaveView(false);
});
el('saveViewCancel').addEventListener('click', () => {
  el('saveViewModal').close();
  state.views.dialog = null;
});
el('deleteViewCancel').addEventListener('click', () => {
  el('deleteViewModal').close();
  state.views.dialog = null;
});
el('deleteViewConfirm').addEventListener('click', () => {
  const dialog = state.views.dialog;
  el('deleteViewModal').close();
  state.views.dialog = null;
  if (!dialog || dialog.mode !== 'delete') return;
  runViewChange(async () => {
    await viewRequest('DELETE', `/api/views/${Number(dialog.viewId)}`);
    if (state.views.currentId === dialog.viewId) {
      state.views.currentId = null;
      updateUrl('replace');
    }
  });
});
el('pinnedViewsCards').addEventListener('click', (event) => {
  const card = event.target instanceof Element ? event.target.closest('[data-pinned-view-id]') : null;
  if (!(card instanceof HTMLElement)) return;
  const view = state.views.list.find((item) => item.id === Number(card.dataset.pinnedViewId));
  if (view) {
    openView(view, { tab: 'logs' }).catch((err) => {
      el('health').textContent = err.message;
    });
  }
});

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
  ensureOlderLogsClosed();
  setDefaultDateRange();
  buildCombobox('pod', 'pod');
  buildCombobox('container', 'container');
  const parsed = parseUrlState(window.location.search);
  let status = null;
  try {
    status = await refreshStatus();
  } catch (err) {
    // The logs still load; the Pipeline tab shows the status as unavailable.
    el('health').textContent = `Status unavailable: ${err.message}`;
  }
  if (status) {
    state.aiConfigured = Boolean(status.ai_configured);
    state.actionsEnabled = status.actions_enabled === true;
    if (status.last_successful_ingest_at) {
      el('freshness').textContent = fmtFreshness(status.last_successful_ingest_at);
    } else if (status.latest_record_timestamp) {
      el('freshness').textContent = `Cached through ${formatTimestamp(status.latest_record_timestamp)}`;
    }
  }
  updateExplainButton();
  await loadFacets();
  // Facets first, so values from the link select existing options.
  await applyUrlState(parsed);
  loadViews();
  startTailPolling();
  startBackgroundStatusRefresh();
  if (!state.insightsLoaded && !state.insightsLoading) loadInsights().catch(() => { });
}

// ─── Event listeners ─────────────────────────────────────────────────────────

// Applying filters is a navigation: one history entry, results view shown.
function reloadLogs() {
  syncFiltersFromUi();
  resetOlderLogsState();
  closeContext({ history: null });
  updateUrl('push');
  return loadLogs(true).catch((err) => showLogsError(`Could not load logs: ${err.message}`));
}

el('apply').addEventListener('click', () => reloadLogs());
// Typing an End time makes the range end there (no longer "now"). Editing
// either bound drops exact bounds from a link or drilldown.
el('end').addEventListener('change', () => {
  forgetHistogramZoom();
  state.endIsLive = !el('end').value;
  state.rangeExact = null;
  el('rangePreset').value = 'custom';
});
el('start').addEventListener('change', () => {
  forgetHistogramZoom();
  if (state.rangeExact) {
    state.endIsLive = !state.rangeExact.before;
    state.rangeExact = null;
  }
  el('rangePreset').value = 'custom';
});
el('loadMore').addEventListener('click', () => {
  openOlderLogsOverlay(true);
});

const olderLogsLoadMore = el('olderLogsLoadMore');
if (olderLogsLoadMore) {
  olderLogsLoadMore.addEventListener('click', () => {
    loadOlderLogsPage().catch((err) => {
      el('health').textContent = err.message;
    });
  });
}

const olderLogsClose = el('olderLogsClose');
if (olderLogsClose) {
  olderLogsClose.addEventListener('click', (event) => {
    event.stopPropagation();
    closeOlderLogsOverlay();
  });
}

const olderLogsOverlay = el('olderLogsOverlay');
if (olderLogsOverlay) {
  olderLogsOverlay.addEventListener('click', (event) => {
    if (event.target === olderLogsOverlay) {
      handleOlderOverlayOutsideClick(event);
    }
  });
}

window.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (state.olderOverlayOpen) {
    closeOlderLogsOverlay();
  } else if (state.context.recordId !== null && state.activeTab === 'logs'
    && !el('actionConfirmModal').open && !(event.target instanceof HTMLInputElement)) {
    closeContext();
  }
});
el('todayShortcut').addEventListener('click', () => {
  forgetHistogramZoom();
  el('rangePreset').value = 'today';
  setDefaultDateRange();
  reloadLogs();
});
el('clearFilters').addEventListener('click', () => {
  el('scope').value = '';
  el('namespace').value = '';
  el('pod').value = '';
  el('container').value = '';
  el('severity_bucket').value = '';
  for (const [field] of FILTER_EXCLUDES) state.exclude[field] = [];
  forgetHistogramZoom();
  el('q').value = '';
  el('rangePreset').value = 'today';
  setDefaultDateRange();
  reloadLogs();
});
el('securityShortcut').addEventListener('click', () => {
  el('scope').value = 'security';
  reloadLogs();
});
el('rangePreset').addEventListener('change', () => {
  const preset = RANGE_PRESETS[el('rangePreset').value];
  if (!preset) return;
  forgetHistogramZoom();
  preset.apply();
  reloadLogs();
});
el('groupByRule').addEventListener('change', async () => {
  state.groupByRule = el('groupByRule').checked;
  state.expandedGroups.clear();
  renderAll();
});
el('refreshInsights').addEventListener('click', () => {
  loadInsights().catch((err) => showInsightsError(err.message));
});
el('insightsStatusFilter').addEventListener('change', () => {
  loadInsights().catch((err) => showInsightsError(err.message));
});
el('refreshDashboard').addEventListener('click', () => {
  loadDashboard().catch((err) => {
    el('health').textContent = err.message;
  });
  loadPinnedCounts({ force: true });
});
document.addEventListener('click', async (event) => {
  const target = event.target;
  const dashboardAction = target instanceof HTMLElement ? target.closest('[data-dashboard-action]') : null;
  if (dashboardAction instanceof HTMLElement) {
    event.preventDefault();
    if (dashboardAction instanceof HTMLButtonElement && dashboardAction.disabled) return;
    const action = dashboardAction.dataset.dashboardAction || '';
    const value = dashboardAction.dataset.dashboardValue || '';
    const severity = dashboardAction.dataset.dashboardSeverity || '';
    drillDownFromDashboard(action, value, severity).catch((err) => {
      el('health').textContent = err.message;
    });
    return;
  }
  if (target instanceof HTMLElement && target.id === 'loadLatestCached') {
    const latest = state.lastStatus?.latest_record_timestamp;
    if (!latest) return;
    const latestDate = new Date(latest);
    if (!Number.isFinite(latestDate.getTime())) return;
    const start = new Date(latestDate);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1); // exclusive: up to the next local midnight
    forgetHistogramZoom();
    setExactRange(start.toISOString(), end.toISOString()); // a fixed past day
    reloadLogs();
  }
});
el('fieldSidebarToggle').addEventListener('click', () => {
  const collapsed = el('logsBody').classList.toggle('fields-collapsed');
  const toggle = el('fieldSidebarToggle');
  toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  toggle.textContent = collapsed ? '›' : '‹';
  toggle.title = collapsed ? 'Show fields' : 'Hide fields';
  toggle.setAttribute('aria-label', toggle.title);
  el('fieldSidebarBody').hidden = collapsed;
});
el('fieldList').addEventListener('mousedown', (event) => {
  if (event.shiftKey) event.preventDefault(); // no text selection on Shift-click
});
el('fieldList').addEventListener('click', (event) => {
  const target = event.target instanceof Element ? event.target : null;
  const chip = target?.closest('[data-field-unexclude]');
  if (chip instanceof HTMLElement) {
    const field = chip.dataset.fieldUnexclude;
    if (!state.exclude[field]) return;
    state.exclude[field] = state.exclude[field].filter((v) => v !== chip.dataset.value);
    reloadLogs();
    return;
  }
  const button = target?.closest('[data-field][data-value]');
  if (!(button instanceof HTMLElement) || !state.exclude[button.dataset.field]) return;
  event.preventDefault();
  applyFieldValue(button.dataset.field, button.dataset.value ?? '', event.altKey || event.shiftKey);
});
el('histogramBars').addEventListener('pointerdown', (event) => {
  if (event.button !== 0) return;
  const index = histogramIndexAt(event.clientX);
  if (index === null) return;
  event.preventDefault();
  el('histogramBars').setPointerCapture(event.pointerId);
  state.logPanels.drag = { from: index, to: index };
  markHistogramSelection();
});
el('histogramBars').addEventListener('pointermove', (event) => {
  const index = histogramIndexAt(event.clientX);
  if (index === null) return;
  const drag = state.logPanels.drag;
  if (drag && drag.to !== index) {
    drag.to = index;
    markHistogramSelection();
  }
  showHistogramTooltip(index, event.clientX);
});
el('histogramBars').addEventListener('pointerup', () => {
  const drag = state.logPanels.drag;
  if (!drag) return;
  state.logPanels.drag = null;
  markHistogramSelection();
  applyHistogramSelection(drag.from, drag.to);
});
el('histogramBars').addEventListener('pointercancel', () => {
  state.logPanels.drag = null;
  markHistogramSelection();
});
el('histogramBars').addEventListener('pointerleave', () => {
  if (!state.logPanels.drag) hideHistogramTooltip();
});
el('histogramReset').addEventListener('click', () => resetHistogramRange());
el('newRowsBanner').addEventListener('click', () => {
  el('newRowsBanner').classList.remove('show');
});
el('live').addEventListener('change', () => {
  if (el('live').checked) startTailPolling(); else stopTailPolling();
});
el('openInActionableBtn').addEventListener('click', () => {
  switchTab('actionable');
});

const actionableAnalyzeLogsBtn = el('actionableAnalyzeLogsBtn');
if (actionableAnalyzeLogsBtn) {
  actionableAnalyzeLogsBtn.addEventListener('click', async () => {
    await runExplain();
    switchTab('actionable');
  });
}

el('actionableRefreshBtn').addEventListener('click', async () => {
  const selVal = el('actionableSourceSelect').value;
  if (selVal && selVal.startsWith('anomaly-')) {
    const anomId = parseInt(selVal.replace('anomaly-', ''), 10);
    const anom = state.anomalies.find((a) => a.id === anomId);
    if (anom) openAnomalyInActionable(anom);
  } else {
    await runExplain();
    switchTab('actionable');
  }
});

init().catch((err) => {
  el('health').textContent = err.message;
});

el('actionableSourceSelect').addEventListener('change', () => {
  const selVal = el('actionableSourceSelect').value;
  if (selVal && selVal.startsWith('anomaly-')) {
    const anomId = parseInt(selVal.replace('anomaly-', ''), 10);
    const anom = state.anomalies.find((a) => a.id === anomId);
    if (anom) openAnomalyInActionable(anom);
  } else {
    state.actionable.sourceType = 'logs';
    state.actionable.anomalyId = null;
    renderActionableWorkspace();
  }
});

el('actionableRunNextBtn').addEventListener('click', () => {
  runNextActionableStep();
});

el('actionableResetStepsBtn').addEventListener('click', () => {
  resetActionableSteps();
});

el('confirmCancelBtn').addEventListener('click', () => {
  el('actionConfirmModal').close();
  state.actionable.pendingMutation = null;
});

el('confirmExecuteBtn').addEventListener('click', () => {
  el('actionConfirmModal').close();
  const pending = state.actionable.pendingMutation;
  if (pending) {
    state.actionable.pendingMutation = null;
    executeActionableStep(pending.key, pending);
  }
});