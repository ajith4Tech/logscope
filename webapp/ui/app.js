const GROUP_WINDOW_MS = 5 * 60 * 1000; // collapse identical alerts within 5 minutes
const EXPLAIN_COOLDOWN_MS = 12000; // client-side cooldown after clicking Explain
const CURRENT_LOG_LIMIT = 7;
const OLDER_LOG_LIMIT = 50;

const state = {
  filters: { scope: '', namespace: '', pod: '', container: '', severity_bucket: '', q: '', start: '', end: '' },
  facets: {},
  items: [],
  nextCursor: null,
  hasMore: false,
  olderItems: [],
  olderCursor: null,
  olderHasMore: false,
  olderLoading: false,
  olderRequestId: 0,
  olderOverlayOpen: false,
  liveCursor: null,
  liveTimer: null,
  lastUpdatedAt: null,
  lastStatus: null,
  expandedRows: new Set(),
  expandedGroups: new Set(),
  groupByRule: false,
  aiConfigured: false,
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
    stepStates: new Map(), // stepIndex -> { status, stdout, stderr, exit_code, duration_ms, error }
    activeStepIndex: 0,
    runningIndex: null,
    pendingMutationAction: null,
  },
};

const el = (id) => document.getElementById(id);

// ─── Tab switching ───────────────────────────────────────────────────────────

function switchTab(name) {
  state.activeTab = name;
  const isLogs = name === 'logs';
  const isInsights = name === 'insights';
  const isActionable = name === 'actionable';

  el('tabLogs').classList.toggle('active', isLogs);
  el('tabInsights').classList.toggle('active', isInsights);
  el('tabActionable').classList.toggle('active', isActionable);

  el('tabLogs').setAttribute('aria-selected', isLogs ? 'true' : 'false');
  el('tabInsights').setAttribute('aria-selected', isInsights ? 'true' : 'false');
  el('tabActionable').setAttribute('aria-selected', isActionable ? 'true' : 'false');

  el('panelLogs').hidden = !isLogs;
  el('panelInsights').hidden = !isInsights;
  el('panelActionable').hidden = !isActionable;

  if (isInsights && !state.insightsLoaded && !state.insightsLoading) {
    loadInsights().catch(() => {});
  }
  if (isActionable) {
    updateActionableSourceOptions();
    renderActionableWorkspace();
  }
}

el('tabLogs').addEventListener('click', () => switchTab('logs'));
el('tabInsights').addEventListener('click', () => switchTab('insights'));
el('tabActionable').addEventListener('click', () => switchTab('actionable'));

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
}

function localValueToIso(value) {
  return value ? new Date(value).toISOString() : '';
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

function queryFromFilters(extra = {}) {
  const current = {
    scope: el('scope').value,
    namespace: el('namespace').value,
    pod: el('pod').value,
    container: el('container').value,
    severity_bucket: el('severity_bucket').value,
    q: el('q').value.trim(),
    start: localValueToIso(el('start').value),
    end: localValueToIso(el('end').value),
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
    .replaceAll('"', '&quot;');
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
  all: { label: 'All time', apply: () => { el('start').value = ''; el('end').value = ''; } },
};

function applyRelativeWindow(spanMs) {
  const now = new Date();
  const start = new Date(now.getTime() - spanMs);
  el('start').value = toDatetimeLocal(start);
  el('end').value = toDatetimeLocal(now);
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
    syncFiltersFromUi();
    loadLogs(true).catch((err) => { el('health').textContent = err.message; });
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
}

// Expandable detail: full (untruncated) message, raw_line, source_key,
// line_number, output_fields when present, and a per-line Explain action.
function detailMarkup(item, rowId) {
  const wrap = document.createElement('div');
  wrap.className = 'row-detail';
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
      } else {
        state.expandedAnomalies.add(anomalyId);
        detail.hidden = false;
        expandBtn.textContent = '▴';
        fillAnomalyDetail(detail.querySelector('.anomaly-detail-inner'), anomaly);
      }
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

async function loadInsights() {
  if (state.insightsLoading) return;

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

function setPlanFromExplainResult(result, sourceType, anomaly = null, lineItem = null) {
  state.actionable.sourceType = sourceType;
  state.actionable.anomalyId = anomaly ? anomaly.id : null;
  state.actionable.lineItem = lineItem;
  state.actionable.plan = {
    summary: result.summary || '',
    steps: result.steps || [],
    suggested_action: result.suggested_action || '',
    filters: result.filters || (sourceType === 'logs' ? queryFromFilters() : null),
    sample_count: result.sample_count,
    anomaly: anomaly,
    lineItem: lineItem,
  };
  state.actionable.stepStates.clear();
  renderActionableWorkspace();
}

function openAnomalyInActionable(anomaly) {
  state.actionable.sourceType = 'anomaly';
  state.actionable.anomalyId = anomaly.id;

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

  state.actionable.plan = {
    summary: anomaly.ai_summary || `Detected anomaly: ${anomaly.type} in ${anomaly.namespace || 'cluster'}`,
    steps: steps,
    suggested_action: anomaly.ai_suggested_action || '',
    evidence: anomaly.evidence,
    anomaly: anomaly,
  };
  state.actionable.stepStates.clear();
  switchTab('actionable');
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

  // Context Description
  if (state.actionable.sourceType === 'anomaly' && plan.anomaly) {
    const anom = plan.anomaly;
    descEl.textContent = `Investigating Anomaly #${anom.id}: ${anomalyTypeLabel(anom.type)} (${anom.namespace || 'cluster'})`;
    el('actionableSummaryTitle').textContent = `Anomaly Investigation: ${anomalyTypeLabel(anom.type)}`;
  } else if (state.actionable.sourceType === 'line') {
    descEl.textContent = 'Investigating single log record';
    el('actionableSummaryTitle').textContent = 'Log Record Investigation';
  } else {
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

  if (state.actionable.sourceType === 'anomaly' && plan.anomaly) {
    addTag(`type: ${plan.anomaly.type}`);
    if (plan.anomaly.namespace) addTag(`ns: ${plan.anomaly.namespace}`);
    if (plan.anomaly.pod) addTag(`pod: ${plan.anomaly.pod}`);
    if (plan.anomaly.severity) addTag(`sev: ${plan.anomaly.severity}`);
  } else if (plan.filters) {
    if (plan.filters.namespace) addTag(`ns: ${plan.filters.namespace}`);
    if (plan.filters.severity_bucket) addTag(`sev: ${plan.filters.severity_bucket}`);
    if (plan.sample_count) addTag(`sample: ${plan.sample_count} lines`);
  }
  const steps = plan.steps || [];
  addTag(`${steps.length} steps`);

  // Summary Text
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

  // Steps Rendering
  const stepsList = el('actionableStepsList');
  stepsList.innerHTML = '';

  let successCount = 0;

  steps.forEach((step, index) => {
    const stepState = state.actionable.stepStates.get(index) || { status: 'ready' };
    if (stepState.status === 'success') successCount++;

    const card = document.createElement('div');
    card.className = `troubleshoot-step-card ${stepState.status === 'running' ? 'active-step' : ''}`;

    // Header
    const head = document.createElement('div');
    head.className = 'step-card-header';

    const titleGroup = document.createElement('div');
    titleGroup.className = 'step-title-group';

    const indexBadge = document.createElement('span');
    indexBadge.className = 'step-index-badge';
    indexBadge.textContent = String(index + 1);
    titleGroup.appendChild(indexBadge);

    const titleText = document.createElement('span');
    titleText.textContent = step.title || `Step ${index + 1}`;
    titleGroup.appendChild(titleText);

    const badges = document.createElement('div');
    badges.className = 'step-badges';

    const risk = step.risk || 'read-only';
    const riskBadge = document.createElement('span');
    riskBadge.className = `badge-risk badge-risk-${risk}`;
    riskBadge.textContent = risk;

    const statusBadge = document.createElement('span');
    statusBadge.className = `badge-status badge-status-${stepState.status}`;
    const statusLabels = { ready: 'Ready', running: 'Running…', success: 'Success', failed: 'Failed' };
    statusBadge.textContent = statusLabels[stepState.status] || stepState.status;

    badges.appendChild(riskBadge);
    badges.appendChild(statusBadge);
    head.appendChild(titleGroup);
    head.appendChild(badges);
    card.appendChild(head);

    // Body
    const body = document.createElement('div');
    body.className = 'step-card-body';

    // Explanation
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

    // Command box
    if (step.command) {
      const cmdBox = document.createElement('div');
      cmdBox.className = 'step-command-box';

      const code = document.createElement('code');
      code.className = 'step-command-code';
      code.textContent = step.command;

      const tools = document.createElement('div');
      tools.className = 'step-command-tools';

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className = 'ghost';
      copyBtn.style.fontSize = '11px';
      copyBtn.style.padding = '3px 8px';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => copyToClipboard(step.command, copyBtn));

      const runBtn = document.createElement('button');
      runBtn.type = 'button';
      runBtn.className = `step-btn-run ${risk !== 'read-only' ? 'mutating' : ''}`;
      runBtn.disabled = stepState.status === 'running';

      if (stepState.status === 'running') {
        runBtn.textContent = 'Running…';
      } else if (stepState.status === 'success' || stepState.status === 'failed') {
        runBtn.textContent = 'Re-run';
      } else if (risk !== 'read-only') {
        runBtn.textContent = 'Confirm & Run';
      } else {
        runBtn.textContent = 'Run Step';
      }

      runBtn.addEventListener('click', () => executeActionableStep(index));

      tools.appendChild(copyBtn);
      tools.appendChild(runBtn);
      cmdBox.appendChild(code);
      cmdBox.appendChild(tools);
      body.appendChild(cmdBox);
    }

    // Output area
    if (stepState.status !== 'ready') {
      const outContainer = document.createElement('div');
      outContainer.className = 'step-output-container';

      const outHead = document.createElement('div');
      outHead.className = 'step-output-head';

      const outTitle = document.createElement('span');
      outTitle.textContent = stepState.command || step.command || 'Output';

      const outMeta = document.createElement('div');
      outMeta.className = 'step-output-meta';

      if (stepState.duration_ms !== undefined) {
        const duration = document.createElement('span');
        duration.textContent = `${stepState.duration_ms}ms`;
        outMeta.appendChild(duration);
      }
      if (stepState.exit_code !== undefined) {
        const exitCode = document.createElement('span');
        exitCode.style.color = stepState.exit_code === 0 ? 'var(--ai)' : 'var(--error)';
        exitCode.style.fontWeight = '600';
        exitCode.textContent = `Exit ${stepState.exit_code}`;
        outMeta.appendChild(exitCode);
      }

      outHead.appendChild(outTitle);
      outHead.appendChild(outMeta);
      outContainer.appendChild(outHead);

      const outBody = document.createElement('pre');
      outBody.className = 'step-output-body';

      if (stepState.status === 'running') {
        outBody.textContent = 'Executing Kubernetes diagnostic action…';
        outBody.classList.add('empty-output');
      } else {
        const text = [stepState.stdout, stepState.stderr, stepState.error].filter(Boolean).join('\n\n');
        if (text) {
          outBody.textContent = text;
          if (stepState.exit_code !== 0 || stepState.error) {
            outBody.classList.add('step-output-error');
          }
        } else {
          outBody.textContent = '(Command completed with no output)';
          outBody.classList.add('empty-output');
        }
      }

      outContainer.appendChild(outBody);
      body.appendChild(outContainer);
    }

    card.appendChild(body);
    stepsList.appendChild(card);
  });

  // Progress summary
  el('actionableStepsCount').textContent = `${successCount} of ${steps.length} steps completed`;
}

async function executeActionableStep(index, confirmed = false) {
  const plan = state.actionable.plan;
  if (!plan || !plan.steps || !plan.steps[index]) return;

  const step = plan.steps[index];
  const risk = step.risk || 'read-only';

  if (!confirmed && risk !== 'read-only') {
    state.actionable.pendingMutationIndex = index;
    el('confirmModalCommand').textContent = step.command || '(structured state-modifying action)';
    el('confirmModalText').textContent = `Step "${step.title}" is a mutating operation that may change cluster state. Do you want to proceed?`;
    el('actionConfirmModal').showModal();
    return;
  }

  state.actionable.stepStates.set(index, { status: 'running', command: step.command });
  renderActionableWorkspace();

  try {
    const payload = {
      command: step.command || '',
      action: step.action ? step.action.action : undefined,
      namespace: step.action ? step.action.namespace : undefined,
      resource: step.action ? step.action.resource : undefined,
      confirmed: confirmed,
    };

    const res = await fetchJson('/api/actions/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.requires_confirmation && !confirmed) {
      state.actionable.pendingMutationIndex = index;
      el('confirmModalCommand').textContent = res.command || step.command;
      el('confirmModalText').textContent = res.message || 'Explicit confirmation required.';
      el('actionConfirmModal').showModal();
      state.actionable.stepStates.set(index, { status: 'ready' });
      renderActionableWorkspace();
      return;
    }

    const success = Boolean(res.success);
    state.actionable.stepStates.set(index, {
      status: success ? 'success' : 'failed',
      exit_code: res.exit_code,
      stdout: res.stdout || '',
      stderr: res.stderr || '',
      duration_ms: res.duration_ms || 0,
      command: res.command || step.command,
    });
  } catch (err) {
    state.actionable.stepStates.set(index, {
      status: 'failed',
      exit_code: -1,
      stdout: '',
      stderr: '',
      error: `Execution error: ${err.message}`,
      duration_ms: 0,
      command: step.command,
    });
  }

  renderActionableWorkspace();
}

function runNextActionableStep() {
  const plan = state.actionable.plan;
  if (!plan || !plan.steps) return;
  for (let i = 0; i < plan.steps.length; i++) {
    const st = state.actionable.stepStates.get(i);
    if (!st || st.status !== 'success') {
      executeActionableStep(i);
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
  el('health').textContent = status.total_records
    ? `Cached ${status.total_records} rows from ${status.total_objects} objects`
    : 'Waiting for ingestion';
  if (!status.total_records && status.last_error) {
    el('health').textContent = `Ingestion error: ${status.last_error}`;
  }
}

function encodeCursor(item) {
  return btoa(JSON.stringify({ ts: item.timestamp, id: item.id })).replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_');
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

async function loadLogs(reset = true) {
  const requestId = ++state.logsRequestId;
  const params = new URLSearchParams(queryFromFilters({ limit: String(CURRENT_LOG_LIMIT) }));
  if (!reset && state.nextCursor) params.set('cursor', state.nextCursor);
  const data = await fetchJson(`/api/logs?${params.toString()}`);
  if (requestId !== state.logsRequestId) return;
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
  if (!el('health').textContent || !el('health').textContent.startsWith('Ingestion error')) {
    el('health').textContent = state.hasMore ? 'More older rows available' : 'End of current page';
  }
  if (reset && el('live').checked && state.items.length) state.liveCursor = encodeCursor(state.items[0]);
}

function flashNewRows(count) {
  const banner = el('newRowsBanner');
  el('newRowsCount').textContent = String(count);
  banner.classList.add('show');
  window.clearTimeout(flashNewRows.timer);
  flashNewRows.timer = window.setTimeout(() => banner.classList.remove('show'), 6000);
}

async function pollTail() {
  if (!el('live').checked || !state.liveCursor) return;
  const requestId = ++state.tailRequestId;
  const params = new URLSearchParams(queryFromFilters({ limit: '200', cursor: state.liveCursor }));
  const data = await fetchJson(`/api/tail?${params.toString()}`);
  if (requestId !== state.tailRequestId || !el('live').checked) return;
  if (data.items.length) {
    state.items = data.items.concat(state.items).slice(0, CURRENT_LOG_LIMIT);
    state.liveCursor = encodeCursor(data.items[data.items.length - 1]);
    state.expandedRows.clear();
    state.expandedGroups.clear();
    renderAll();
    flashNewRows(data.items.length);
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

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
  ensureOlderLogsClosed();
  setDefaultDateRange();
  buildCombobox('pod', 'pod');
  buildCombobox('container', 'container');
  const status = await fetchJson('/api/status');
  state.lastStatus = status;
  state.aiConfigured = Boolean(status.ai_configured);
  updateExplainButton();
  updateHealthFromStatus(status);
  if (status.last_successful_ingest_at) {
    el('freshness').textContent = fmtFreshness(status.last_successful_ingest_at);
  } else if (status.latest_record_timestamp) {
    el('freshness').textContent = `Cached through ${formatTimestamp(status.latest_record_timestamp)}`;
  }
  await loadFacets();
  await loadLogs(true);
  startTailPolling();
  loadInsights().catch(() => { });
}

// ─── Event listeners ─────────────────────────────────────────────────────────

el('apply').addEventListener('click', async () => {
  syncFiltersFromUi();
  resetOlderLogsState();
  await loadLogs(true);
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
  if (event.key === 'Escape' && state.olderOverlayOpen) {
    closeOlderLogsOverlay();
  }
});
el('todayShortcut').addEventListener('click', async () => {
  setDefaultDateRange();
  syncFiltersFromUi();
  resetOlderLogsState();
  await loadLogs(true);
});
el('clearFilters').addEventListener('click', async () => {
  el('scope').value = '';
  el('namespace').value = '';
  el('pod').value = '';
  el('container').value = '';
  el('severity_bucket').value = '';
  el('q').value = '';
  el('rangePreset').value = 'today';
  setDefaultDateRange();
  syncFiltersFromUi();
  resetOlderLogsState();
  await loadLogs(true);
});
el('securityShortcut').addEventListener('click', async () => {
  el('scope').value = 'security';
  syncFiltersFromUi();
  resetOlderLogsState();
  await loadLogs(true);
});
el('rangePreset').addEventListener('change', async () => {
  const preset = RANGE_PRESETS[el('rangePreset').value];
  if (!preset) return;
  preset.apply();
  syncFiltersFromUi();
  resetOlderLogsState();
  await loadLogs(true);
});
el('groupByRule').addEventListener('change', async () => {
  state.groupByRule = el('groupByRule').checked;
  state.expandedGroups.clear();
  renderAll();
});
el('refreshInsights').addEventListener('click', async () => {
  await loadInsights();
});
el('insightsStatusFilter').addEventListener('change', async () => {
  await loadInsights();
});
document.addEventListener('click', async (event) => {
  const target = event.target;
  if (target instanceof HTMLElement && target.id === 'loadLatestCached') {
    const latest = state.lastStatus?.latest_record_timestamp;
    if (!latest) return;
    const latestDate = new Date(latest);
    const start = new Date(latestDate);
    start.setHours(0, 0, 0, 0);
    const end = new Date(latestDate);
    end.setHours(23, 59, 59, 999);
    const pad = (value) => String(value).padStart(2, '0');
    el('start').value = `${start.getFullYear()}-${pad(start.getMonth() + 1)}-${pad(start.getDate())}T00:00`;
    el('end').value = `${end.getFullYear()}-${pad(end.getMonth() + 1)}-${pad(end.getDate())}T23:59`;
    syncFiltersFromUi();
    resetOlderLogsState();
    await loadLogs(true);
  }
});
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
  state.actionable.pendingMutationIndex = null;
});

el('confirmExecuteBtn').addEventListener('click', () => {
  el('actionConfirmModal').close();
  const idx = state.actionable.pendingMutationIndex;
  if (idx !== null && idx !== undefined) {
    state.actionable.pendingMutationIndex = null;
    executeActionableStep(idx, true);
  }
});

init().catch((err) => {
  el('health').textContent = err.message;
});