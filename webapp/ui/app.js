const GROUP_WINDOW_MS = 5 * 60 * 1000; // collapse identical alerts within 5 minutes

const state = {
  filters: { scope: '', namespace: '', pod: '', container: '', severity_bucket: '', q: '', start: '', end: '' },
  facets: {},
  items: [],
  nextCursor: null,
  hasMore: false,
  liveCursor: null,
  liveTimer: null,
  lastUpdatedAt: null,
  lastStatus: null,
  expandedRows: new Set(),
  expandedGroups: new Set(),
  groupByRule: false,
};

const el = (id) => document.getElementById(id);

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

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function optionList(items) {
  return ['<option value="">All</option>'].concat(items.map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.value)} (${item.count})</option>`)).join('');
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
      parts.push(`<button type="button" class="combobox-option${selected}" data-value="${escapeHtml(item.value)}">${escapeHtml(item.value)} <span class="combobox-count">${item.count}</span></button>`);
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
  // ruleKeyOf strips embedded per-event Falco timestamps so identical alerts
  // collapse even when their raw messages differ only by event time.
  const message = ruleKeyOf(item);
  return [item.severity_bucket, item.namespace, item.pod, item.container, message].join('|');
}

// items arrive newest-first; identical keys within GROUP_WINDOW_MS merge,
// except in "group by rule" mode where matching rules aggregate across the
// whole result set (no window).
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

// Expandable detail: full (untruncated) message, raw_line, source_key,
// line_number, and output_fields when the backend provides them.
function detailMarkup(item) {
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
  for (const group of buildGroups(items)) {
    const representative = group.items[0];
    collapsed += group.items.length - 1;
    const node = rowMarkup(representative);
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
        node.appendChild(timestampsMarkup(group));
      }
    }
    const rowId = String(representative.id);
    node.dataset.rowId = rowId;
    if (state.expandedRows.has(rowId)) {
      node.classList.add('expanded');
      node.appendChild(detailMarkup(representative));
    }
    node.addEventListener('click', () => {
      if (group.items.length > 1 && !state.expandedRows.has(rowId)) {
        const key = node.dataset.groupKey;
        if (state.expandedGroups.has(key)) state.expandedGroups.delete(key);
        else state.expandedGroups.add(key);
      }
      if (state.expandedRows.has(rowId)) state.expandedRows.delete(rowId);
      else state.expandedRows.add(rowId);
      renderAll();
    });
    rows.appendChild(node);
  }
  const total = append ? state.items.length : items.length;
  const groupedNote = collapsed > 0 ? ` · ${collapsed} collapsed` : '';
  el('resultSummary').textContent = `${total} visible lines${groupedNote}`;
}

function renderAll() {
  renderRows(state.items, false);
}

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

async function loadLogs(reset = true) {
  const params = new URLSearchParams(queryFromFilters({ limit: '200' }));
  if (!reset && state.nextCursor) params.set('cursor', state.nextCursor);
  const data = await fetchJson(`/api/logs?${params.toString()}`);
  state.nextCursor = data.next_cursor;
  state.hasMore = Boolean(data.has_more);
  state.lastUpdatedAt = data.last_updated_at;
  if (reset) state.items = data.items; else state.items = state.items.concat(data.items);
  state.expandedRows.clear();
  state.expandedGroups.clear();
  renderAll();
  el('freshness').textContent = fmtFreshness(state.lastUpdatedAt);
  const loadMore = el('loadMore');
  loadMore.disabled = !state.hasMore;
  loadMore.textContent = state.hasMore ? 'Load older' : 'End of results';
  if (!el('health').textContent || !el('health').textContent.startsWith('Ingestion error')) {
    el('health').textContent = data.has_more ? 'More rows available' : 'End of current page';
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
  const params = new URLSearchParams(queryFromFilters({ limit: '200', cursor: state.liveCursor }));
  const data = await fetchJson(`/api/tail?${params.toString()}`);
  if (data.items.length) {
    state.items = data.items.concat(state.items);
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
}

async function init() {
  setDefaultDateRange();
  buildCombobox('pod', 'pod');
  buildCombobox('container', 'container');
  const status = await fetchJson('/api/status');
  state.lastStatus = status;
  updateHealthFromStatus(status);
  if (status.last_successful_ingest_at) {
    el('freshness').textContent = fmtFreshness(status.last_successful_ingest_at);
  } else if (status.latest_record_timestamp) {
    el('freshness').textContent = `Cached through ${formatTimestamp(status.latest_record_timestamp)}`;
  }
  await loadFacets();
  await loadLogs(true);
  startTailPolling();
}

el('apply').addEventListener('click', async () => {
  syncFiltersFromUi();
  await loadLogs(true);
});
el('loadMore').addEventListener('click', async () => {
  await loadLogs(false);
});
el('todayShortcut').addEventListener('click', async () => {
  setDefaultDateRange();
  syncFiltersFromUi();
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
  await loadLogs(true);
});
el('securityShortcut').addEventListener('click', async () => {
  el('scope').value = 'security';
  syncFiltersFromUi();
  await loadLogs(true);
});
el('rangePreset').addEventListener('change', async () => {
  const preset = RANGE_PRESETS[el('rangePreset').value];
  if (!preset) return;
  preset.apply();
  syncFiltersFromUi();
  await loadLogs(true);
});
el('groupByRule').addEventListener('change', async () => {
  state.groupByRule = el('groupByRule').checked;
  state.expandedGroups.clear();
  renderAll();
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
    await loadLogs(true);
  }
});
el('newRowsBanner').addEventListener('click', () => {
  el('newRowsBanner').classList.remove('show');
});
el('live').addEventListener('change', () => {
  if (el('live').checked) startTailPolling(); else stopTailPolling();
});

init().catch((err) => {
  el('health').textContent = err.message;
});