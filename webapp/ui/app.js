const state = {
  filters: { scope: '', namespace: '', pod: '', container: '', severity_bucket: '', q: '', start: '', end: '' },
  facets: {},
  items: [],
  nextCursor: null,
  liveCursor: null,
  liveTimer: null,
  lastUpdatedAt: null,
  lastStatus: null,
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
  el('pod').innerHTML = optionList(facets.pod || []);
  el('container').innerHTML = optionList(facets.container || []);
  el('severity_bucket').innerHTML = optionList(facets.severity_bucket || []);
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
  messageButton.title = 'Click to view full message';
  messageButton.addEventListener('click', (event) => {
    event.stopPropagation();
    openMessageDialog(item);
  });
  node.addEventListener('click', () => openMessageDialog(item));
  return node;
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
  for (const item of items) rows.appendChild(rowMarkup(item));
  const total = append ? state.items.length : items.length;
  el('resultSummary').textContent = `${total} visible lines`;
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

function openMessageDialog(item) {
  const dialog = el('messageDialog');
  el('dialogTitle').textContent = `${item.timestamp} · ${item.namespace}/${item.pod}`;
  el('dialogBody').textContent = item.message;
  el('dialogMeta').textContent = `${item.scope} · ${item.severity_bucket} · ${item.container} · source id ${item.id}`;
  if (typeof dialog.showModal === 'function') {
    dialog.showModal();
  } else {
    alert(item.message);
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
  state.lastUpdatedAt = data.last_updated_at;
  if (reset) state.items = data.items; else state.items = state.items.concat(data.items);
  renderRows(data.items, !reset);
  el('freshness').textContent = fmtFreshness(state.lastUpdatedAt);
  if (!el('health').textContent || !el('health').textContent.startsWith('Ingestion error')) {
    el('health').textContent = data.has_more ? 'More rows available' : 'End of current page';
  }
  if (reset && el('live').checked && state.items.length) state.liveCursor = encodeCursor(state.items[0]);
}

async function pollTail() {
  if (!el('live').checked || !state.liveCursor) return;
  const params = new URLSearchParams(queryFromFilters({ limit: '200', cursor: state.liveCursor }));
  const data = await fetchJson(`/api/tail?${params.toString()}`);
  if (data.items.length) {
    state.items = data.items.concat(state.items);
    const rows = el('rows');
    for (const item of data.items.slice().reverse()) rows.prepend(rowMarkup(item));
    state.liveCursor = encodeCursor(data.items[data.items.length - 1]);
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
  setDefaultDateRange();
  syncFiltersFromUi();
  await loadLogs(true);
});
el('securityShortcut').addEventListener('click', async () => {
  el('scope').value = 'security';
  syncFiltersFromUi();
  await loadLogs(true);
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
el('messageDialog').addEventListener('click', (event) => {
  const rect = el('messageDialog').getBoundingClientRect();
  const clickedInPanel = rect.top <= event.clientY && event.clientY <= rect.bottom && rect.left <= event.clientX && event.clientX <= rect.right;
  if (!clickedInPanel) el('messageDialog').close();
});
el('live').addEventListener('change', () => {
  if (el('live').checked) startTailPolling(); else stopTailPolling();
});

init().catch((err) => {
  el('health').textContent = err.message;
});