"""The action confirm dialog: every way out except "Execute" (Cancel, Esc,
a click on the backdrop) drops the pending mutation, so a stale confirmation
can never run later. Runs app.js under node with a minimal DOM stand-in."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const elements = new Map();
const listeners = new Map();  // id -> { type: [fn] }
function makeEl(id) {
  const base = { id, value: '', checked: false, hidden: false, disabled: false, textContent: '', innerHTML: '',
    title: '', className: '', options: [], style: {}, dataset: {}, children: [], open: false,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener(type, fn) {
      if (!listeners.has(id)) listeners.set(id, {});
      (listeners.get(id)[type] ||= []).push(fn);
    },
    showModal() { this.open = true; }, close() { this.open = false; } };
  return new Proxy(base, { get(t, p) { return p in t ? t[p] : (typeof p === 'string' ? () => makeEl('') : undefined); } });
}
const document = { getElementById(id) { if (!elements.has(id)) elements.set(id, makeEl(id)); return elements.get(id); },
  addEventListener() {}, querySelector() { return makeEl(''); }, querySelectorAll() { return []; },
  createElement() { return makeEl(''); }, body: makeEl('body'), documentElement: makeEl('html') };
const window = { location: { search: '', pathname: '/', href: 'http://x/' }, history: { pushState() {}, replaceState() {} },
  addEventListener() {}, setInterval() { return 0; }, clearInterval() {}, setTimeout() { return 0; }, clearTimeout() {},
  sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} }, matchMedia() { return { matches: false, addEventListener() {} }; },
  confirm() { return true; } };
const ctx = { document, window, console, URLSearchParams, Intl, Date, Math, JSON, Map, Set, Promise, Number, String,
  Array, Object, Error, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
  fetch: () => Promise.reject(new Error('offline')), HTMLElement: class {}, HTMLButtonElement: class {},
  HTMLInputElement: class {}, HTMLSelectElement: class {}, Element: class {}, Node: class {}, navigator: {},
  AbortController: class { abort() {} get signal() { return {}; } }, requestAnimationFrame() {}, ResizeObserver: class { observe() {} } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx);
const run = (code) => vm.runInContext(code, ctx);
const fire = (id, type, event) => (listeners.get(id)?.[type] || []).forEach((fn) => fn(event));
const modal = document.getElementById('actionConfirmModal');
const arm = () => { run(`state.actionable.pendingMutation = { key: 'plan:0', command: 'kubectl delete pod x' }`); modal.open = true; };
const pending = () => run('state.actionable.pendingMutation');
const out = {};

arm(); fire('actionConfirmModal', 'cancel', { target: modal });
out.esc = { pending: pending(), open: modal.open };
arm(); fire('actionConfirmModal', 'click', { target: modal });
out.backdrop = { pending: pending(), open: modal.open };
arm(); fire('actionConfirmModal', 'click', { target: document.getElementById('confirmModalCommand') });
out.insideClick = { pending: pending() !== null, open: modal.open };
fire('confirmCancelBtn', 'click', {});
out.cancel = { pending: pending(), open: modal.open };
// Execute hands the pending mutation on (actions are off here, so nothing runs) and clears it.
arm(); fire('confirmExecuteBtn', 'click', {});
out.execute = { pending: pending(), open: modal.open };
out.removed = { analyzeLogsBtn: !listeners.has('actionableAnalyzeLogsBtn'), filters: run("'filters' in state") };
run(`alertsState.channels = [{ id: 1, name: 'ops-hook' }, { id: 2, name: 'pager' }]`);
out.deliveries = run(`alertDeliveryMarkup({ id: 7, notified: 'retrying', attempts: 2, retryable: true, deliveries: [
  { channel_id: 1, state: 'sent', attempts: 1 },
  { channel_id: 2, state: 'retrying', attempts: 2, next_attempt_at: '2026-10-21T06:01:00.000Z', last_error: 'HTTP 503' }] })`);
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_confirm_dialog_esc_and_backdrop_clear_the_pending_mutation(tmp_path):
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS)
    proc = subprocess.run(["node", str(harness), str(ROOT / "webapp" / "ui" / "app.js")], capture_output=True,
                          text=True, timeout=60, env={**os.environ, "TZ": "UTC"})
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout)
    assert out["esc"] == {"pending": None, "open": False}
    assert out["backdrop"] == {"pending": None, "open": False}
    assert out["insideClick"] == {"pending": True, "open": True}   # a click inside the dialog keeps it
    assert out["cancel"] == {"pending": None, "open": False}
    assert out["execute"] == {"pending": None, "open": False}
    assert out["removed"] == {"analyzeLogsBtn": True, "filters": False}   # dead UI code is gone


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_alert_history_shows_delivery_per_channel(tmp_path):
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS)
    proc = subprocess.run(["node", str(harness), str(ROOT / "webapp" / "ui" / "app.js")], capture_output=True,
                          text=True, timeout=60, env={**os.environ, "TZ": "UTC"})
    assert proc.returncode == 0, proc.stderr[-2000:]
    html = json.loads(proc.stdout)["deliveries"]
    assert html.count("<li>") == 2
    sent, retrying = html.split("<li>")[1:]
    assert "ops-hook" in sent and "alert-delivery-sent" in sent and "attempt" not in sent
    assert "pager" in retrying and "alert-delivery-retrying" in retrying and "2 attempts" in retrying
    assert "HTTP 503" in retrying and ">next " in retrying
    assert 'data-event-id="7"' in html and "Retry now" in html
