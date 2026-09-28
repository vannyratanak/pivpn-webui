const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '../..');
const settle = () => new Promise(setImmediate);

function page() {
  const handlers = new Map();
  const make = () => ({
    style: {}, dataset: {}, checked: false,
    classList: { contains: () => false },
    querySelectorAll: () => [],
    addEventListener(event, fn) { const key = this; const events = handlers.get(key) || {}; (events[event] ||= []).push(fn); handlers.set(key, events); },
    dispatchEvent(event) { (handlers.get(this)?.[event.type] || []).forEach((fn) => fn(event)); },
    setAttribute() {}, appendChild() {}, remove() {}, close() { this.closed = true; }, reset() {},
  });
  const ids = new Map();
  const get = (id) => { if (!ids.has(id)) ids.set(id, make()); return ids.get(id); };
  const forms = Object.fromEntries(['resync', 'persist', 'import'].map((name) => [name, make()]));
  const checkbox = make();
  checkbox.dataset.ruleId = '7';
  checkbox.closest = () => ({ style: {} });
  const document = make();
  document.getElementById = get;
  document.createElement = make;
  document.body = make();
  document.querySelector = (selector) => Object.entries(forms).find(([name]) => selector.includes(`/firewall/${name}`))?.[1] || null;
  document.querySelectorAll = (selector) => selector.includes('.rule-select-checkbox') ? [checkbox] : [];
  const requests = [];
  const confirmations = [];
  const window = { askConfirm: (...args) => confirmations.push(args) };
  const context = vm.createContext({
    document, window, Event: class { constructor(type) { this.type = type; } },
    FormData: class { constructor(form) { this.form = form; } },
    ApiClient: { async call(url, options) { requests.push({ url, options }); return { ok: true, json: async () => url.endsWith('/rules') ? { rules: [] } : { changed: 1, added: 1, errors: [] } }; } },
    attachPagination: () => ({ refresh() {} }), attachSelectFilter: () => ({ refresh() {} }),
    attachLogFilter() {}, attachFirewallReorder() {}, setTimeout() {},
  });
  vm.runInContext(fs.readFileSync(path.join(root, 'app/static/js/firewall-page.js'), 'utf8'), context);
  const html = fs.readFileSync(path.join(root, 'app/templates/firewall.html'), 'utf8');
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  vm.runInContext(scripts.at(-1)[1], context);
  document.dispatchEvent({ type: 'DOMContentLoaded' });
  return { get, forms, requests, confirmations, checkbox, submit(form) {
    const event = { type: 'submit', preventDefault() { this.defaultPrevented = true; } };
    form.dispatchEvent(event);
    assert.equal(event.defaultPrevented, true, 'native form navigation must be suppressed');
  } };
}

test('rules table does not wire up column sorting (divider rows would get stranded)', () => {
  // This table's rows are grouped under kind-divider-row section headers
  // (FORWARD/INPUT/NAT/...) — attachLogFilter's column sort moves matched
  // rows via appendChild with no idea dividers exist, permanently
  // stranding every one of them at the top the first time any column is
  // sorted (reproduced live: the grouping never recovers, even via its
  // own "3rd click, back to unsorted" reset, without a full page reload).
  // A source check, not a behavioral one: the existing DOM mock here
  // stubs querySelectorAll/appendChild as no-ops, so it can't actually
  // exercise the real sort-vs-divider interaction either way.
  const source = fs.readFileSync(path.join(root, 'app/static/js/firewall-page.js'), 'utf8');
  const call = source.match(/attachLogFilter\('rules-filter',[^)]*\)/s)[0];
  assert.match(call, /,\s*null\s*,/, 'rules table must pass no headerSelector to attachLogFilter');
});

test('Apply, Save, and Import use the API without a native form post', async () => {
  const p = page();
  await settle();
  for (const action of ['resync', 'persist', 'import']) {
    p.submit(p.forms[action]);
    await settle();
    const request = p.requests.find((r) => r.url === `/api/firewall/${action}`);
    assert.equal(request.options.method, 'POST');
    if (action === 'import') {
      assert.equal(request.options.body.form, p.forms.import);
      assert.equal(p.get('import-rules-dialog').closed, true);
    }
  }
});

test('bulk deletion waits for confirmation and sends the selected IDs as JSON', async () => {
  const p = page();
  await settle();
  p.checkbox.checked = true;
  p.submit(p.get('bulk-delete-form'));
  assert.equal(p.requests.some((r) => r.url.endsWith('bulk-delete')), false);
  assert.equal(p.confirmations.length, 1);
  assert.match(p.confirmations[0][0], /Delete 1/);
  p.confirmations[0][2]();
  await settle();
  const request = p.requests.find((r) => r.url.endsWith('bulk-delete'));
  assert.deepEqual(JSON.parse(request.options.body), { rule_ids: ['7'] });
});

test('bulk disable posts selected IDs through the API', async () => {
  const p = page();
  await settle();
  p.checkbox.checked = true;
  p.submit(p.get('bulk-disable-form'));
  await settle();
  const request = p.requests.find((r) => r.url.endsWith('bulk-disable'));
  assert.deepEqual(JSON.parse(request.options.body), { rule_ids: ['7'] });
});
