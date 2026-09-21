const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function browser() {
  let now = 1000000;
  const listeners = {};
  const intervals = [];
  const stored = new Map();
  const requests = [];
  const nodes = [];
  const document = {
    querySelector(selector) {
      if (selector.includes('idle-timeout-minutes')) return { content: '1.5' };
      if (selector.includes('csrf-token')) return { content: 'csrf' };
      return null;
    },
    addEventListener(event, handler) { (listeners[event] ||= []).push(handler); },
    createElement() {
      const node = { textContent: '', setAttribute() {}, appendChild(child) { nodes.push(child); }, remove() { this.removed = true; } };
      return node;
    },
    body: { appendChild(node) { nodes.push(node); } },
  };
  const context = vm.createContext({
    document, Date: { now: () => now },
    window: { location: { href: '/clients' } },
    localStorage: { getItem: (key) => stored.get(key) || null, setItem: (key, value) => stored.set(key, value), removeItem: (key) => stored.delete(key) },
    setInterval(callback) { intervals.push(callback); },
    fetch(url) { requests.push(url); return Promise.resolve({ redirected: false, ok: true }); },
  });
  return {
    context, stored, requests, nodes,
    advance(ms) { now += ms; },
    tick() { intervals.forEach((f) => f()); },
    event(name) { (listeners[name] || []).forEach((f) => f()); },
    load(file) { vm.runInContext(fs.readFileSync(path.join(__dirname, '../../app/static/js', file), 'utf8'), context); },
  };
}

test('idle browser logs out and clears bearer credential after 90 seconds', () => {
  const b = browser();
  b.stored.set('pivpn_webui_api_token', 'token');
  b.load('idle-timeout.js');
  b.advance(90 * 1000);
  b.tick();
  assert.equal(b.context.window.location.href, '/logout');
  assert.equal(b.stored.has('pivpn_webui_api_token'), false);
  assert.deepEqual(b.requests, []);
});

test('activity extends idle deadline and sends heartbeat', () => {
  const b = browser();
  b.load('idle-timeout.js');
  b.advance(60 * 1000);
  b.event('keydown');
  b.tick();
  assert.deepEqual(b.requests, ['/account/heartbeat']);
  b.advance(31 * 1000);
  b.tick();
  assert.equal(b.context.window.location.href, '/clients');
});

test('first input after a suspended tab exceeded its deadline cannot revive it', () => {
  const b = browser();
  b.load('idle-timeout.js');
  b.advance(91 * 1000);
  b.event('mousemove');
  assert.equal(b.context.window.location.href, '/logout');
});

test('another tab activity keeps this tab alive', () => {
  const b = browser();
  b.load('idle-timeout.js');
  b.advance(80 * 1000);
  b.stored.set('pivpn_webui_last_activity', String(b.context.Date.now()));
  b.advance(11 * 1000);
  b.tick();
  assert.equal(b.context.window.location.href, '/clients');
});

test('logout warning follows actual activity and disappears when activity resumes', () => {
  const b = browser();
  b.load('idle-timeout.js');
  b.load('jwt-expiry-watcher.js');
  b.event('DOMContentLoaded');
  b.advance(80 * 1000);
  b.tick();
  const warning = b.nodes.find((node) => node.textContent.includes('10s'));
  assert.ok(warning);
  b.event('keydown');
  b.tick();
  assert.equal(warning.removed, true);
  assert.equal(b.context.window.location.href, '/clients');
});

test('a redirected token-mint request returns the browser to login', async () => {
  const b = browser();
  b.context.fetch = async () => ({ redirected: true, status: 200, ok: true });
  b.load('api-client.js');
  await assert.rejects(vm.runInContext("ApiClient.call('/api/clients')", b.context), /not authenticated/);
  assert.equal(b.context.window.location.href, '/login');
});
