const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../../app/static/js/client-detail-page.js'), 'utf8');
const functions = source.slice(source.indexOf('  function parseServerTs'), source.indexOf('  function renderDestChart'));

function render(sessions) {
  const container = { innerHTML: '' };
  const now = new Date(2026, 8, 25, 12).getTime();
  class Clock extends Date { static now() { return now; } }
  const context = vm.createContext({
    Date: Clock, document: { getElementById: () => container },
    RANGE_HOURS: { '7d': 168 }, activityRangeSelect: { value: '7d' },
    escapeHtml: String, sessions,
  });
  vm.runInContext(functions + '\nrenderSessionTimeline(sessions);', context);
  return container.innerHTML;
}

function ts(day, hour) {
  return new Date(2026, 8, day, hour).toISOString().slice(0, 19).replace('T', ' ');
}

test('multi-day sessions split at midnight and duplicate intervals do not inflate totals', () => {
  const session = { start: ts(23, 18), end: ts(25, 9), ongoing: false };
  const html = render([session, session]);
  assert.match(html, /6h 0m/);
  assert.match(html, /24h 0m/);
  assert.match(html, /9h 0m/);
  assert.doesNotMatch(html, /39h|48h|78h/);
});

test('unmatched and restart-interrupted connections do not count outage time', () => {
  const html = render([
    { start: ts(23, 18), end: null, ongoing: true },
    { start: ts(23, 18), end: null, ongoing: false, status_note: 'Interrupted' },
    { start: ts(23, 18), end: ts(25, 9), ongoing: false, duration_note: 'Clock changed' },
  ]);
  assert.match(html, /No completed sessions/);
  assert.doesNotMatch(html, /dest-chart-bar/);
});
