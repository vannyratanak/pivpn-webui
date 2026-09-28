const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '../..');
const SOURCE = fs.readFileSync(path.join(root, 'app/static/js/log-filter.js'), 'utf8');

// A small but functionally real DOM mock — unlike the other JS tests'
// stubs, sorting genuinely depends on appendChild actually reordering
// nodes and classList actually tracking classes, so those can't be
// no-ops here the way they are in e.g. firewall.test.cjs.
function table() {
  const rows = []; // the "container"'s current child order
  function makeClassList(node) {
    return {
      add(...names) { names.forEach((n) => node._classes.add(n)); },
      remove(...names) { names.forEach((n) => node._classes.delete(n)); },
      contains(name) { return node._classes.has(name); },
    };
  }
  function makeRow(cellTexts) {
    const node = {
      _classes: new Set(), isConnected: true,
      children: cellTexts.map((text) => ({ textContent: text })),
      attrs: {},
      setAttribute(name, value) { this.attrs[name] = value; },
    };
    node.classList = makeClassList(node);
    return node;
  }
  function makeHeader(cellIndex) {
    const node = { _classes: new Set(), cellIndex, attrs: {}, listeners: {} };
    node.classList = makeClassList(node);
    node.setAttribute = function (name, value) { this.attrs[name] = value; };
    node.addEventListener = function (event, fn) { (this.listeners[event] ||= []).push(fn); };
    node.click = function () { (this.listeners.click || []).forEach((fn) => fn()); };
    return node;
  }
  const container = {
    querySelectorAll: () => rows.slice(),
    appendChild(row) {
      const at = rows.indexOf(row);
      if (at !== -1) rows.splice(at, 1);
      rows.push(row);
      row.isConnected = true;
    },
  };
  return { rows, container, makeRow, makeHeader };
}

// Wires up a real attachLogFilter() against the given container/headers,
// resolving the same way the browser would: getElementById/querySelector/
// querySelectorAll by the (fake) selector strings passed to it.
function attach(t, headers) {
  const searchInput = { addEventListener() {} }; // not under test here
  const document = {
    getElementById: () => searchInput,
    querySelector: () => t.container,
    querySelectorAll: () => headers,
  };
  const context = vm.createContext({ document });
  vm.runInContext(SOURCE, context);
  context.attachLogFilter('search-input', '.container', 'tr', 'th', null);
}

test('a sortable header cycles ascending -> descending -> back to original order', () => {
  const t = table();
  const rowB = t.makeRow(['b']);
  const rowA = t.makeRow(['a']);
  const rowC = t.makeRow(['c']);
  t.rows.push(rowB, rowA, rowC); // deliberately unsorted original order
  const nameHeader = t.makeHeader(0);
  attach(t, [nameHeader]);

  // Click 1: ascending
  nameHeader.click();
  assert.deepEqual(t.rows.map((r) => r.children[0].textContent), ['a', 'b', 'c']);
  assert.equal(nameHeader.attrs['aria-sort'], 'ascending');
  assert.equal(nameHeader.classList.contains('sort-asc'), true);

  // Click 2: descending
  nameHeader.click();
  assert.deepEqual(t.rows.map((r) => r.children[0].textContent), ['c', 'b', 'a']);
  assert.equal(nameHeader.attrs['aria-sort'], 'descending');
  assert.equal(nameHeader.classList.contains('sort-desc'), true);

  // Click 3: back to the original (pre-sort) order, not a third sort order
  nameHeader.click();
  assert.deepEqual(t.rows.map((r) => r.children[0].textContent), ['b', 'a', 'c']);
  assert.equal(nameHeader.attrs['aria-sort'], 'none');
  assert.equal(nameHeader.classList.contains('sort-asc'), false);
  assert.equal(nameHeader.classList.contains('sort-desc'), false);

  // Click 4: cycle repeats from ascending
  nameHeader.click();
  assert.deepEqual(t.rows.map((r) => r.children[0].textContent), ['a', 'b', 'c']);
  assert.equal(nameHeader.attrs['aria-sort'], 'ascending');
});

test('switching to a different header sorts by that one instead, from ascending', () => {
  const t = table();
  const rowB = t.makeRow(['b', '2']);
  const rowA = t.makeRow(['a', '1']);
  t.rows.push(rowB, rowA);
  const nameHeader = t.makeHeader(0);
  const numHeader = t.makeHeader(1);
  attach(t, [nameHeader, numHeader]);

  nameHeader.click(); // ascending by name: a, b
  assert.deepEqual(t.rows.map((r) => r.children[0].textContent), ['a', 'b']);

  numHeader.click(); // switch to the other column — starts fresh at ascending
  assert.deepEqual(t.rows.map((r) => r.children[1].textContent), ['1', '2']);
  assert.equal(numHeader.attrs['aria-sort'], 'ascending');
  // The previously-active header's own sort indicator is cleared.
  assert.equal(nameHeader.attrs['aria-sort'], 'none');
  assert.equal(nameHeader.classList.contains('sort-asc'), false);
});

test('a row removed before the third click is not resurrected on restore', () => {
  const t = table();
  const rowB = t.makeRow(['b']);
  const rowA = t.makeRow(['a']);
  t.rows.push(rowB, rowA);
  const nameHeader = t.makeHeader(0);
  attach(t, [nameHeader]);

  nameHeader.click(); // ascending — snapshot of [b, a] taken here

  // Simulate rowB being removed from the table (e.g. Clients' removeRow)
  // while "Name" is actively sorted.
  const at = t.rows.indexOf(rowB);
  t.rows.splice(at, 1);
  rowB.isConnected = false;

  nameHeader.click(); // descending
  nameHeader.click(); // back to "original" order — must skip the removed row

  assert.deepEqual(t.rows.map((r) => r.children[0].textContent), ['a']);
});
