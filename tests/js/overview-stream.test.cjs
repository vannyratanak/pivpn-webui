const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function harness() {
  const timers = new Map(), events = [], states = [], readers = [];
  let nextTimer = 0, calls = 0;
  const context = {
    window: {}, AbortController, TextDecoder, JSON, Math,
    setTimeout(fn, delay) { timers.set(++nextTimer, {fn, delay}); return nextTimer; },
    clearTimeout(id) { timers.delete(id); },
    ApiClient: {async call(url, {signal}) {
      assert.equal(url, '/api/overview/events');
      calls++;
      let ctrl;
      const body = new ReadableStream({ start(controller) { ctrl = controller; } });
      readers.push(ctrl);
      signal.addEventListener('abort', () => { try {ctrl.close();} catch {} });
      return new Response(body, {headers:{'content-type':'text/event-stream'}});
    }},
  };
  vm.runInNewContext(fs.readFileSync('app/static/js/overview-stream.js','utf8'), context);
  const stream = context.window.OverviewStream((event,data) => events.push([event,data]), state => states.push(state));
  return {stream, events, states, timers, readers, calls:()=>calls,
    send(text) {readers.at(-1).enqueue(new TextEncoder().encode(text));},
    fire(predicate) {
      const entry = [...timers].find(([,t])=>predicate(t.delay));
      assert(entry, 'Expected timer'); timers.delete(entry[0]); entry[1].fn();
    },
  };
}
const settle = async () => {for (let i=0;i<20;i++) await Promise.resolve();};

test('Overview stream parses fragmented frames and ignores heartbeat comments', async () => {
  const h=harness();
  try {
    h.stream.start(); await settle();
    h.send('event: rea'); await settle();
    h.send('dy\ndata: {}\n\n: heartbeat\n\nevent: changed\ndata: ["snapshot"]\n\n'); await settle();
    assert.equal(JSON.stringify(h.events), JSON.stringify([['ready',{}],['changed',['snapshot']]]));
    assert(h.states.includes('Live updates connected'));
    assert.equal(h.calls(),1);
  } finally {h.stream.stop();}
  await settle();
  assert.equal(h.timers.size,0);
});

test('Dropped stream reconnects once; stop cancels pending reconnection', async () => {
  const h=harness();
  try {
    h.stream.start(); h.stream.start(); await settle();
    assert.equal(h.calls(),1);
    h.readers.at(-1).close(); await settle();
    assert(h.states.some(s=>s.includes('Reconnecting')));
    h.fire(delay=>delay<2000); await settle();
    assert.equal(h.calls(),2);
    h.readers.at(-1).close(); await settle();
    h.stream.stop(); await settle();
    assert.equal(h.timers.size,0);
  } finally {h.stream.stop();}
});

test('Silent connection watchdog reconnects instead of leaving stale live status', async () => {
  const h=harness();
  try {
    h.stream.start(); await settle();
    h.fire(delay=>delay===45000); await settle();
    assert(h.states.some(s=>s.includes('Reconnecting')));
    h.fire(delay=>delay<2000); await settle();
    assert.equal(h.calls(),2);
  } finally {h.stream.stop();}
});
