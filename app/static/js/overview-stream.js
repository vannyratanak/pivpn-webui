// SSE over fetch keeps the API's existing Bearer authentication (no URL tokens).
// One bounded reconnect loop; data is resynchronized whenever it reconnects.
window.OverviewStream = function (onEvent, onState) {
  let controller = null, retry = null, stopped = true, delay = 1000;
  async function connect() {
    if (stopped) return;
    const active = new AbortController();
    controller = active;
    onState('Connecting live updates…');
    let watchdog = setTimeout(() => active.abort(), 45000);
    try {
      const response = await ApiClient.call('/api/overview/events', { signal: active.signal });
      if (!response.ok || !response.headers.get('content-type')?.includes('text/event-stream')) throw new Error('Stream unavailable');
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (!active.signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        clearTimeout(watchdog);
        watchdog = setTimeout(() => active.abort(), 45000);
        buffer += decoder.decode(value, { stream: true });
        if (buffer.length > 65536) throw new Error('Stream frame too large');
        let end;
        while ((end = buffer.indexOf('\n\n')) >= 0) {
          const lines = buffer.slice(0, end).split('\n');
          buffer = buffer.slice(end + 2);
          const event = lines.find(line => line.startsWith('event: '))?.slice(7);
          const data = lines.find(line => line.startsWith('data: '))?.slice(6);
          if (event && data && !active.signal.aborted) {
            if (event === 'ready') { delay = 1000; onState('Live updates connected'); }
            onEvent(event, JSON.parse(data));
          }
        }
      }
    } catch (error) {
      if (stopped || controller !== active) return;
    } finally {
      clearTimeout(watchdog);
      active.abort();
    }
    if (!stopped && controller === active) {
      onState('Live updates disconnected. Reconnecting…');
      retry = setTimeout(connect, delay + Math.random() * 500);
      delay = Math.min(delay * 2, 30000);
    }
  }
  return {
    start() { if (!stopped) return; stopped = false; delay = 1000; connect(); },
    stop() { stopped = true; clearTimeout(retry); if (controller) controller.abort(); },
  };
};
