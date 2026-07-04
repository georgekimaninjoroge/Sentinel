const QUEUE_KEY = "sentinel_refresh_queue";
const REFRESH_ENDPOINT = "/api/auth/refresh"; 

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

self.addEventListener("sync", e => {
  if (e.tag === "sentinel-refresh") {
    e.waitUntil(_executeRefresh());
  }
});

self.addEventListener("message", e => {
  if (e.data?.type === "SENTINEL_QUEUE_REFRESH") {
    const endpoint = e.data.endpoint ?? REFRESH_ENDPOINT;
    _queueRefresh(endpoint);

    if (navigator.onLine) {
      _executeRefresh(endpoint).then(result => {
        e.source?.postMessage({ type: "SENTINEL_REFRESH_RESULT", ...result });
      });
    } else {
      e.source?.postMessage({ type: "SENTINEL_REFRESH_QUEUED" });
    }
  }
});

self.addEventListener("fetch", e => {
  if (!navigator.onLine) return; 

  const queued = _getQueue();
  if (queued.length > 0) {

    e.waitUntil(_drainQueue());
  }
});

async function _executeRefresh(endpoint = REFRESH_ENDPOINT) {
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
    });

    if (!res.ok) throw new Error(`Refresh failed: ${res.status}`);

    const data = await res.json();


    const clients = await self.clients.matchAll({ includeUncontrolled: true });
    clients.forEach(c =>
      c.postMessage({ type: "SENTINEL_NEW_TOKEN", token: data.token ?? null })
    );

    _clearQueue(endpoint);
    return { success: true, token: data.token ?? null };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function _getQueue() {
  try {
    return JSON.parse(self._sentinelQueue ?? "[]");
  } catch {
    return [];
  }
}

function _queueRefresh(endpoint) {
  const q = _getQueue();
  if (!q.includes(endpoint)) q.push(endpoint);
  self._sentinelQueue = JSON.stringify(q);
}

function _clearQueue(endpoint) {
  const q = _getQueue().filter(e => e !== endpoint);
  self._sentinelQueue = JSON.stringify(q);
}

async function _drainQueue() {
  const q = _getQueue();
  for (const endpoint of q) {
    await _executeRefresh(endpoint);
  }
}