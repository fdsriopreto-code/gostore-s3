// gostore console service worker.
//
// Caches only the static app shell (this console's own files under
// /gostore/console/) so the PWA loads instantly and works offline for the
// shell. It deliberately NEVER touches S3 / admin API traffic — those are
// authenticated, dynamic requests signed per-call and must always hit the
// network — nor anything cross-origin.

const CACHE = "gostore-console-v1";
const SHELL = [
  "./",
  "./index.html",
  "./app.js",
  "./manifest.json",
  "./icon-192.png",
  "./icon-512.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting())
      .catch(() => {}),
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  // Only ever handle this console's own static shell.
  if (url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith("/gostore/console/")) return;

  // Network-first so a redeploy is picked up, with a cache fallback so the
  // shell still opens offline. Navigations fall back to the cached index.
  e.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        return res;
      })
      .catch(() =>
        caches.match(req).then((r) => r || caches.match("./index.html")),
      ),
  );
});
