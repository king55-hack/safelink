/* SafeLink service worker: makes the app installable and keeps the page shell available offline.
   It never touches /api/*, /admin/ or any URL with a query string (e.g. text shared from another app). */
const CACHE = "safelink-v1";
const SHELL = ["./", "logo.webp", "favicon.png", "manifest.webmanifest", "vendor/jsQR.min.js"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/admin")) return;

  // network first (so a new deploy shows up immediately), cache as the offline fallback
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok && !url.search) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req, { ignoreSearch: true }).then((r) => r || caches.match("./"))),
  );
});
