/* FejkRadar – service worker PWA
 *  1. Instalacja i działanie offline: app shell w cache (strona, ikony, Cytoscape.js), API zawsze z sieci.
 *  2. Android Share Target: przechwytuje POST /share („Udostępnij → FejkRadar”), odkłada link/tekst/obraz
 *     do Cache Storage i otwiera zakładkę „Złap fejk”, która wypełnia formularz i uruchamia analizę.
 *  3. Powiadomienia: kliknięcie przełącza otwarte okno aplikacji na alert (albo otwiera nowe).
 */
const VERSION = "fejkradar-v6";
const SHELL_CACHE = `${VERSION}-shell`;
const SHARE_CACHE = "fejkradar-share";
const SHELL = [
  "/",
  "/manifest.webmanifest",
  "/web/icon.svg",
  "/web/icons/icon-192.png",
  "/web/icons/icon-512.png",
  "/web/icons/badge-96.png",
  "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      // pojedynczy błąd (np. brak sieci do CDN) nie może zablokować instalacji
      .then((cache) => Promise.allSettled(SHELL.map((u) => cache.add(new Request(u, {cache: "reload"})))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.endsWith("-shell") && k !== SHELL_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // --- Share Target ---
  if (req.method === "POST" && url.origin === location.origin && url.pathname === "/share") {
    event.respondWith(handleShare(req));
    return;
  }
  if (req.method !== "GET") return;

  // --- API: zawsze sieć (dane muszą być świeże) ---
  if (url.origin === location.origin && (url.pathname.startsWith("/api/") || url.pathname.startsWith("/uploads/"))) {
    event.respondWith(fetch(req).catch(() =>
      new Response(JSON.stringify({offline: true, detail: "Brak połączenia z serwerem FejkRadar"}),
        {status: 503, headers: {"Content-Type": "application/json"}})));
    return;
  }

  // --- nawigacja: sieć, a offline – zapisany app shell ---
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).then((res) => { putShell("/", res.clone()); return res; })
        .catch(() => caches.match("/", {cacheName: SHELL_CACHE}))
    );
    return;
  }

  // --- zasoby statyczne i Cytoscape z CDN: stale-while-revalidate ---
  if ((url.origin === location.origin && (url.pathname.startsWith("/web/") || url.pathname === "/manifest.webmanifest"))
      || url.hostname === "cdnjs.cloudflare.com") {
    event.respondWith(
      caches.match(req, {cacheName: SHELL_CACHE}).then((cached) => {
        const network = fetch(req).then((res) => { if (res.ok) putShell(req, res.clone()); return res; }).catch(() => cached);
        return cached || network;
      })
    );
  }
});

function putShell(key, res) {
  if (res && res.ok) caches.open(SHELL_CACHE).then((c) => c.put(key, res));
}

async function handleShare(req) {
  try {
    const form = await req.formData();
    const files = form.getAll("files").filter((f) => f && typeof f === "object" && f.size > 0);
    const meta = {
      title: form.get("title") || "",
      text: form.get("text") || "",
      url: form.get("url") || "",
      files: files.map((f, i) => ({key: `/__share/file/${i}`, name: f.name || `udostepnione-${i}.jpg`, type: f.type})),
      at: Date.now(),
    };
    const cache = await caches.open(SHARE_CACHE);
    await Promise.all(files.map((f, i) =>
      cache.put(meta.files[i].key, new Response(f, {headers: {"Content-Type": f.type || "application/octet-stream"}}))));
    await cache.put("/__share/meta", new Response(JSON.stringify(meta), {headers: {"Content-Type": "application/json"}}));
    return Response.redirect("/?shared=1#submit", 303);
  } catch (e) {
    return Response.redirect("/?shared=error#submit", 303);
  }
}

// --- powiadomienia ---
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || "/#alerts", self.location.origin).href;
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({type: "window", includeUncontrolled: true});
    const win = wins.find((w) => new URL(w.url).origin === self.location.origin);
    if (win) {
      win.postMessage({type: "open", url: target});
      return win.focus();
    }
    return self.clients.openWindow(target);
  })());
});

// Gotowe pod Web Push (VAPID): serwer wysyła {title, body, url}
self.addEventListener("push", (event) => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(self.registration.showNotification(data.title || "FejkRadar", {
    body: data.body || "Nowy wariant w obserwowanej kampanii",
    icon: "/web/icons/icon-192.png",
    badge: "/web/icons/badge-96.png",
    tag: data.tag || "fejkradar-alert",
    data: {url: data.url || "/#alerts"},
  }));
});
