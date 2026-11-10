/* Perathos Gate service worker: shows approval-request notifications. No fetch handler, no caching. */
"use strict";

self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (event) { event.waitUntil(self.clients.claim()); });

self.addEventListener("push", function (event) {
  var d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { /* show the generic text */ }
  event.waitUntil(self.registration.showNotification(d.title || "Perathos Gate", {
    body: d.body || "An approval request is waiting.",
    tag: d.tag || undefined,
    data: { url: d.url || "/" }
  }));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var url = new URL((event.notification.data && event.notification.data.url) || "/", self.location.origin);
  if (url.origin !== self.location.origin) url = new URL("/", self.location.origin);  // only ever open this Gate
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].url === url.href && "focus" in list[i]) return list[i].focus();
    }
    return self.clients.openWindow(url.href);
  }));
});
