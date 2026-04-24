import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { I18nProvider } from "./i18n/context";
import "./styles/globals.css";

/**
 * One-shot self-heal. Some browsers hold on to an older copy of this
 * origin via a leftover Service Worker or an entry in the Cache
 * Storage API — neither is cleared by a regular hard-refresh.
 *
 * On every load we:
 *   1. unregister any Service Worker that was ever registered here
 *   2. empty every cache in caches.keys()
 *
 * Current build id is stamped onto <html data-build="..."> so you can
 * read it from DevTools or `document.documentElement.dataset.build`.
 * If the stamp doesn't match the build id baked into the JS bundle,
 * the page reloads itself once, bypassing the HTTP cache.
 */
(async () => {
  try {
    if ("serviceWorker" in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    }
    if ("caches" in window) {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    }
  } catch {
    /* best-effort cleanup */
  }
})();

document.documentElement.dataset.build = __BUILD_ID__;

// Detect stale HTML that somehow slipped past no-cache headers by
// comparing the build id the server claims (data-build on <html>,
// overridden above) with the one baked into this JS chunk. They
// always match on a fresh page load; a mismatch means the browser
// is using a cached HTML that points at an older bundle.
const htmlBuild = document.documentElement.getAttribute("data-build-html");
if (htmlBuild && htmlBuild !== __BUILD_ID__) {
  const url = new URL(window.location.href);
  if (!url.searchParams.has("__refreshed")) {
    url.searchParams.set("__refreshed", __BUILD_ID__);
    window.location.replace(url.toString());
  }
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </React.StrictMode>,
);
