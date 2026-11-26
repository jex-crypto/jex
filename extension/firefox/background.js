// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/* Jex background (Firefox MV2 event page + Chrome MV3 service worker). */
var api = typeof browser !== "undefined" ? browser : chrome;
var HOST = "ru.jex.nmcades";
var contentPorts = {};
var nativePorts = {};

function registerPageHook() {
  if (!api.scripting || !api.scripting.registerContentScripts) {
    return;
  }
  var p = api.scripting.unregisterContentScripts({ ids: ["jex-page-hook"] });
  Promise.resolve(p)
    .catch(function () {})
    .then(function () {
      return api.scripting.registerContentScripts([
        {
          id: "jex-page-hook",
          matches: ["http://*/*", "https://*/*", "file://*/*"],
          js: ["page_hook.js"],
          runAt: "document_start",
          world: "MAIN",
          allFrames: true,
        },
      ]);
    })
    .then(function () {
      console.info("Jex: MAIN page_hook registered");
    })
    .catch(function (e) {
      console.error("Jex: failed to register page_hook", e);
    });
}

if (api.runtime.onInstalled) {
  api.runtime.onInstalled.addListener(registerPageHook);
}
if (api.runtime.onStartup) {
  api.runtime.onStartup.addListener(registerPageHook);
}
registerPageHook();

function sendNative(msg) {
  var port = nativePorts[msg.tabid];
  if (!port) {
    console.error("Jex: no native port for", msg.tabid);
    return;
  }
  try {
    port.postMessage(msg);
  } catch (e) {
    console.error("Jex NMH send failed", e);
    nativePorts[msg.tabid] = null;
  }
}

function connectNative(tabid) {
  var np;
  try {
    np = api.runtime.connectNative(HOST);
  } catch (e) {
    console.error("Jex connectNative threw", e);
    return;
  }
  nativePorts[tabid] = np;
  np.onMessage.addListener(function (message) {
    var cp = contentPorts[tabid];
    if (!cp) return;
    try {
      cp.postMessage(message);
    } catch (e) {
      console.error("Jex content post failed", e);
    }
  });
  np.onDisconnect.addListener(function () {
    var err = api.runtime.lastError;
    console.error("Jex NMH disconnect:", err && err.message);
    nativePorts[tabid] = null;
  });
}

api.runtime.onConnect.addListener(function (contentPort) {
  var tabid = contentPort.name;
  contentPorts[tabid] = contentPort;
  contentPort.onMessage.addListener(function (msg) {
    sendNative(msg);
  });
  contentPort.onDisconnect.addListener(function () {
    contentPorts[tabid] = null;
    if (nativePorts[tabid]) {
      try {
        nativePorts[tabid].disconnect();
      } catch (err) {}
      nativePorts[tabid] = null;
    }
  });
  if (!nativePorts[tabid]) connectNative(tabid);
});
