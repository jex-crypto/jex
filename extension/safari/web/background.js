// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/* Safari background: content ↔ HTTP bridge on 127.0.0.1:18787
   (LaunchAgent ru.jex.nmcades-http). Avoids connectNative — Safari ad-hoc
   appex UUID changes every Run and breaks NMH. If the bridge is down, ask
   SafariWebExtensionHandler to kickstart the LaunchAgent, then retry once. */
var api = typeof browser !== "undefined" ? browser : chrome;
var BRIDGE = "http://127.0.0.1:18787/";
var contentPorts = {};

function replyError(tabid, requestid, message) {
  var cp = contentPorts[tabid];
  if (!cp) return;
  try {
    cp.postMessage({
      tabid: tabid,
      data: { type: "error", requestid: requestid, message: message },
    });
  } catch (e) {}
}

function postJson(msg, signal) {
  return fetch(BRIDGE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg),
    signal: signal,
  }).then(function (r) {
    if (!r.ok) throw new Error("bridge HTTP " + r.status);
    return r.json();
  });
}

function kickstartBridge() {
  // Safari routes sendNativeMessage to SafariWebExtensionHandler.
  if (!api.runtime || !api.runtime.sendNativeMessage) {
    return Promise.reject(new Error("sendNativeMessage unavailable"));
  }
  try {
    var p = api.runtime.sendNativeMessage("local.jex.Jex", { cmd: "ensureBridge" });
    if (p && typeof p.then === "function") return p;
  } catch (e1) {}
  return new Promise(function (resolve, reject) {
    try {
      api.runtime.sendNativeMessage("local.jex.Jex", { cmd: "ensureBridge" }, function (resp) {
        var err = api.runtime.lastError;
        if (err) reject(new Error(err.message || String(err)));
        else resolve(resp);
      });
    } catch (e) {
      reject(e);
    }
  });
}

function deliverBridgeResponse(tabid, requestid, response) {
  var cp = contentPorts[tabid];
  if (!cp) return;
  if (response && response.data) {
    cp.postMessage(response);
  } else if (response && response.type) {
    cp.postMessage({ tabid: tabid, data: response });
  } else {
    replyError(tabid, requestid, "empty bridge reply");
  }
}

function forwardToBridge(msg) {
  var tabid = msg && msg.tabid;
  var requestid = msg && msg.data && msg.data.requestid;
  var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
  var timer = null;
  if (ctrl) {
    timer = setTimeout(function () {
      try {
        ctrl.abort();
      } catch (e) {}
    }, 15000);
  }
  var signal = ctrl ? ctrl.signal : undefined;

  function fail(e) {
    if (timer) clearTimeout(timer);
    console.error("Jex bridge failed", e);
    var aborted = e && (e.name === "AbortError" || /abort/i.test(String(e)));
    replyError(
      tabid,
      requestid,
      aborted
        ? "Jex bridge timeout (15s). PC/SC busy or host stuck — retry."
        : "Jex bridge unreachable (" +
            ((e && e.message) || e) +
            "). Run scripts/install-nmcades-http.sh (LaunchAgent)."
    );
  }

  postJson(msg, signal)
    .then(function (response) {
      if (timer) clearTimeout(timer);
      deliverBridgeResponse(tabid, requestid, response);
    })
    .catch(function (e) {
      // Bridge down → kickstart LaunchAgent via appex, then one retry.
      console.warn("Jex bridge down, kickstarting LaunchAgent…", e);
      kickstartBridge()
        .catch(function () {
          return null;
        })
        .then(function () {
          return new Promise(function (r) {
            setTimeout(r, 500);
          });
        })
        .then(function () {
          return postJson(msg, signal);
        })
        .then(function (response) {
          if (timer) clearTimeout(timer);
          deliverBridgeResponse(tabid, requestid, response);
        })
        .catch(fail);
    });
}

api.runtime.onConnect.addListener(function (contentPort) {
  var tabid = contentPort.name;
  contentPorts[tabid] = contentPort;
  contentPort.onMessage.addListener(function (msg) {
    forwardToBridge(msg);
  });
  contentPort.onDisconnect.addListener(function () {
    contentPorts[tabid] = null;
  });
});
