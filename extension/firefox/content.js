// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/* Jex content script: bridge page to background NMH host. */
(function () {
  "use strict";

  var api = typeof browser !== "undefined" ? browser : chrome;
  var extensionId = api.runtime.id;
  var apiUrl = api.runtime.getURL("nmcades_plugin_api.js");
  var apiHostId = null;
  try {
    var hostMatch = apiUrl.match(/:\/\/([^/]+)\//);
    if (hostMatch) apiHostId = hostMatch[1];
  } catch (err) {}
  var bgPort = null;
  var tabid = "jex-" + String(Date.now()) + "-" + String(Math.floor(Math.random() * 1e9));
  var ua = navigator.userAgent || "";
  var isSafari = /safari/i.test(ua) && !/chrome|chromium|android/i.test(ua);
  var isFirefox = /firefox/i.test(ua);

  /*
   * Safari only: inject MAIN-world bootstrap SYNCHRONOUSLY (inline).
   * Chrome uses scripting.registerContentScripts(world: MAIN) + page_hook.js —
   * inline <script> violates page CSP (script-src without unsafe-inline).
   */
  if (isSafari) {
    try {
      if (!document.documentElement.getAttribute("data-jex-hook")) {
        document.documentElement.setAttribute("data-jex-hook", "1");
        var boot = document.createElement("script");
        boot.textContent =
          "(" +
          function (realApiUrl) {
            if (window.__jex_page_hook) return;
            window.__jex_page_hook = true;
            window.__jex_nmcades_api_url = realApiUrl;
            var apiUrl = realApiUrl;
            var CRYPTOPRO_IDS = [
              "pfhgbfnnjiafkhfdkmpiflachepdcjod",
              "iifchhfnnmpdbibifmljnfjhpififfog",
              "epebfcehmdedogndhlcacafjaacknbcm",
            ];
            window.addEventListener("message", function (e) {
              if (e.source !== window || !e.data || !e.data.__jex_set_api_url) return;
              apiUrl = e.data.__jex_set_api_url;
              window.__jex_nmcades_api_url = apiUrl;
            });
            var origMatch = String.prototype.match;
            String.prototype.match = function (re) {
              if (
                this &&
                typeof this === "string" &&
                re &&
                re.toString &&
                re.toString().indexOf("moz|safari)-extension") !== -1 &&
                this.indexOf("nmcades_plugin_api.js") !== -1 &&
                (this.indexOf("safari-web-extension://") === 0 ||
                  this.indexOf("safari-extension://") === 0 ||
                  this.indexOf("chrome-extension://") === 0)
              ) {
                return [String(this)];
              }
              return origMatch.apply(this, arguments);
            };
            function isCryptoPro(url) {
              for (var i = 0; i < CRYPTOPRO_IDS.length; i++) {
                if (url.indexOf(CRYPTOPRO_IDS[i]) !== -1) return true;
              }
              return false;
            }
            function rewrite(url) {
              if (typeof url !== "string") return url;
              if (url.indexOf("nmcades_plugin_api.js") === -1) return url;
              if (url.indexOf("safari-extension://") === 0) return apiUrl;
              if (url.indexOf("chrome-extension://") === 0 && isCryptoPro(url)) return apiUrl;
              return url;
            }
            try {
              var desc = Object.getOwnPropertyDescriptor(
                HTMLScriptElement.prototype,
                "src"
              );
              if (desc && desc.set) {
                Object.defineProperty(HTMLScriptElement.prototype, "src", {
                  configurable: true,
                  enumerable: desc.enumerable,
                  get: desc.get,
                  set: function (v) {
                    desc.set.call(this, rewrite(v));
                  },
                });
              }
            } catch (e1) {}
            var origSetAttribute = Element.prototype.setAttribute;
            Element.prototype.setAttribute = function (name, value) {
              if (this.tagName === "SCRIPT" && String(name).toLowerCase() === "src") {
                value = rewrite(value);
              }
              return origSetAttribute.call(this, name, value);
            };
          }.toString() +
          ")(" +
          JSON.stringify(apiUrl) +
          ");";
        (document.documentElement || document.head).appendChild(boot);
        boot.remove();
      }
    } catch (err) {}
  }

  function connect() {
    if (bgPort) return;
    try {
      bgPort = api.runtime.connect({ name: tabid });
    } catch (e) {
      bgPort = null;
      return;
    }
    bgPort.onMessage.addListener(function (msg) {
      window.postMessage(msg, "*");
    });
    bgPort.onDisconnect.addListener(function () {
      bgPort = null;
    });
  }

  /* Safari: open NMH early so About/info is not racing connectNative. */
  if (isSafari) connect();

  function echoApiUrl() {
    /* cadesplugin regex: ^(moz|safari)-extension://… — not safari-web-extension. */
    if (isSafari && apiUrl.indexOf("safari-web-extension://") === 0) {
      return "safari-extension://" + apiUrl.substring("safari-web-extension://".length);
    }
    return apiUrl;
  }

  function answerLoaded() {
    if (isSafari || isFirefox) {
      window.postMessage("cadesplugin_loadedurl:" + echoApiUrl(), "*");
    } else {
      window.postMessage("cadesplugin_loaded", "*");
      window.postMessage("cadesplugin_loadedurl:" + apiUrl, "*");
    }
    window.postMessage("cadesplugin_extension_id_response:" + extensionId, "*");
  }

  function isOurDestination(dest) {
    if (!dest || typeof dest !== "string") return false;
    if (dest === "nmcades" || dest === "nmcades_v3") return true;
    var lower = dest.toLowerCase();
    if (lower === ("nmcades_" + extensionId).toLowerCase()) return true;
    if (apiHostId && lower === ("nmcades_" + apiHostId).toLowerCase()) return true;
    return false;
  }

  window.addEventListener("message", function (event) {
    if (event.source !== window) return;
    var data = event.data;

    if (
      data === "cadesplugin_echo_request" ||
      data === "cadesplugin_echo_request_" + extensionId ||
      data === "cadesplugin_echo_request_v3"
    ) {
      answerLoaded();
      return;
    }
    if (data === "cadesplugin_extension_version_request") {
      window.postMessage(
        "cadesplugin_extension_version_response:" + api.runtime.getManifest().version,
        "*"
      );
      return;
    }
    if (data === "cadesplugin_extension_id_request") {
      window.postMessage("cadesplugin_extension_id_response:" + extensionId, "*");
      return;
    }
    if (data === "jex_echo_request") {
      window.postMessage("jex_loaded:" + api.runtime.getURL("jex_api.js"), "*");
      return;
    }

    if (typeof data !== "object" || data === null) return;
    if (!isOurDestination(data.destination)) return;

    connect();
    if (!bgPort) {
      window.postMessage(
        {
          tabid: tabid,
          data: {
            type: "error",
            requestid: data.requestid,
            message: "Lost connection to Jex extension",
          },
        },
        "*"
      );
      return;
    }
    bgPort.postMessage({ tabid: tabid, data: data });
  });
})();
