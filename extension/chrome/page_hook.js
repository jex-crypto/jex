// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/* MAIN world document_start: rewrite CryptoPro chrome-extension API URLs to Jex.
   Do NOT rewrite moz-/safari-extension URLs — Firefox/Safari load via echoed getURL. */
(function () {
  "use strict";
  if (window.__jex_page_hook) return;
  window.__jex_page_hook = true;

  var CRYPTOPRO_IDS = [
    "pfhgbfnnjiafkhfdkmpiflachepdcjod",
    "iifchhfnnmpdbibifmljnfjhpififfog",
    "epebfcehmdedogndhlcacafjaacknbcm",
  ];
  var JEX_CHROME_ID = "ogfkpliagdeofggffdpifnakdhgfiagc";
  var apiUrl =
    window.__jex_nmcades_api_url ||
    "chrome-extension://" + JEX_CHROME_ID + "/nmcades_plugin_api.js";

  window.addEventListener("message", function (e) {
    if (e.source !== window || !e.data || !e.data.__jex_set_api_url) return;
    apiUrl = e.data.__jex_set_api_url;
    window.__jex_nmcades_api_url = apiUrl;
  });

  /* Official cadesplugin_api.js only allows moz-extension:// and safari-extension://.
     Safari Web Extensions use safari-web-extension://UUID/... — accept those too. */
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
        this.indexOf("chrome-extension://") === 0)
    ) {
      return [String(this)];
    }
    return origMatch.apply(this, arguments);
  };

  function isCryptoProExtUrl(url) {
    for (var i = 0; i < CRYPTOPRO_IDS.length; i++) {
      if (url.indexOf(CRYPTOPRO_IDS[i]) !== -1) return true;
    }
    return false;
  }

  function rewrite(url) {
    if (typeof url !== "string") return url;
    if (url.indexOf("nmcades_plugin_api.js") === -1) return url;
    /* Firefox/Safari: leave moz-/safari-* URLs alone (echo already points at Jex). */
    if (
      url.indexOf("moz-extension://") === 0 ||
      url.indexOf("safari-extension://") === 0 ||
      url.indexOf("safari-web-extension://") === 0
    ) {
      return url;
    }
    if (url.indexOf("chrome-extension://") === 0 && isCryptoProExtUrl(url)) {
      return apiUrl;
    }
    return url;
  }

  try {
    var desc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src");
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
  } catch (err) {}

  var origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    if (this.tagName === "SCRIPT" && String(name).toLowerCase() === "src") {
      value = rewrite(value);
    }
    return origSetAttribute.call(this, name, value);
  };
})();
