// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/*!
 * Jex first-party web SDK (no CryptoPro CADESCOM).
 * Served by the daemon as GET /jex.js
 */
(function (global) {
  "use strict";

  function bytesToB64(bytes) {
    var bin = "";
    var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (var i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    return btoa(bin);
  }

  function toBytes(content) {
    if (content == null) return Promise.reject(new Error("content required"));
    if (typeof content === "string") {
      return Promise.resolve(new TextEncoder().encode(content));
    }
    if (content instanceof ArrayBuffer) {
      return Promise.resolve(new Uint8Array(content));
    }
    if (content instanceof Uint8Array) {
      return Promise.resolve(content);
    }
    if (typeof Blob !== "undefined" && content instanceof Blob) {
      return content.arrayBuffer().then(function (ab) {
        return new Uint8Array(ab);
      });
    }
    return Promise.reject(new Error("unsupported content type"));
  }

  function JexError(code, message, status) {
    var e = new Error(message || code);
    e.name = "JexError";
    e.code = code;
    e.status = status;
    return e;
  }

  function Client(opts) {
    opts = opts || {};
    this.baseUrl = (opts.baseUrl || "").replace(/\/$/, "");
    this.token = opts.token || null;
  }

  Client.prototype._headers = function (extra) {
    var h = Object.assign({ Accept: "application/json" }, extra || {});
    if (this.token) h.Authorization = "Bearer " + this.token;
    return h;
  };

  Client.prototype._fetch = function (method, path, body) {
    var self = this;
    var init = {
      method: method,
      headers: self._headers(
        body != null ? { "Content-Type": "application/json" } : undefined
      ),
      credentials: "omit",
    };
    if (body != null) init.body = JSON.stringify(body);
    return fetch(self.baseUrl + path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try {
          data = text ? JSON.parse(text) : null;
        } catch (_) {
          data = { error: { code: "invalid_json", message: text } };
        }
        if (!res.ok) {
          var err = (data && data.error) || {};
          throw JexError(
            err.code || "http_error",
            err.message || res.statusText || "request failed",
            res.status
          );
        }
        return data;
      });
    });
  };

  Client.prototype.discovery = function () {
    return this._fetch("GET", "/api/v1");
  };

  Client.prototype.keys = function () {
    return this._fetch("GET", "/api/v1/keys");
  };

  Client.prototype.sign = function (opts) {
    opts = opts || {};
    var self = this;
    var body = {
      key_id: opts.keyId || opts.key_id,
      profile: opts.profile || "bes",
      mode: opts.mode || "detached",
      tsa: opts.tsa === undefined ? null : opts.tsa,
    };
    if (opts.contentHash || opts.content_hash || opts.hashHex) {
      body.content = {
        hash_hex: opts.contentHash || opts.content_hash || opts.hashHex,
      };
      return self._fetch("POST", "/api/v1/sign", body);
    }
    return toBytes(opts.content).then(function (bytes) {
      body.content = { b64: bytesToB64(bytes) };
      return self._fetch("POST", "/api/v1/sign", body);
    });
  };

  Client.prototype.verify = function (opts) {
    opts = opts || {};
    var self = this;
    var body = {
      signature: {
        b64:
          typeof opts.signature === "string"
            ? opts.signature
            : opts.signature && opts.signature.b64,
      },
    };
    if (opts.contentHash || opts.hashHex) {
      body.content = { hash_hex: opts.contentHash || opts.hashHex };
      return self._fetch("POST", "/api/v1/verify", body);
    }
    if (opts.content == null) {
      return self._fetch("POST", "/api/v1/verify", body);
    }
    return toBytes(opts.content).then(function (bytes) {
      body.content = { b64: bytesToB64(bytes) };
      return self._fetch("POST", "/api/v1/verify", body);
    });
  };

  Client.prototype.enhance = function (opts) {
    opts = opts || {};
    var self = this;
    var body = {
      signature: {
        b64:
          typeof opts.signature === "string"
            ? opts.signature
            : opts.signature && opts.signature.b64,
      },
      profile: opts.profile || "xlt1",
      tsa: opts.tsa === undefined ? null : opts.tsa,
    };
    if (opts.contentHash || opts.hashHex) {
      body.content = { hash_hex: opts.contentHash || opts.hashHex };
      return self._fetch("POST", "/api/v1/enhance", body);
    }
    if (opts.content == null) {
      return self._fetch("POST", "/api/v1/enhance", body);
    }
    return toBytes(opts.content).then(function (bytes) {
      body.content = { b64: bytesToB64(bytes) };
      return self._fetch("POST", "/api/v1/enhance", body);
    });
  };

  Client.prototype.convert = function (opts) {
    opts = opts || {};
    var self = this;
    var body = {
      signature: {
        b64:
          typeof opts.signature === "string"
            ? opts.signature
            : opts.signature && opts.signature.b64,
      },
      to: opts.to,
    };
    if (opts.content == null) {
      return self._fetch("POST", "/api/v1/convert", body);
    }
    return toBytes(opts.content).then(function (bytes) {
      body.content = { b64: bytesToB64(bytes) };
      return self._fetch("POST", "/api/v1/convert", body);
    });
  };

  Client.prototype.hash = function (opts) {
    opts = opts || {};
    var self = this;
    return toBytes(opts.content).then(function (bytes) {
      return self._fetch("POST", "/api/v1/hash", {
        alg: opts.alg || "streebog256",
        content: { b64: bytesToB64(bytes) },
      });
    });
  };

  var Jex = {
    create: function (opts) {
      return new Client(opts);
    },
  };

  global.Jex = Jex;
})(typeof window !== "undefined" ? window : globalThis);
