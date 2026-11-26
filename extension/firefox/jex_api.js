// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/* window.jex - thin async API over the same NMH as cadesplugin */
(function () {
  if (window.jex && window.jex.__jex) return;

  function waitPlugin() {
    return new Promise((resolve, reject) => {
      const t0 = Date.now();
      (function poll() {
        if (window.cpcsp_chrome_nmcades && window.cpcsp_chrome_nmcades.CreatePluginObject) {
          resolve(window.cpcsp_chrome_nmcades);
          return;
        }
        if (Date.now() - t0 > 8000) {
          reject(new Error("Jex plugin API not loaded"));
          return;
        }
        setTimeout(poll, 50);
      })();
    });
  }

  async function withStore(fn) {
    const api = await waitPlugin();
    const plugin = await api.CreatePluginObject();
    const store = await plugin.CreateObjectAsync("CAdESCOM.Store");
    await store.Open(2, "My");
    const certs = await store.Certificates;
    return fn(plugin, store, certs);
  }

  window.jex = {
    __jex: true,
    async certificates() {
      return withStore(async (_p, _s, certs) => {
        const n = await certs.Count;
        const out = [];
        for (let i = 1; i <= n; i++) {
          const c = await certs.Item(i);
          out.push({
            subject: await c.SubjectName,
            issuer: await c.IssuerName,
            thumbprint: await c.Thumbprint,
            serial: await c.SerialNumber,
            notBefore: await c.ValidFromDate,
            notAfter: await c.ValidToDate,
            _cert: c,
          });
        }
        return out;
      });
    },
    async sign(content, opts) {
      opts = opts || {};
      return withStore(async (plugin, _s, certs) => {
        const n = await certs.Count;
        if (!n) throw new Error("no certificates");
        let cert = await certs.Item(opts.index || n);
        if (opts.thumbprint) {
          const want = String(opts.thumbprint).toUpperCase();
          for (let i = 1; i <= n; i++) {
            const c = await certs.Item(i);
            const tp = String(await c.Thumbprint).toUpperCase();
            if (tp === want) {
              cert = c;
              break;
            }
          }
        }
        const signer = await plugin.CreateObjectAsync("CAdESCOM.CPSigner");
        await signer.propset_Certificate(cert);
        if (opts.pin) await signer.propset_KeyPin(opts.pin);
        const sd = await plugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
        await sd.propset_ContentEncoding(1);
        const b64 =
          typeof btoa === "function"
            ? btoa(unescape(encodeURIComponent(content)))
            : content;
        await sd.propset_Content(b64);
        return sd.SignCades(signer, opts.cadesType || 1);
      });
    },
  };

  // Ensure nmcades_plugin_api is present (same extension).
  if (!window.cpcsp_chrome_nmcades) {
    const s = document.createElement("script");
    s.src = document.currentScript
      ? document.currentScript.src.replace(/jex_api\.js.*/, "nmcades_plugin_api.js")
      : "";
    if (s.src) document.documentElement.appendChild(s);
  }
})();
