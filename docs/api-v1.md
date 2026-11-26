# Jex Web API (`/api/v1`)

Собственный HTTP API для веб-страниц. **Без** совместимости с CryptoPro CADESCOM.

- Префикс: `/api/v1`
- JS SDK: `GET /jex.js`
- Auth / CORS: как у демона (Bearer или разрешённый `Origin`) — см. ниже
- Ошибки: `{ "error": { "code": "…", "message": "…" } }` + HTTP 4xx/5xx

Legacy (не расширять): `/v1/*`. Frozen shim: `/nmcades/*` + `cadesplugin_api.js`.

---

## Auth и CORS

1. `Authorization: Bearer <token>` из `api_keys[].token` / `token_file`
2. Или `Origin`, совпадающий с `api_keys[].origins[]`

`allow`: список `key_id` или `"*"`.

Публично (без auth): `GET /health`, `GET /api/v1` (discovery), `GET /jex.js`, `GET /cadesplugin_api.js`, `GET /nmcades/about`.

---

## Профили и режим

| `profile` | Значение |
|-----------|----------|
| `bes` | CAdES-BES |
| `t` | CAdES-T |
| `xlt1` | CAdES-X Long Type 1 |
| `a` | CAdES-A (archive / ATSv3) |

Алиасы: `archive` → `a`, `xlong` → `xlt1`.

| `mode` | Значение |
|--------|----------|
| `detached` | без eContent (по умолчанию) |
| `attached` | контент внутри CMS |

---

## Модель контента

Взаимоисключающие варианты:

```json
{ "content": { "b64": "…" } }
{ "content": { "hash_hex": "…" } }
```

`hash_hex` = `messageDigest` (Streebog подписи). Достаточно для `verify` и `enhance`→`a` (и SignHash-стиля при `sign` с `mode: "detached"`).

---

## Ошибки (стабильные `code`)

| code | Когда |
|------|--------|
| `unauthorized` | нет/плохой auth |
| `forbidden_key` | `key_id` не в ACL |
| `invalid_json` | тело не JSON |
| `invalid_base64` | битый b64 |
| `invalid_content` | нет/оба варианта content |
| `invalid_profile` | неизвестный profile |
| `invalid_mode` | неизвестный mode |
| `missing_field` | обязательное поле |
| `missing_tsa` | нужен TSA, его нет |
| `content_digest_mismatch` | хеш/контент не совпал с подписью |
| `verification_failed` | локальная проверка не прошла |
| `not_detached` / `not_attached` | convert в неверном направлении |
| `key_required` | несколько ключей, `key_id` не указан |
| `no_keys` | ACL пуст |
| `internal` | прочая ошибка сервера |

---

## `GET /api/v1` — discovery (публичный)

```json
{
  "name": "jex",
  "api": "v1",
  "profiles": ["bes", "t", "xlt1", "a"],
  "hash_algs": ["streebog256", "streebog512"],
  "features": {
    "sign": true,
    "verify": true,
    "enhance": true,
    "convert": true,
    "hash": true,
    "archive": true,
    "default_tsa": true
  }
}
```

`features.default_tsa` — есть ли TSA в конфиге демона.

---

## `GET /api/v1/keys`

Список ключей ACL.

```json
[
  {
    "id": "roman",
    "subject": "…",
    "serial_hex": "…",
    "thumbprint": "…",
    "not_before": "…",
    "not_after": "…",
    "curve": "…"
  }
]
```

---

## `POST /api/v1/sign`

Подпись до целевого `profile` одной ручкой (BES→…→A).

```json
{
  "key_id": "roman",
  "profile": "a",
  "mode": "detached",
  "content": { "b64": "…" },
  "tsa": null
}
```

| Поле | Описание |
|------|----------|
| `key_id` | опционально, если в ACL ровно один ключ |
| `profile` | default `bes` |
| `mode` | default `detached` |
| `content` | `b64` или `hash_hex` (hash → только detached) |
| `tsa` | URL, или `null`/omit → default конфига (нужен для t/xlt1/a) |

**Ответ 200**

```json
{
  "profile": "a",
  "detached": true,
  "signature": { "b64": "…" },
  "digest": { "alg": "streebog256", "hex": "…" },
  "signer": {
    "key_id": "roman",
    "subject": "…",
    "thumbprint": "…"
  }
}
```

---

## `POST /api/v1/verify`

```json
{
  "signature": { "b64": "…" },
  "content": { "b64": "…" }
}
```

Для detached: `content.b64` или `content.hash_hex`. Attached — content опционален.

**Ответ 200**

```json
{
  "ok": true,
  "profile": "a",
  "detached": true,
  "checks": {
    "signature": true,
    "message_digest": true,
    "signing_certificate_v2": true
  },
  "digest": { "alg": "streebog256", "hex": "…" },
  "signer": { "subject": "…", "thumbprint": "…" }
}
```

При провале крипто/профиля: HTTP 400, `code: verification_failed`, в `message` краткая сводка (тело без подписи).

---

## `POST /api/v1/enhance`

```json
{
  "signature": { "b64": "…" },
  "profile": "a",
  "content": { "hash_hex": "…" },
  "tsa": null
}
```

`profile`: `t` | `xlt1` (default) | `a`. Для `a` + detached нужен content/hash.

**Ответ 200** — как у sign (`profile`, `detached`, `signature`, `digest`, `signer` без `key_id` если ключ не из store).

---

## `POST /api/v1/convert`

```json
{
  "signature": { "b64": "…" },
  "to": "attached",
  "content": { "b64": "…" }
}
```

| `to` | Нужен content |
|------|----------------|
| `attached` | да (`b64`) |
| `detached` | нет (контент вернётся в ответе) |

**Ответ 200**

```json
{
  "profile": "a",
  "detached": false,
  "signature": { "b64": "…" },
  "content": { "b64": "…" },
  "digest": { "alg": "streebog256", "hex": "…" },
  "signer": { "subject": "…", "thumbprint": "…" }
}
```

`content` в ответе — при `to: "detached"` (извлечённый) или эхо при attach.

---

## `POST /api/v1/hash`

```json
{
  "alg": "streebog256",
  "content": { "b64": "…" }
}
```

`alg`: `streebog256` (default) | `streebog512`.

**Ответ 200**

```json
{
  "digest": { "alg": "streebog256", "hex": "…", "b64": "…" }
}
```

---

## JS SDK

```html
<script src="http://127.0.0.1:8787/jex.js"></script>
<script>
  const jex = Jex.create({ baseUrl: 'http://127.0.0.1:8787', token: '…' });
  const keys = await jex.keys();
  const signed = await jex.sign({
    keyId: 'roman',
    profile: 'a',
    mode: 'detached',
    content: new Uint8Array([…]),
  });
</script>
```

Origin-auth: можно без `token`, если origin в ACL.

---

## Примеры curl

```bash
curl -s http://127.0.0.1:8787/api/v1

curl -s -H "Authorization: Bearer dev-token-change-me" \
  http://127.0.0.1:8787/api/v1/keys

curl -s -H "Authorization: Bearer dev-token-change-me" \
  -H "Content-Type: application/json" \
  -d '{"key_id":"roman","profile":"bes","mode":"detached","content":{"b64":"aGVsbG8="}}' \
  http://127.0.0.1:8787/api/v1/sign
```
