# Jex daemon HTTP API

Запуск:

```bash
jex daemon --config examples/daemon.json
# опционально: --listen 127.0.0.1:8787
```

Базовый URL по умолчанию: `http://127.0.0.1:8787`.

## Пространства имён

| Префикс | Статус | Назначение |
|---------|--------|------------|
| **`/api/v1/…`** + **`/jex.js`** | **primary** | Свой веб-API без CryptoPro — см. [`api-v1.md`](api-v1.md) |
| `/v1/…` | **legacy** | Старая общая API; не расширять |
| `/nmcades/…` + `/cadesplugin_api.js` | **frozen** | Shim CryptoPro Browser plug-in (только багфиксы) |
| `/health` | — | Liveness |

Для новых страниц использовать только `/api/v1` и `jex.js`.

---

## Авторизация и CORS

Два способа (первый сработавший):

1. **Bearer token** — заголовок `Authorization: Bearer <token>`  
   Токен задаётся в `api_keys[].token` или `api_keys[].token_file`.
2. **Origin** — заголовок `Origin` совпадает с `api_keys[].origins[]`  
   (для браузерного shim / SDK без Bearer).

У каждой записи `api_keys` список `allow`: id контейнеров из `keys` или `"*"`.

- Non-loopback listen **требует** непустые `api_keys` с токенами/origins.
- `OPTIONS *` — CORS preflight (`204`).
- CORS-заголовки выставляются, если `Origin` разрешён ACL.

Публичные (без auth): `GET /health`, `GET /api/v1`, `GET /jex.js`, `GET /nmcades/about`, `GET /cadesplugin_api.js`.

---

# Legacy `/v1` и frozen `/nmcades`

Ниже — справочник старых ручек. Новые фичи добавлять в [`api-v1.md`](api-v1.md).

## Константы `cades_type` (CADESCOM)

| Значение | Профиль |
|---------:|---------|
| `1` (`0x1`) | CAdES-BES |
| `5` (`0x5`) | CAdES-T |
| `93` (`0x5d`) | CAdES-X Long Type 1 |
| `221` (`0xdd`) | CAdES-A |

---

## Сводка ручек (legacy / frozen)

Primary surface: [`api-v1.md`](api-v1.md).

### Legacy `/v1`

| Метод | Путь | Auth | Назначение |
|-------|------|:----:|------------|
| `GET` | `/health` | нет | Liveness |
| `GET` | `/jex.js` | нет | First-party JS SDK |
| `GET` | `/cadesplugin_api.js` | нет | CryptoPro shim JS (frozen) |
| `GET` | `/v1/keys` | да | Список ключей ACL |
| `POST` | `/v1/sign` | да | Простая подпись (JSON или raw body) |
| `POST` | `/v1/enhance` | да | Enhance → T / XLT1 / A (archive) |
| `POST` | `/v1/attach` | да | Detached → attached CMS |
| `POST` | `/v1/detach` | да | Attached → detached CMS |
| `OPTIONS` | любой | — | CORS preflight |

### Frozen `/nmcades`

| Метод | Путь | Auth | Назначение |
|-------|------|:----:|------------|
| `GET` | `/nmcades/about` | нет | Версии «плагина» для shim |
| `GET` | `/nmcades/certificates` | да | Сертификаты (Store) |
| `POST` | `/nmcades/sign` | да | SignCades / SignHash, BES→A |
| `POST` | `/nmcades/verify` | да | VerifyCades |
| `POST` | `/nmcades/hash` | да | HashedData |
| `POST` | `/nmcades/raw-sign` | да | RawSignature.SignHash |
| `POST` | `/nmcades/raw-verify` | да | RawSignature.VerifyHash |
| `POST` | `/nmcades/enhance` | да | EnhanceCades → T / XLT1 / A |
| `POST` | `/nmcades/xml-sign` | да | SignedXML |
| `POST` | `/nmcades/xml-verify` | да | проверка SignedXML |

---

## `GET /health`

**Ответ 200**

```json
{ "status": "ok" }
```

---

## `GET /nmcades/about`

Публичный probe для браузерного shim.

**Ответ 200**

```json
{
  "PluginVersion": "2.0.15512",
  "CSPVersion": "5.0.13000"
}
```

---

## `GET /cadesplugin_api.js`

Отдаёт встроенный `cadesplugin_api.js` (`Content-Type: application/javascript`, `Cache-Control: no-store`).

---

## `GET /v1/keys`

Ключи, видимые текущему ACL.

**Ответ 200** — массив:

```json
[
  {
    "id": "roman",
    "subject": "…",
    "serial_hex": "…",
    "not_before": "…",
    "not_after": "…",
    "curve": "…"
  }
]
```

---

## `GET /nmcades/certificates`

То же множество ключей в формате ближе к CryptoPro Store.

**Ответ 200** — массив:

| Поле | Описание |
|------|----------|
| `id` | id из конфига |
| `subject` / `subject_name` | subject |
| `issuer` / `issuer_name` | issuer |
| `serial_hex` | серийный номер |
| `thumbprint` | SHA-1 отпечаток (hex) |
| `not_before` / `not_after` | строки |
| `not_before_unix` / `not_after_unix` | unix time |
| `cert_b64` | DER сертификата, base64 |

---

## `POST /v1/sign`

Упрощённая подпись. Content-Type:

- `application/json` — JSON-тело;
- `application/octet-stream` — сырые байты контента; параметры в query.

### JSON

```json
{
  "key_id": "roman",
  "content_b64": "…",
  "attached": false,
  "tsa": null
}
```

| Поле | Описание |
|------|----------|
| `key_id` | опционально; иначе первый разрешённый ключ |
| `content_b64` | контент |
| `attached` | `true` → attached CMS, иначе detached |
| `tsa` | см. ниже |

**`tsa`:**

| Значение | Поведение |
|----------|-----------|
| отсутствует / `null` | default TSA из конфига → при наличии URL будет **CAdES-T**, иначе BES |
| `false` | принудительно BES, без TSA |
| `true` | default TSA (ошибка, если в конфиге нет) |
| `"http://…"` | этот TSA → CAdES-T |

### Octet-stream

Тело = байты документа. Query:

- `key_id=…`
- `attached=1` / `true`
- `tsa=0|false` — BES; иначе default/URL как у JSON

### Ответ 200

```json
{
  "profile": "CAdES-BES",
  "signature_b64": "…",
  "key_id": "roman",
  "content_digest_hex": "…"
}
```

`profile` — `CAdES-BES` или `CAdES-T` (этот endpoint не поднимает до XLT1/A).

---

## `POST /v1/enhance`

Повышение профиля без private key (TSA + сеть для XLT1/A). Цель задаётся строкой `profile`, не CADESCOM-константами.

```json
{
  "signature_b64": "…",
  "content_b64": null,
  "content_hash_hex": "…",
  "content_hash_b64": null,
  "profile": "a",
  "tsa": "http://qs.cryptopro.ru/tsp/tsp.srf"
}
```

| Поле | Описание |
|------|----------|
| `signature_b64` | входной CMS |
| `content_b64` | оригинал (detached) |
| `content_hash_hex` / `content_hash_b64` | вместо content для **CAdES-A** |
| `profile` | цель: `t`, `xlt1` (default), `a` / `archive` |
| `tsa` | URL; иначе default конфига |

Шаги по цели: при необходимости BES→T, затем XLT1, затем A (ATSv3).

Для A и detached нужен content **или** content-hash (= `messageDigest`).

**Ответ 200**

```json
{
  "profile": "CAdES-A",
  "signature_b64": "…"
}
```

Для shim с CADESCOM `cades_type` см. [`POST /nmcades/enhance`](#post-nmcadesenhance).

---

## `POST /v1/attach`

Встроить контент в detached CMS (`eContent`). `SignerInfo` / unsigned attrs не меняются; перед ответом — локальный verify (в т.ч. ATSv3 для A).

```json
{
  "signature_b64": "…",
  "content_b64": "…"
}
```

**Ответ 200**

```json
{
  "signature_b64": "…",
  "detached": false,
  "content_len": 1234
}
```

---

## `POST /v1/detach`

Убрать `eContent` из attached CMS. В ответе — detached-подпись и извлечённый контент.

```json
{
  "signature_b64": "…"
}
```

**Ответ 200**

```json
{
  "signature_b64": "…",
  "content_b64": "…",
  "detached": true,
  "content_len": 1234
}
```

---

## `POST /nmcades/sign`

Полная подпись под CryptoPro/nmcades (включая SignHash и профили до A).

```json
{
  "thumbprint": "…",
  "key_id": "roman",
  "content_b64": "…",
  "hash_hex": null,
  "hash_b64": null,
  "detached": true,
  "cades_type": 1,
  "tsa": "http://qs.cryptopro.ru/tsp/tsp.srf",
  "attrs": []
}
```

| Поле | Описание |
|------|----------|
| `thumbprint` / `key_id` | выбор ключа (хотя бы один путь через ACL) |
| `content_b64` | контент (можно пусто при SignHash) |
| `hash_hex` / `hash_b64` | готовый digest → SignHash; CMS detached |
| `detached` | detached CMS (при hash всегда detached) |
| `cades_type` | `1` / `5` / `0x5d` / `0xdd` (default `1` BES) |
| `tsa` | URL; иначе default из конфига (нужен для T/XLT1/A) |
| `attrs` | доп. signed attrs: `{ "name": <int>, "value": "…" }` |

Нужен `content_b64` **или** `hash_hex`/`hash_b64`.

Для **CAdES-A** при SignHash (пустой content) ATSv3 берёт `messageDigest` из CMS — полный файл не обязателен.

**Ответ 200** — как у `/v1/sign` (`profile`, `signature_b64`, `key_id`, `content_digest_hex`).

---

## `POST /nmcades/verify`

Локальная проверка CMS/CAdES (крипто + messageDigest; не полный PKI trust).

```json
{
  "signature_b64": "…",
  "content_b64": "…",
  "content_hash_hex": null,
  "content_hash_b64": null,
  "detached": true
}
```

Для detached: **`content_b64` или `content_hash_hex`/`content_hash_b64`** (не оба).  
Хеш = `messageDigest` (Streebog подписи). Достаточно и для ATSv3 imprint.

**Ответ 200**

```json
{
  "ok": true,
  "signature_valid": true,
  "message_digest_valid": true,
  "signing_certificate_v2_valid": true,
  "detached": true,
  "thumbprint": "…",
  "subject": "…",
  "cert_b64": "…"
}
```

---

## `POST /nmcades/hash`

```json
{
  "algorithm": 101,
  "data_b64": "…",
  "data_encoding": 0
}
```

| `algorithm` | Хеш |
|------------:|------|
| `101` / `100` | Streebog-256 |
| `102` | Streebog-512 |

**Ответ 200**

```json
{
  "hash_hex": "…",
  "hash_b64": "…"
}
```

---

## `POST /nmcades/raw-sign`

Сырая GOST R 34.10 подпись уже посчитанного digest (без CMS).

```json
{
  "thumbprint": "…",
  "key_id": "roman",
  "hash_hex": "…",
  "hash_b64": null
}
```

**Ответ 200**

```json
{
  "signature_b64": "…",
  "signature_hex": "…",
  "key_id": "roman"
}
```

---

## `POST /nmcades/raw-verify`

```json
{
  "thumbprint": "…",
  "cert_b64": null,
  "hash_hex": "…",
  "signature_b64": "…"
}
```

Ключ: `thumbprint` из store **или** `cert_b64` (внешний сертификат).

**Ответ 200**

```json
{ "ok": true }
```

---

## `POST /nmcades/enhance`

Тот же пайплайн, что [`POST /v1/enhance`](#post-v1enhance), но цель — CADESCOM `cades_type` (для shim EnhanceCades).

```json
{
  "signature_b64": "…",
  "content_b64": null,
  "content_hash_hex": "…",
  "content_hash_b64": null,
  "cades_type": 221,
  "tsa": "http://qs.cryptopro.ru/tsp/tsp.srf"
}
```

| Поле | Описание |
|------|----------|
| `cades_type` | цель: `5` T, `0x5d` XLT1 (default), `0xdd` A |
| остальные | как у `/v1/enhance` |

**Ответ 200** — `{ "profile", "signature_b64" }`.

---

## `POST /nmcades/xml-sign`

```json
{
  "content": "<Document>…</Document>",
  "thumbprint": "…",
  "key_id": "roman",
  "signature_type": 0,
  "digest_method": null,
  "signature_method": null,
  "xpath": null,
  "xades_flags": 32,
  "tsa": null
}
```

| Поле | Описание |
|------|----------|
| `content` | XML-строка |
| `signature_type` | `0` enveloped, `1` enveloping, `2` template |
| `xades_flags` | `0` XMLDSIG, `0x20` BES, `0x50` T, `0x5d0` XLT1, `0x7d0` A |
| `digest_method` / `signature_method` | URI; иначе по размеру ключа |
| `xpath` | для template |
| `tsa` | для T/XLT1 |

**Ответ 200**

```json
{ "signed_xml": "…" }
```

---

## `POST /nmcades/xml-verify`

```json
{
  "signed_xml": "…",
  "xpath": null
}
```

**Ответ 200**

```json
{
  "ok": true,
  "signature_valid": true,
  "references_valid": true,
  "cert_b64": "…",
  "thumbprint": "…",
  "subject": "…"
}
```

---

## Конфиг (`examples/daemon.json`)

```json
{
  "listen": "127.0.0.1:8787",
  "tsa": "http://qs.cryptopro.ru/tsp/tsp.srf",
  "tsa_timeout_secs": 20,
  "tsa_policy": null,
  "token_pin": "12345678",
  "token_pin_file": null,
  "keys": [
    {
      "id": "roman",
      "container_dir": "../roman",
      "pin_file": "../roman.pin"
    }
  ],
  "api_keys": [
    {
      "origins": ["http://localhost:3000"],
      "allow": ["roman"]
    },
    {
      "token": "dev-token-change-me",
      "allow": ["*"]
    }
  ]
}
```

| Поле | Описание |
|------|----------|
| `listen` | bind address |
| `tsa` / `tsa_timeout_secs` / `tsa_policy` | default TSA |
| `token_pin` / `token_pin_file` | для nmcades-host / Rutoken |
| `keys[]` | HDIMAGE-контейнеры (`pin` или `pin_file`) |
| `api_keys[]` | ACL: token и/или origins + `allow` |

Переменная `JEX_DAEMON_WORKERS` — число worker-потоков (по умолчанию = parallelism).

---

## Примеры curl

Предпочтительно [`api-v1.md`](api-v1.md). Legacy:

```bash
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8787/api/v1

curl -s -H "Authorization: Bearer dev-token-change-me" \
  http://127.0.0.1:8787/api/v1/keys

curl -s -H "Authorization: Bearer dev-token-change-me" \
  -H "Content-Type: application/json" \
  -d '{"key_id":"roman","profile":"bes","mode":"detached","content":{"b64":"aGVsbG8="}}' \
  http://127.0.0.1:8787/api/v1/sign
```
