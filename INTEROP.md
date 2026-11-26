# Interoperability status

Known-good final construction:

```text
CAdES-T
  -> collect document signer validation material
  -> augment signature timestamp with nested TSA evidence
  -> provisional CAdES-C timestamp to discover .25 TSA signer
  -> collect signature-TSA + .25-TSA evidence into outer .21/.22/.23/.24
  -> final CAdES-C timestamp over completed .21/.22
  -> augment final .25 with its nested TSA evidence
  -> archive-time-stamp-v3 + ATSHashIndexV3
```

Validated locally with CryptoPro CryptCP 5.0 / CSP 5.0.13800 on macOS ARM64 and CAdES runtime 2.0.15700:

```text
-xlongtype1: PASS
-cadesa:     PASS
```

Successful CAdES-A output includes:

```text
Штамп времени на подпись
Штамп времени на доказательства
Архивный штамп времени
Подпись проверена.
```

The important CryptoPro-specific behavior is historical/offline validation of the pre-existing `.25` timestamp in CAdES-A mode. If the TSA status evidence is only nested or only copied as values without matching outer refs, CryptCP may report:

```text
Cannot find OCSP response for certificate. Download prohibited.
```

The final implementation avoids that state by building a complete outer refs-to-values set before issuing the final `.25`.

## Local verification before external policy validation

The production `cades verify` path is profile-aware and rejects partial XLT1 structures. It verifies the document GOST signature, signature timestamp CMS/GOST signature, CAdES-C timestamp CMS/GOST signature, refs-to-values mappings, the CryptoPro offline outer TSA OCSP bindings, ATSHashIndexV3/archive imprints and every archive timestamp CMS/GOST signature.

It intentionally does not replace a system PKI policy engine: trust-anchor selection, certificate-chain signature validation and revocation-policy acceptance remain external-policy checks.
