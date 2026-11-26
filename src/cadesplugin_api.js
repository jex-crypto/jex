// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
/* CryptoPro ЭЦП Browser plug-in API (compatible shim). */
;(function () {
    if (window.cadesplugin && window.cadesplugin.LOG_LEVEL_DEBUG !== undefined && window.cadesplugin.__nmcades_shim) {
        return;
    }

    var canPromise = !!window.Promise;
    var plugin_resolve;
    var plugin_reject;
    var cadesplugin;

    if (canPromise) {
        cadesplugin = new window.Promise(function (resolve, reject) {
            plugin_resolve = resolve;
            plugin_reject = reject;
        });
    } else {
        cadesplugin = {};
    }

    cadesplugin.__nmcades_shim = true;
    cadesplugin.JSModuleVersion = "2.4.2";
    cadesplugin.async_spawn = async_spawn;
    cadesplugin.getLastError = getLastError;
    cadesplugin.set_log_level = set_log_level;
    cadesplugin.get_extension_version = function (cb) { if (cb) cb("2.0.0"); };
    cadesplugin.get_extension_id = function (cb) { if (cb) cb("iifchhfnnmpdbibifmljnfjhpififfog"); };

    cadesplugin.LOG_LEVEL_DEBUG = 4;
    cadesplugin.LOG_LEVEL_INFO = 2;
    cadesplugin.LOG_LEVEL_ERROR = 1;
    cadesplugin.current_log_level = cadesplugin.LOG_LEVEL_ERROR;

    function set_constantValues() {
        cadesplugin.CAPICOM_MEMORY_STORE = 0;
        cadesplugin.CAPICOM_LOCAL_MACHINE_STORE = 1;
        cadesplugin.CAPICOM_CURRENT_USER_STORE = 2;
        cadesplugin.CAPICOM_SMART_CARD_USER_STORE = 4;
        cadesplugin.CADESCOM_MEMORY_STORE = 0;
        cadesplugin.CADESCOM_LOCAL_MACHINE_STORE = 1;
        cadesplugin.CADESCOM_CURRENT_USER_STORE = 2;
        cadesplugin.CADESCOM_SMART_CARD_USER_STORE = 4;
        cadesplugin.CADESCOM_CONTAINER_STORE = 100;

        cadesplugin.CAPICOM_ROOT_STORE = "Root";
        cadesplugin.CAPICOM_CA_STORE = "CA";
        cadesplugin.CAPICOM_MY_STORE = "My";
        cadesplugin.CAPICOM_ADDRESSBOOK_STORE = "AddressBook";

        cadesplugin.CAPICOM_STORE_OPEN_READ_WRITE = 1;
        cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;
        cadesplugin.CAPICOM_STORE_OPEN_INCLUDE_ARCHIVED = 256;

        cadesplugin.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;

        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0;
        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING = 1;
        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE = 2;

        cadesplugin.CADESCOM_XADES_DEFAULT = 0x00000010;
        cadesplugin.CADESCOM_XADES_BES = 0x00000020;
        cadesplugin.CADESCOM_XADES_T = 0x00000050;
        cadesplugin.CADESCOM_XADES_X_LONG_TYPE_1 = 0x000005d0;
        cadesplugin.CADESCOM_XADES_A = 0x000007d0;
        cadesplugin.CADESCOM_XMLDSIG_TYPE = 0x00000000;

        cadesplugin.XmlDsigGost3410UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
        cadesplugin.XmlDsigGost3411UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
        cadesplugin.XmlDsigGost3410Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
        cadesplugin.XmlDsigGost3411Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

        cadesplugin.XmlDsigGost3411Url2012256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        cadesplugin.XmlDsigGost3410Url2012256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
        cadesplugin.XmlDsigGost3411Url2012512 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
        cadesplugin.XmlDsigGost3410Url2012512 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

        cadesplugin.CADESCOM_CADES_DEFAULT = 0;
        cadesplugin.CADESCOM_CADES_BES = 1;
        cadesplugin.CADESCOM_CADES_T = 0x5;
        cadesplugin.CADESCOM_CADES_X_LONG_TYPE_1 = 0x5d;
        cadesplugin.CADESCOM_CADES_A = 0xdd;
        cadesplugin.CADESCOM_PKCS7_TYPE = 0xffff;

        cadesplugin.CADESCOM_ENCODE_BASE64 = 0;
        cadesplugin.CADESCOM_ENCODE_BINARY = 1;
        cadesplugin.CADESCOM_ENCODE_ANY = -1;

        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT = 0;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN = 1;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY = 2;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_NONE = 0x100;

        cadesplugin.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME = 0;
        cadesplugin.CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME = 1;

        cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_ISSUER_NAME = 2;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_ROOT_NAME = 3;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME = 4;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENSION = 5;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY = 6;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_APPLICATION_POLICY = 7;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY = 8;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_VALID = 9;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID = 10;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED = 11;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_KEY_USAGE = 12;

        cadesplugin.CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE = 128;

        cadesplugin.CAPICOM_PROPID_ENHKEY_USAGE = 9;

        cadesplugin.CAPICOM_OID_OTHER = 0;
        cadesplugin.CAPICOM_OID_KEY_USAGE_EXTENSION = 10;

        cadesplugin.CAPICOM_EKU_CLIENT_AUTH = 2;
        cadesplugin.CAPICOM_EKU_SMARTCARD_LOGON = 5;
        cadesplugin.CAPICOM_EKU_OTHER = 0;

        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_MACHINE_INFO = 0x100;
        cadesplugin.CADESCOM_ATTRIBUTE_OTHER = -1;

        cadesplugin.CADESCOM_STRING_TO_UCS2LE = 0;
        cadesplugin.CADESCOM_BASE64_TO_BINARY = 1;

        cadesplugin.CADESCOM_DISPLAY_DATA_NONE = 0;
        cadesplugin.CADESCOM_DISPLAY_DATA_CONTENT = 1;
        cadesplugin.CADESCOM_DISPLAY_DATA_ATTRIBUTE = 2;

        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_RC2 = 0;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_RC4 = 1;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_DES = 2;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_3DES = 3;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_AES = 4;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89 = 25;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA = 35;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA_OMAC = 36;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK = 45;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK_OMAC = 46;

        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA1 = 0;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD2 = 1;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD4 = 2;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD5 = 3;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_256 = 4;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_384 = 5;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_512 = 6;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411 = 100;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 = 101;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 = 102;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_HMAC = 110;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC = 111;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512_HMAC = 112;

        cadesplugin.CADESCOM_CERT_INFO_ROLE = 100;
        cadesplugin.CADESCOM_ROLE_ROOT = "ROOT";
        cadesplugin.CADESCOM_ROLE_CA = "CA";
        cadesplugin.CADESCOM_ROLE_LEAF = "LEAF";

        cadesplugin.LOG_LEVEL_DEBUG = 4;
        cadesplugin.LOG_LEVEL_INFO = 2;
        cadesplugin.LOG_LEVEL_ERROR = 1;

        cadesplugin.CADESCOM_AllowNone = 0;
        cadesplugin.CADESCOM_AllowNoOutstandingRequest = 0x1;
        cadesplugin.CADESCOM_AllowUntrustedCertificate = 0x2;
        cadesplugin.CADESCOM_AllowUntrustedRoot = 0x4;
        cadesplugin.CADESCOM_SkipInstallToStore = 0x10000000;
        cadesplugin.CADESCOM_InstallCertChainToContainer = 0x20000000;
        cadesplugin.CADESCOM_UseContainerStore = 0x40000000;

        cadesplugin.ContextNone = 0;
        cadesplugin.ContextUser = 0x1;
        cadesplugin.ContextMachine = 0x2;
        cadesplugin.ContextAdministratorForceMachine = 0x3;

        cadesplugin.ENABLE_CARRIER_TYPE_CSP = 0x01;
        cadesplugin.ENABLE_CARRIER_TYPE_FKC_NO_SM = 0x02;
        cadesplugin.ENABLE_CARRIER_TYPE_FKC_SM = 0x04;
        cadesplugin.ENABLE_ANY_CARRIER_TYPE = 0x07;

        cadesplugin.DISABLE_EVERY_CARRIER_OPERATION = 0x00;
        cadesplugin.ENABLE_CARRIER_OPEN_ENUM = 0x01;
        cadesplugin.ENABLE_CARRIER_CREATE = 0x02;
        cadesplugin.ENABLE_ANY_OPERATION = 0x03;

        cadesplugin.CADESCOM_PRODUCT_CSP = 0;
        cadesplugin.CADESCOM_PRODUCT_OCSP = 1;
        cadesplugin.CADESCOM_PRODUCT_TSP = 2;

        cadesplugin.MEDIA_TYPE_DEFAULT = 0x00000000;
        cadesplugin.MEDIA_TYPE_REGISTRY = 0x00000001;
        cadesplugin.MEDIA_TYPE_HDIMAGE = 0x00000002;
        cadesplugin.MEDIA_TYPE_CLOUD = 0x00000004;
        cadesplugin.MEDIA_TYPE_SCARD = 0x00000008;

        cadesplugin.XCN_CRYPT_STRING_BASE64HEADER = 0;
        cadesplugin.XCN_CRYPT_STRING_BASE64 = 0x1;
        cadesplugin.XCN_CRYPT_STRING_BINARY = 0x2;
        cadesplugin.XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3;
        cadesplugin.XCN_CRYPT_STRING_HEX = 0x4;
        cadesplugin.XCN_CRYPT_STRING_HEXASCII = 0x5;
        cadesplugin.XCN_CRYPT_STRING_BASE64_ANY = 0x6;
        cadesplugin.XCN_CRYPT_STRING_ANY = 0x7;
        cadesplugin.XCN_CRYPT_STRING_HEX_ANY = 0x8;
        cadesplugin.XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9;
        cadesplugin.XCN_CRYPT_STRING_HEXADDR = 0xa;
        cadesplugin.XCN_CRYPT_STRING_HEXASCIIADDR = 0xb;
        cadesplugin.XCN_CRYPT_STRING_HEXRAW = 0xc;
        cadesplugin.XCN_CRYPT_STRING_BASE64URI = 0xd;
        cadesplugin.XCN_CRYPT_STRING_ENCODEMASK = 0xff;
        cadesplugin.XCN_CRYPT_STRING_CHAIN = 0x100;
        cadesplugin.XCN_CRYPT_STRING_TEXT = 0x200;
        cadesplugin.XCN_CRYPT_STRING_PERCENTESCAPE = 0x8000000;
        cadesplugin.XCN_CRYPT_STRING_HASHDATA = 0x10000000;
        cadesplugin.XCN_CRYPT_STRING_STRICT = 0x20000000;
        cadesplugin.XCN_CRYPT_STRING_NOCRLF = 0x40000000;
        cadesplugin.XCN_CRYPT_STRING_NOCR = 0x80000000;

        cadesplugin.XCN_CERT_NAME_STR_NONE = 0;
        cadesplugin.XCN_AT_NONE = 0;
        cadesplugin.XCN_AT_KEYEXCHANGE = 1;
        cadesplugin.XCN_AT_SIGNATURE = 2;

        cadesplugin.AT_KEYEXCHANGE = 1;
        cadesplugin.AT_SIGNATURE = 2;

        cadesplugin.CARRIER_FLAG_REMOVABLE = 1;
        cadesplugin.CARRIER_FLAG_UNIQUE = 2;
        cadesplugin.CARRIER_FLAG_PROTECTED = 4;
        cadesplugin.CARRIER_FLAG_FUNCTIONAL_CARRIER = 8;
        cadesplugin.CARRIER_FLAG_SECURE_MESSAGING = 16;
        cadesplugin.CARRIER_FLAG_ABLE_SET_KEY = 32;
        cadesplugin.CARRIER_FLAG_ABLE_VISUALISE_SIGNATURE = 64;
        cadesplugin.CARRIER_FLAG_VIRTUAL = 128;

        cadesplugin.CRYPT_MODE_CBCSTRICT = 1;
        cadesplugin.CRYPT_MODE_CNT = 3;
        cadesplugin.CRYPT_MODE_CBCRFC4357 = 31;
        cadesplugin.CRYPT_MODE_CTR = 32;
        cadesplugin.CRYPT_MODE_MGM = 33;
        cadesplugin.CRYPT_MODE_GCM = 34;
        cadesplugin.CRYPT_MODE_OMAC_CTR = 35;
        cadesplugin.CRYPT_MODE_WRAP = 36;
        cadesplugin.CRYPT_MODE_WRAP_PAD = 37;

        cadesplugin.PKCS5_PADDING = 1;
        cadesplugin.RANDOM_PADDING = 2;
        cadesplugin.ZERO_PADDING = 3;
        cadesplugin.ISO10126_PADDING = 4;
        cadesplugin.ANSI_X923_PADDING = 5;
        cadesplugin.TLS_1_0_PADDING = 6;
        cadesplugin.ISO_IEC_7816_4_PADDING = 7;

        cadesplugin.CAPICOM_STORE_SAVE_AS_SERIALIZED = 0;
        cadesplugin.CAPICOM_STORE_SAVE_AS_PKCS7 = 1;

        cadesplugin.CADESCOM_IDSCANNER_IMAGE_TYPE_W = 0x00;
        cadesplugin.CADESCOM_IDSCANNER_IMAGE_TYPE_IR = 0x01;
        cadesplugin.CADESCOM_IDSCANNER_IMAGE_TYPE_UV = 0x02;

        cadesplugin.CERT_TRUST_NO_ERROR = 0x00000000;
        cadesplugin.CERT_TRUST_IS_NOT_TIME_VALID = 0x00000001;
        cadesplugin.CERT_TRUST_IS_REVOKED = 0x00000004;
        cadesplugin.CERT_TRUST_IS_NOT_SIGNATURE_VALID = 0x00000008;
        cadesplugin.CERT_TRUST_IS_NOT_VALID_FOR_USAGE = 0x00000010;
        cadesplugin.CERT_TRUST_IS_UNTRUSTED_ROOT = 0x00000020;
        cadesplugin.CERT_TRUST_REVOCATION_STATUS_UNKNOWN = 0x00000040;
        cadesplugin.CERT_TRUST_IS_CYCLIC = 0x00000080;
        cadesplugin.CERT_TRUST_INVALID_EXTENSION = 0x00000100;
        cadesplugin.CERT_TRUST_INVALID_POLICY_CONSTRAINTS = 0x00000200;
        cadesplugin.CERT_TRUST_INVALID_BASIC_CONSTRAINTS = 0x00000400;
        cadesplugin.CERT_TRUST_INVALID_NAME_CONSTRAINTS = 0x00000800;
        cadesplugin.CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x00001000;
        cadesplugin.CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT = 0x00002000;
        cadesplugin.CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x00004000;
        cadesplugin.CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT = 0x00008000;
        cadesplugin.CERT_TRUST_IS_OFFLINE_REVOCATION = 0x01000000;
        cadesplugin.CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY = 0x02000000;
        cadesplugin.CERT_TRUST_IS_EXPLICIT_DISTRUST = 0x04000000;
        cadesplugin.CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT = 0x08000000;
        cadesplugin.CERT_TRUST_HAS_WEAK_SIGNATURE = 0x00100000;

        cadesplugin.XCN_CERT_NO_KEY_USAGE = 0;
        cadesplugin.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x80;
        cadesplugin.XCN_CERT_NON_REPUDIATION_KEY_USAGE = 0x40;
        cadesplugin.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x20;
        cadesplugin.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE = 0x10;
        cadesplugin.XCN_CERT_KEY_AGREEMENT_KEY_USAGE = 0x8;
        cadesplugin.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE = 0x4;
        cadesplugin.XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 0x2;
        cadesplugin.XCN_CERT_CRL_SIGN_KEY_USAGE = 0x2;
        cadesplugin.XCN_CERT_ENCIPHER_ONLY_KEY_USAGE = 0x1;
        cadesplugin.XCN_CERT_DECIPHER_ONLY_KEY_USAGE = 0x8000;

        cadesplugin.CADESCOM_XADES_ACCEPT_ANY_ID_ATTR_NAMESPACE = 1;
        cadesplugin.CADES_USE_OCSP_AUTHORIZED_POLICY = 0x00020000;

        cadesplugin.XCN_NCRYPT_NO_OPERATION = 0;
        cadesplugin.XCN_NCRYPT_CIPHER_OPERATION = 0x1;
        cadesplugin.XCN_NCRYPT_HASH_OPERATION = 0x2;
        cadesplugin.XCN_NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x4;
        cadesplugin.XCN_NCRYPT_SECRET_AGREEMENT_OPERATION = 0x8;
        cadesplugin.XCN_NCRYPT_SIGNATURE_OPERATION = 0x10;
        cadesplugin.XCN_NCRYPT_RNG_OPERATION = 0x20;

        cadesplugin.XCN_CRYPT_ANY_GROUP_ID = 0;
        cadesplugin.XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 1;
        cadesplugin.XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2;
        cadesplugin.XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3;
        cadesplugin.XCN_CRYPT_SIGN_ALG_OID_GROUP_ID = 4;
        cadesplugin.XCN_CRYPT_RDN_ATTR_OID_GROUP_ID = 5;
        cadesplugin.XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6;
        cadesplugin.XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7;
        cadesplugin.XCN_CRYPT_POLICY_OID_GROUP_ID = 8;
        cadesplugin.XCN_CRYPT_TEMPLATE_OID_GROUP_ID = 9;

        cadesplugin.XCN_CRYPT_OID_INFO_PUBKEY_ANY = 0;
        cadesplugin.XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = 0x80000000;
        cadesplugin.XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = 0x40000000;

        cadesplugin.CONTROL_KEY_TIME_VALIDITY_DISABLED = 0;
        cadesplugin.CONTROL_KEY_TIME_VALIDITY_ENABLED = 1;
        cadesplugin.CONTROL_KEY_TIME_VALIDITY_STRICT = 2;

        cadesplugin.AlgorithmFlagsNone = 0;
        cadesplugin.AlgorithmFlagsWrap = 0x1;
    }

    var BASE = detectBaseUrl();
    var certCache = null;
    var signerStates = typeof WeakMap !== "undefined" ? new WeakMap() : null;

    function detectBaseUrl() {
        if (typeof window.cadesplugin_base_url === "string" && window.cadesplugin_base_url) {
            return window.cadesplugin_base_url.replace(/\/$/, "");
        }
        var scripts = document.getElementsByTagName("script");
        for (var i = scripts.length - 1; i >= 0; i--) {
            var src = scripts[i].src || "";
            var m = src.match(/^(.*)\/cadesplugin_api\.js(?:\?.*)?$/i);
            if (m) return m[1];
        }
        return "http://127.0.0.1:8787";
    }

    function set_log_level(level) {
        if (level === cadesplugin.LOG_LEVEL_DEBUG ||
            level === cadesplugin.LOG_LEVEL_INFO ||
            level === cadesplugin.LOG_LEVEL_ERROR) {
            cadesplugin.current_log_level = level;
        }
    }

    function cpcsp_console_log(level, msg) {
        if (typeof console === "undefined") return;
        if (level > cadesplugin.current_log_level) return;
        if (level === cadesplugin.LOG_LEVEL_ERROR) console.error(msg);
        else if (level === cadesplugin.LOG_LEVEL_INFO) console.info(msg);
        else console.log(msg);
    }

    function getLastError(exception) {
        if (!exception) return "Unknown error";
        if (typeof exception === "string") return exception;
        if (exception.message) return exception.message;
        return String(exception);
    }

    function async_spawn(generatorFunc) {
        function continuer(verb, arg) {
            var result;
            try { result = generator[verb](arg); }
            catch (err) { return window.Promise.reject(err); }
            if (result.done) return result.value;
            return window.Promise.resolve(result.value).then(onFulfilled, onRejected);
        }
        var generator = generatorFunc(Array.prototype.slice.call(arguments, 1));
        var onFulfilled = continuer.bind(continuer, "next");
        var onRejected = continuer.bind(continuer, "throw");
        return onFulfilled();
    }

    function apiFetch(path, opts) {
        opts = opts || {};
        var headers = opts.headers || {};
        headers["Accept"] = "application/json";
        if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
        return fetch(BASE + path, {
            method: opts.method || "GET",
            headers: headers,
            body: opts.body,
            credentials: "omit"
        }).then(function (resp) {
            return resp.text().then(function (text) {
                var data = null;
                try { data = text ? JSON.parse(text) : null; } catch (e) { data = { error: text }; }
                if (!resp.ok) {
                    var msg = (data && data.error) ? data.error : ("HTTP " + resp.status);
                    throw new Error(msg);
                }
                return data;
            });
        });
    }

    function loadCertificates(force) {
        if (certCache && !force) return window.Promise.resolve(certCache);
        return apiFetch("/nmcades/certificates").then(function (list) {
            certCache = list || [];
            return certCache;
        });
    }

    function makeAsyncProxy(handlers) {
        return new Proxy({}, {
            get: function (_t, prop) {
                if (prop === "then" || typeof prop === "symbol") return undefined;
                if (handlers[prop] !== undefined) {
                    var v = handlers[prop];
                    if (typeof v === "function") {
                        return function () {
                            var args = arguments;
                            return window.Promise.resolve().then(function () {
                                return v.apply(handlers, args);
                            });
                        };
                    }
                    return window.Promise.resolve().then(function () {
                        return typeof v === "function" ? v() : v;
                    });
                }
                if (String(prop).indexOf("propset_") === 0) {
                    var name = String(prop).substring(8);
                    return function (value) {
                        return window.Promise.resolve().then(function () {
                            if (typeof handlers["set_" + name] === "function") {
                                return handlers["set_" + name](value);
                            }
                            handlers["_" + name] = value;
                        });
                    };
                }
                return function () {
                    return window.Promise.reject(new Error("Method " + String(prop) + " is not implemented"));
                };
            }
        });
    }

    function createCertificate(meta) {
        var handlers = {
            get SubjectName() { return meta.subject_name; },
            get IssuerName() { return meta.issuer_name; },
            get Thumbprint() { return meta.thumbprint; },
            get SerialNumber() { return meta.serial_hex; },
            get ValidFromDate() { return new Date(meta.not_before_unix * 1000); },
            get ValidToDate() { return new Date(meta.not_after_unix * 1000); },
            get HasPrivateKey() { return true; },
            Export: function (encoding) {
                if (encoding === undefined || encoding === 0) return meta.cert_b64;
                throw new Error("Unsupported Export encoding");
            },
            GetInfo: function (infoType) {
                if (infoType === 0) return meta.subject;
                if (infoType === 1) return meta.issuer;
                return meta.subject;
            },
            FindPrivateKey: function () {},
            IsValid: function () {
                return makeAsyncProxy({
                    get Result() { return true; },
                    get ValidationResult() { return true; }
                });
            },
            get PrivateKey() {
                return makeAsyncProxy({
                    set_CachePin: function () {},
                    get ProviderName() { return "Jex GOST R 34.10-2012 Cryptographic Service Provider"; },
                    get UniqueContainerName() { return meta.id; }
                });
            },
            get PublicKey() {
                return makeAsyncProxy({
                    get Algorithm() {
                        return makeAsyncProxy({
                            get Value() { return "172.16.0.4.2.19"; }
                        });
                    }
                });
            },
            get ExtendedKeyUsage() {
                return makeAsyncProxy({
                    get EKUs() {
                        return makeAsyncProxy({
                            get Count() { return 0; },
                            Item: function () { throw new Error("EKU index out of range"); }
                        });
                    }
                });
            },
            _meta: meta
        };
        return makeAsyncProxy(handlers);
    }

    function createCertificates(list) {
        var items = list.slice();
        return makeAsyncProxy({
            get Count() { return items.length; },
            Item: function (index) {
                var i = index - 1;
                if (i < 0 || i >= items.length) throw new Error("Certificate index out of range");
                return createCertificate(items[i]);
            },
            Find: function (findType, query) {
                var q = (query === undefined || query === null) ? "" : String(query);
                var filtered = items.filter(function (c) {
                    if (findType === 0) {
                        return c.thumbprint.toUpperCase() === q.replace(/\s+/g, "").toUpperCase();
                    }
                    if (findType === 1) {
                        return (c.subject_name + " " + c.subject).toLowerCase().indexOf(q.toLowerCase()) !== -1;
                    }
                    if (findType === 2) {
                        return (c.issuer_name + " " + c.issuer).toLowerCase().indexOf(q.toLowerCase()) !== -1;
                    }
                    return true;
                });
                return createCertificates(filtered);
            }
        });
    }

    function createStore() {
        var opened = false;
        var certs = [];
        return makeAsyncProxy({
            Open: function () {
                return loadCertificates(true).then(function (list) {
                    certs = list;
                    opened = true;
                });
            },
            Close: function () { opened = false; },
            get Certificates() {
                if (!opened) throw new Error("Store is not opened");
                return createCertificates(certs);
            }
        });
    }

    function createAttribute() {
        var state = { name: 0, value: "", valueEncoding: 0 };
        var obj = makeAsyncProxy({
            set_Name: function (v) { state.name = v; },
            set_Value: function (v) {
                if (v instanceof Date) state.value = String(Math.floor(v.getTime() / 1000));
                else state.value = v == null ? "" : String(v);
            },
            set_ValueEncoding: function (v) { state.valueEncoding = v; },
            get Name() { return state.name; },
            get Value() { return state.value; }
        });
        obj.__attr = state;
        return obj;
    }

    function createAttrs2(listRef) {
        return makeAsyncProxy({
            Add: function (attr) {
                var st = attr && attr.__attr;
                if (!st) throw new Error("CPAttribute expected");
                listRef.push({ name: st.name, value: st.value });
            },
            Clear: function () { listRef.length = 0; },
            Remove: function (index) { listRef.splice(index - 1, 1); },
            get Count() { return listRef.length; },
            Item: function (index) {
                var a = listRef[index - 1];
                if (!a) throw new Error("attribute index out of range");
                var o = createAttribute();
                o.__attr.name = a.name;
                o.__attr.value = a.value;
                return o;
            }
        });
    }

    function createSignerTracked() {
        var state = {
            certificate: null,
            checkCertificate: false,
            tsaAddress: "",
            options: 2,
            attrs: []
        };
        var obj = makeAsyncProxy({
            set_Certificate: function (cert) { state.certificate = cert; },
            set_CheckCertificate: function (v) { state.checkCertificate = !!v; },
            set_TSAAddress: function (v) { state.tsaAddress = v || ""; },
            set_Options: function (v) { state.options = v; },
            set_KeyPin: function () {},
            get Certificate() { return state.certificate; },
            get TSAAddress() { return state.tsaAddress; },
            get AuthenticatedAttributes2() { return createAttrs2(state.attrs); },
            get SigningTime() { return new Date(); },
            get SignatureTimeStampTime() { return new Date(); }
        });
        if (signerStates) signerStates.set(obj, state);
        obj.__state = state;
        return obj;
    }

    function createHashedData() {
        var state = {
            algorithm: 101,
            dataEncoding: 1,
            value: ""
        };
        var handlers = {
            set_Algorithm: function (v) { state.algorithm = v; },
            set_DataEncoding: function (v) { state.dataEncoding = v; },
            set_Value: function (v) { state.value = v || ""; },
            get Algorithm() { return state.algorithm; },
            get DataEncoding() { return state.dataEncoding; },
            get Value() { return state.value; },
            Hash: function (data) {
                var payload;
                if (state.dataEncoding === 1) {
                    payload = { algorithm: state.algorithm, data_b64: data, data_encoding: 1 };
                } else {
                    payload = {
                        algorithm: state.algorithm,
                        data_b64: btoa(unescape(encodeURIComponent(String(data)))),
                        data_encoding: 0
                    };
                }
                return apiFetch("/nmcades/hash", {
                    method: "POST",
                    body: JSON.stringify(payload)
                }).then(function (resp) {
                    state.value = resp.hash_hex;
                    return state.value;
                });
            },
            SetHashValue: function (v) {
                state.value = String(v || "").replace(/\s+/g, "").toUpperCase();
            }
        };
        var obj = makeAsyncProxy(handlers);
        obj.__state = state;
        return obj;
    }

    function createRawSignature() {
        return makeAsyncProxy({
            SignHash: function (hashedData, certThumbOrObj) {
                var hs = hashedData && (hashedData.__state || hashedData);
                return window.Promise.resolve(hashedData.Value).then(function (hashHex) {
                    var body = { hash_hex: hashHex };
                    if (typeof certThumbOrObj === "string") body.thumbprint = certThumbOrObj;
                    return apiFetch("/nmcades/raw-sign", {
                        method: "POST",
                        body: JSON.stringify(body)
                    }).then(function (r) { return r.signature_b64; });
                });
            },
            VerifyHash: function (hashedData, certificate, signature) {
                return window.Promise.resolve(hashedData.Value).then(function (hashHex) {
                    return window.Promise.resolve(certificate.Thumbprint).then(function (tp) {
                        return apiFetch("/nmcades/raw-verify", {
                            method: "POST",
                            body: JSON.stringify({
                                hash_hex: hashHex,
                                thumbprint: tp,
                                signature_b64: signature
                            })
                        }).then(function (r) {
                            if (!r.ok) throw new Error("Raw signature verification failed");
                        });
                    });
                });
            }
        });
    }

    function createSignedDataTracked() {
        var state = {
            content: "",
            contentEncoding: 1,
            displayData: 0,
            lastSignature: "",
            lastContentB64: "",
            signers: []
        };
        function contentToB64() {
            if (state.contentEncoding === 1) return state.content;
            return btoa(unescape(encodeURIComponent(state.content)));
        }
        function signerState(signer) {
            return (signer && signer.__state) || (signerStates && signerStates.get(signer));
        }
        function doSign(signer, cadesType, detached, hashHex) {
            var sstate = signerState(signer);
            if (!sstate || !sstate.certificate) {
                return window.Promise.reject(new Error("Certificate is not set for CPSigner"));
            }
            return window.Promise.resolve(sstate.certificate.Thumbprint).then(function (tp) {
                var body = {
                    thumbprint: String(tp).replace(/\s+/g, ""),
                    detached: !!detached,
                    cades_type: cadesType === undefined ? 1 : cadesType,
                    attrs: sstate.attrs || []
                };
                if (sstate.tsaAddress) body.tsa = sstate.tsaAddress;
                if (hashHex) body.hash_hex = hashHex;
                else {
                    body.content_b64 = contentToB64();
                    state.lastContentB64 = body.content_b64;
                }
                return apiFetch("/nmcades/sign", {
                    method: "POST",
                    body: JSON.stringify(body)
                }).then(function (resp) {
                    state.lastSignature = resp.signature_b64;
                    return resp.signature_b64;
                });
            });
        }
        var obj = makeAsyncProxy({
            set_Content: function (v) { state.content = v == null ? "" : String(v); },
            set_ContentEncoding: function (v) { state.contentEncoding = v; },
            set_DisplayData: function (v) { state.displayData = v; },
            SignCades: function (signer, cadesType, detached) {
                return doSign(signer, cadesType, detached, null);
            },
            SignHash: function (hashedData, signer, cadesType) {
                return window.Promise.resolve(hashedData.Value).then(function (hv) {
                    return doSign(signer, cadesType, true, hv);
                });
            },
            VerifyCades: function (signedMessage, cadesType, detached) {
                var body = {
                    signature_b64: signedMessage,
                    detached: !!detached
                };
                if (detached) body.content_b64 = contentToB64();
                return apiFetch("/nmcades/verify", {
                    method: "POST",
                    body: JSON.stringify(body)
                }).then(function (resp) {
                    if (!resp.ok) throw new Error("Signature verification failed");
                    state.lastSignature = signedMessage;
                    state.signers = [{
                        thumbprint: resp.thumbprint,
                        subject: resp.subject,
                        cert_b64: resp.cert_b64
                    }];
                });
            },
            VerifyHash: function (hashedData, signedMessage, cadesType) {
                return window.Promise.resolve(hashedData.Value).then(function () {
                    return apiFetch("/nmcades/verify", {
                        method: "POST",
                        body: JSON.stringify({
                            signature_b64: signedMessage,
                            detached: true
                        })
                    }).then(function (resp) {
                        if (!resp.ok) throw new Error("Hash signature verification failed");
                        state.lastSignature = signedMessage;
                    });
                });
            },
            EnhanceCades: function (cadesType, tsaAddress) {
                var sig = state.lastSignature;
                if (!sig) throw new Error("No signature to enhance");
                var body = {
                    signature_b64: sig,
                    cades_type: cadesType === undefined ? 0x5d : cadesType
                };
                if (tsaAddress) body.tsa = tsaAddress;
                if (state.lastContentB64) body.content_b64 = state.lastContentB64;
                return apiFetch("/nmcades/enhance", {
                    method: "POST",
                    body: JSON.stringify(body)
                }).then(function (resp) {
                    state.lastSignature = resp.signature_b64;
                    return resp.signature_b64;
                });
            },
            get Signers() {
                return makeAsyncProxy({
                    get Count() { return state.signers.length; },
                    Item: function (index) {
                        var s = state.signers[index - 1];
                        if (!s) throw new Error("signer index out of range");
                        var signer = createSignerTracked();
                        if (s.cert_b64) {
                            var meta = {
                                subject_name: s.subject || "",
                                subject: s.subject || "",
                                issuer_name: "",
                                issuer: "",
                                thumbprint: s.thumbprint || "",
                                serial_hex: "",
                                not_before_unix: 0,
                                not_after_unix: 0,
                                cert_b64: s.cert_b64,
                                id: s.thumbprint || ""
                            };
                            signer.__state.certificate = createCertificate(meta);
                        }
                        return signer;
                    }
                });
            },
            get Certificates() {
                return createCertificates([]);
            }
        });
        obj.__state = state;
        return obj;
    }

    function createSignedXML() {
        var state = {
            content: "",
            digestMethod: cadesplugin.XmlDsigGost3411Url2012256,
            signatureMethod: cadesplugin.XmlDsigGost3410Url2012256,
            signatureType: 0,
            xpath: "",
            lastSigned: "",
            signers: []
        };
        function signerState(signer) {
            return (signer && signer.__state) || (signerStates && signerStates.get(signer));
        }
        function splitSignatureType(raw) {
            // CryptoPro: SignatureType = CADESCOM_XML_SIGNATURE_TYPE_* | CADESCOM_XADES_*
            var n = Number(raw) || 0;
            var packaging = n & 0x3;
            var xades_flags = n & ~0x3;
            if (n >= 0x20 && packaging > 2) {
                packaging = 0;
                xades_flags = n;
            }
            return { packaging: packaging, xades_flags: xades_flags };
        }
        return makeAsyncProxy({
            set_Content: function (v) { state.content = v == null ? "" : String(v); },
            set_DigestMethod: function (v) { state.digestMethod = v; },
            set_SignatureMethod: function (v) { state.signatureMethod = v; },
            set_SignatureType: function (v) { state.signatureType = v; },
            get Content() { return state.content; },
            get DigestMethod() { return state.digestMethod; },
            get SignatureMethod() { return state.signatureMethod; },
            get SignatureType() { return state.signatureType; },
            Sign: function (signer, xpathOrXades) {
                var sstate = signerState(signer);
                if (!sstate || !sstate.certificate) {
                    return window.Promise.reject(new Error("Certificate is not set for CPSigner"));
                }
                return window.Promise.resolve(sstate.certificate.Thumbprint).then(function (tp) {
                    var split = splitSignatureType(state.signatureType);
                    var body = {
                        content: state.content,
                        thumbprint: String(tp).replace(/\s+/g, ""),
                        signature_type: split.packaging,
                        digest_method: state.digestMethod,
                        signature_method: state.signatureMethod,
                        xades_flags: split.xades_flags
                    };
                    if (typeof xpathOrXades === "string" && xpathOrXades) {
                        body.xpath = xpathOrXades;
                    } else if (state.xpath) {
                        body.xpath = state.xpath;
                    }
                    if (sstate.tsaAddress) body.tsa = sstate.tsaAddress;
                    return apiFetch("/nmcades/xml-sign", {
                        method: "POST",
                        body: JSON.stringify(body)
                    }).then(function (resp) {
                        state.lastSigned = resp.signed_xml;
                        state.content = resp.signed_xml;
                        return resp.signed_xml;
                    });
                });
            },
            Verify: function (xpath) {
                var body = { signed_xml: state.content };
                if (xpath) body.xpath = xpath;
                return apiFetch("/nmcades/xml-verify", {
                    method: "POST",
                    body: JSON.stringify(body)
                }).then(function (resp) {
                    if (!resp.ok) throw new Error("XML signature verification failed");
                    state.signers = [{
                        thumbprint: resp.thumbprint,
                        subject: resp.subject,
                        cert_b64: resp.cert_b64
                    }];
                });
            },
            get Signers() {
                return makeAsyncProxy({
                    get Count() { return state.signers.length; },
                    Item: function (index) {
                        var s = state.signers[index - 1];
                        if (!s) throw new Error("signer index out of range");
                        var signer = createSignerTracked();
                        if (s.cert_b64) {
                            var meta = {
                                subject_name: s.subject || "",
                                subject: s.subject || "",
                                issuer_name: "",
                                issuer: "",
                                thumbprint: s.thumbprint || "",
                                serial_hex: "",
                                not_before_unix: 0,
                                not_after_unix: 0,
                                cert_b64: s.cert_b64,
                                id: s.thumbprint || ""
                            };
                            signer.__state.certificate = createCertificate(meta);
                        }
                        return signer;
                    }
                });
            }
        });
    }

    function createAbout() {
        var versionObj = function () {
            return makeAsyncProxy({
                toString: function () { return "2.0.15512"; },
                get MajorVersion() { return 2; },
                get MinorVersion() { return 0; },
                get BuildVersion() { return 15512; }
            });
        };
        var cspVersionObj = function () {
            return makeAsyncProxy({
                toString: function () { return "5.0.13000"; },
                get MajorVersion() { return 5; },
                get MinorVersion() { return 0; },
                get BuildVersion() { return 13000; }
            });
        };
        return makeAsyncProxy({
            get Version() { return "5.0.13000"; },
            get PluginVersion() { return versionObj(); },
            CSPVersion: function () { return cspVersionObj(); },
            get MajorVersion() { return 2; },
            get MinorVersion() { return 0; },
            get BuildVersion() { return 15512; },
            CSPName: function () { return "Jex GOST R 34.10-2012 Cryptographic Service Provider"; },
            ProviderVersion: function () { return "5.0.13000"; },
            toString: function () { return "2.0.15512"; }
        });
    }

    function CreateObjectAsync(name) {
        name = String(name);
        switch (name) {
            case "CAdESCOM.About":
            case "CAdESCOM.Version":
                return window.Promise.resolve(createAbout());
            case "CAdESCOM.Store":
            case "CAPICOM.Store":
                return window.Promise.resolve(createStore());
            case "CAdESCOM.CPSigner":
                return window.Promise.resolve(createSignerTracked());
            case "CAdESCOM.CadesSignedData":
                return window.Promise.resolve(createSignedDataTracked());
            case "CAdESCOM.HashedData":
            case "CAdESCOM.CPHashedData":
                return window.Promise.resolve(createHashedData());
            case "CAdESCOM.CPAttribute":
            case "CADESCOM.CPAttribute":
                return window.Promise.resolve(createAttribute());
            case "CAdESCOM.RawSignature":
                return window.Promise.resolve(createRawSignature());
            case "CAdESCOM.SignedXML":
                return window.Promise.resolve(createSignedXML());
            default:
                return window.Promise.reject(new Error("Unknown object name: " + name));
        }
    }

    function CreateObject(name) {
        throw new Error("Synchronous CreateObject is not supported; use CreateObjectAsync");
    }

    cadesplugin.CreateObjectAsync = CreateObjectAsync;
    cadesplugin.CreateObject = CreateObject;

    apiFetch("/nmcades/about").then(function () {
        if (canPromise) plugin_resolve();
        else window.postMessage("cadesplugin_loaded", "*");
        if (window.cadesplugin_plugin_loaded_callback) {
            try { window.cadesplugin_plugin_loaded_callback(); } catch (e) {}
        }
    }).catch(function (err) {
        cpcsp_console_log(cadesplugin.LOG_LEVEL_ERROR, "cadesplugin: " + getLastError(err));
        if (canPromise) plugin_reject("Плагин недоступен");
        else window.postMessage("cadesplugin_load_error", "*");
    });

    window.cadesplugin = cadesplugin;
})();
