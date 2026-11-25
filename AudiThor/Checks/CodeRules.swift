import Foundation

/// Catalog of source-level rules. Each maps to a MASVS v2 control, a MASTG test and a CWE.
///
/// Patterns are written primarily against jadx Java output. Rules that also list
/// `.smali` use string-literal patterns that look the same in both representations.
enum CodeRules {
    private static let code: Set<SourceKind> = [.java]
    private static let codeAndSmali: Set<SourceKind> = [.java, .smali]
    private static let everything: Set<SourceKind> = [.java, .smali, .xml, .asset]
    private static func rx(_ p: String, _ o: NSRegularExpression.Options = []) -> NSRegularExpression {
        NSRegularExpression.rx(p, o)
    }

    /// Tokens whose presence anywhere is recorded (used for pinning detection,
    /// permission-vs-usage, and positive "good practice" signals).
    static let probes: [String] = [
        "CertificatePinner", "TrustKit", "pin-set", "sha256/", "PinningTrustManager",
        "EncryptedSharedPreferences", "EncryptedFile", "MasterKey", "AndroidKeyStore",
        "SafetyNet", "PlayIntegrity", "IntegrityManager",
    ] + PermissionUsage.allTokens

    static func all() -> [CodeRule] {
        crypto + storage + network + logging + webview + secrets
    }

    // MARK: Cryptography (MASVS-CRYPTO)

    static let crypto: [CodeRule] = [
        CodeRule(
            id: "CRYPTO_WEAK_CIPHER", title: "Weak or broken cipher algorithm",
            description: "The app requests a cipher that is considered broken or too weak (DES, 3DES, RC2, RC4, Blowfish). Data protected with these algorithms can be recovered by an attacker.",
            severity: .high, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0014 (Testing the Configuration of Cryptographic Standard Algorithms)", cwe: "CWE-327",
            remediation: "Use AES-256 in GCM mode (`AES/GCM/NoPadding`) or ChaCha20-Poly1305 with keys held in the Android Keystore.",
            kinds: codeAndSmali, prefilter: ["DES", "RC4", "RC2", "ARCFOUR", "Blowfish"],
            matcher: .line(rx("\"(DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)(/[A-Za-z0-9]+/[A-Za-z0-9]+)?\""))),
        CodeRule(
            id: "CRYPTO_ECB_MODE", title: "Block cipher used in ECB mode",
            description: "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns. `Cipher.getInstance(\"AES\")` without a mode also defaults to ECB on Android.",
            severity: .high, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0013 (Testing Symmetric Cryptography)", cwe: "CWE-327",
            remediation: "Specify an authenticated mode explicitly, e.g. `AES/GCM/NoPadding`, with a unique random IV per encryption.",
            kinds: codeAndSmali, prefilter: ["ECB", "\"AES\""],
            matcher: .line(rx("\"[A-Za-z0-9]+/ECB/[A-Za-z0-9]+\"|Cipher\\.getInstance\\(\\s*\"AES\"\\s*[,)]"))),
        CodeRule(
            id: "CRYPTO_WEAK_HASH", title: "Weak hash algorithm (MD5 / SHA-1)",
            description: "MD5 and SHA-1 are vulnerable to collision attacks and must not be used for integrity, signatures or password hashing.",
            severity: .medium, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0014 (Testing the Configuration of Cryptographic Standard Algorithms)", cwe: "CWE-328",
            remediation: "Use SHA-256 or stronger for integrity. For passwords use a dedicated KDF (Argon2, scrypt, PBKDF2 with a high iteration count).",
            kinds: code, prefilter: ["MessageDigest", "DigestUtils"],
            matcher: .line(rx("MessageDigest\\.getInstance\\(\\s*\"(MD5|MD4|MD2|SHA-?1)\"|DigestUtils\\.(md5|sha1)", [.caseInsensitive]))),
        CodeRule(
            id: "CRYPTO_WEAK_SIGNATURE", title: "Weak signature algorithm",
            description: "Signatures based on MD5 or SHA-1 can be forged via collision attacks.",
            severity: .high, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0014 (Testing the Configuration of Cryptographic Standard Algorithms)", cwe: "CWE-327",
            remediation: "Use `SHA256withECDSA`, `SHA256withRSA/PSS` or Ed25519.",
            kinds: codeAndSmali, prefilter: ["with"],
            matcher: .line(rx("\"(MD5|SHA1|SHA-1)with(RSA|DSA|ECDSA)\"", [.caseInsensitive]))),
        CodeRule(
            id: "CRYPTO_STATIC_IV", title: "Hardcoded or static initialization vector",
            description: "An IV is built from a constant array or string. Reusing an IV with the same key breaks the confidentiality of CBC/CTR/GCM encryption.",
            severity: .medium, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0013 (Testing Symmetric Cryptography)", cwe: "CWE-329",
            remediation: "Generate a fresh random IV with `SecureRandom` for every encryption and store it alongside the ciphertext.",
            kinds: code, prefilter: ["IvParameterSpec", "GCMParameterSpec"],
            matcher: .line(rx("new (IvParameterSpec|GCMParameterSpec)\\((\\d+,\\s*)?(new byte\\[\\]\\s*\\{|\"[^\"]*\"\\.getBytes|new byte\\[\\d+\\]\\))"))),
        CodeRule(
            id: "CRYPTO_HARDCODED_KEY", title: "Hardcoded symmetric key",
            description: "A `SecretKeySpec` is created from a literal string or byte array. Anyone with the APK can extract the key and decrypt the data.",
            severity: .high, category: .crypto, control: "MASVS-CRYPTO-2",
            mastg: "MASTG-TEST-0013 (Testing Symmetric Cryptography)", cwe: "CWE-321",
            remediation: "Generate keys at runtime inside the Android Keystore (`KeyGenParameterSpec`) and never ship key material in the APK.",
            kinds: code, prefilter: ["SecretKeySpec"],
            matcher: .line(rx("new SecretKeySpec\\(\\s*(\"[^\"]*\"\\.getBytes|new byte\\[\\]\\s*\\{)")),
            masksSecrets: true),
        CodeRule(
            id: "CRYPTO_STATIC_SALT", title: "Static salt used for key derivation",
            description: "A password-based key derivation uses a constant salt, which enables pre-computation attacks across all installations.",
            severity: .medium, category: .crypto, control: "MASVS-CRYPTO-2",
            mastg: "MASTG-TEST-0013 (Testing Symmetric Cryptography)", cwe: "CWE-760",
            remediation: "Use a per-user random salt of at least 16 bytes generated by `SecureRandom`.",
            kinds: code, prefilter: ["PBEKeySpec", "PBEParameterSpec"],
            matcher: .line(rx("new (PBEKeySpec|PBEParameterSpec)\\([^;]*(\"[^\"]*\"\\.getBytes|new byte\\[\\]\\s*\\{)"))),
        CodeRule(
            id: "CRYPTO_INSECURE_RANDOM", title: "Insecure random number generator in security context",
            description: "`java.util.Random` / `Math.random()` is used in a class that also performs cryptographic operations. These generators are predictable and unsuitable for keys, IVs, nonces or tokens.",
            severity: .medium, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0016 (Testing Random Number Generation)", cwe: "CWE-330",
            remediation: "Use `java.security.SecureRandom` for any security-relevant randomness.",
            kinds: code, prefilter: ["new Random(", "Math.random()"],
            matcher: .file({ content, lines in
                let cryptoContext = content.contains("javax.crypto")
                    || content.range(of: "\\b(token|nonce|salt|otp|password|secret)\\b",
                                     options: [.regularExpression, .caseInsensitive]) != nil
                guard cryptoContext else { return [] }
                return lines.enumerated().compactMap { i, l in
                    (l.contains("new Random(") || l.contains("Math.random()")) ? RuleHit(line: i + 1, snippet: String(l)) : nil
                }
            })),
        CodeRule(
            id: "CRYPTO_SEEDED_SECURERANDOM", title: "SecureRandom seeded with a fixed value",
            description: "Calling `setSeed` with constant data, or constructing `SecureRandom` with a seed, can make output predictable on some providers.",
            severity: .medium, category: .crypto, control: "MASVS-CRYPTO-1",
            mastg: "MASTG-TEST-0016 (Testing Random Number Generation)", cwe: "CWE-337",
            remediation: "Use the default `new SecureRandom()` constructor and never seed it with application data.",
            kinds: code, prefilter: ["SecureRandom"],
            matcher: .line(rx("new SecureRandom\\(\\s*[^)\\s]|\\.setSeed\\(\\s*(\"|\\d|new byte|System\\.currentTimeMillis)"))),
    ]

    // MARK: Data storage (MASVS-STORAGE)

    static let storage: [CodeRule] = [
        CodeRule(
            id: "STORAGE_WORLD_ACCESSIBLE", title: "World-readable or world-writable file mode",
            description: "Files are created with MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE or made globally accessible, allowing any app on the device to read or modify them.",
            severity: .high, category: .storage, control: "MASVS-STORAGE-1",
            mastg: "MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)", cwe: "CWE-732",
            remediation: "Use `MODE_PRIVATE` and share data with other apps through a `FileProvider` with scoped URI permissions.",
            kinds: codeAndSmali, prefilter: ["MODE_WORLD", "setReadable", "setWritable", "openFileOutput", "getSharedPreferences"],
            matcher: .line(rx("MODE_WORLD_(READABLE|WRITEABLE)|set(Readable|Writable)\\(\\s*true\\s*,\\s*false\\s*\\)|(openFileOutput|getSharedPreferences|openOrCreateDatabase)\\([^,]+,\\s*[123]\\s*[,)]"))),
        CodeRule(
            id: "STORAGE_PREFS_SECRETS", title: "Sensitive values written to SharedPreferences",
            description: "Values with credential-like keys (password, token, secret, PIN…) are stored in plain SharedPreferences, which are kept unencrypted in the app sandbox and included in backups.",
            severity: .medium, category: .storage, control: "MASVS-STORAGE-1",
            mastg: "MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)", cwe: "CWE-312",
            remediation: "Avoid persisting secrets. If required, store them encrypted with a Keystore-backed key (e.g. Jetpack Security `EncryptedSharedPreferences` or Tink).",
            kinds: code, prefilter: ["putString", "putInt", "putLong"],
            matcher: .line(rx("\\.put(String|Int|Long)\\(\\s*\"[^\"]*(pass(word|wd)?|pwd|token|secret|api_?key|apikey|pin|otp|credential|session|auth|private_?key|card)[^\"]*\"", [.caseInsensitive]),
                           exclude: rx("Encrypted|is_?[a-z_]*(enabled|shown|set)", [.caseInsensitive]))),
        CodeRule(
            id: "STORAGE_EXTERNAL", title: "Use of external / shared storage",
            description: "The app reads or writes files on external storage. External storage is accessible to other apps (pre-scoped-storage) and to anyone with physical access; it must not hold sensitive data.",
            severity: .medium, category: .storage, control: "MASVS-STORAGE-2",
            mastg: "MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)", cwe: "CWE-922",
            remediation: "Keep sensitive files in internal storage (`getFilesDir()` / `getNoBackupFilesDir()`), or encrypt them with Jetpack Security `EncryptedFile` before writing externally.",
            kinds: codeAndSmali, prefilter: ["getExternal", "/sdcard", "EXTERNAL_STORAGE"],
            matcher: .line(rx("getExternalStorageDirectory|getExternalStoragePublicDirectory|getExternalFilesDir|getExternalCacheDir|\"/sdcard|\"/storage/emulated"))),
        CodeRule(
            id: "STORAGE_SQL_RAW", title: "Raw SQL built with string concatenation",
            description: "SQL statements are composed with string concatenation, which can lead to SQL injection when values derive from untrusted input (e.g. via an exported ContentProvider).",
            severity: .low, category: .code, control: "MASVS-CODE-4",
            mastg: "MASTG-TEST-0025 (Testing for Injection Flaws)", cwe: "CWE-89",
            remediation: "Use parameterised queries (`?` placeholders with selectionArgs) or Room.",
            kinds: code, prefilter: ["rawQuery", "execSQL"],
            matcher: .line(rx("\\.(rawQuery|execSQL)\\(\\s*(\"[^\"]*\"\\s*\\+|[A-Za-z_][\\w.]*\\s*\\+|String\\.format)"))),
    ]

    // MARK: Network (MASVS-NETWORK)

    static let network: [CodeRule] = [
        CodeRule(
            id: "NETWORK_TRUST_ALL_CERTS", title: "TrustManager accepts all certificates",
            description: "A custom `X509TrustManager` implements `checkServerTrusted` with an empty body, disabling TLS certificate validation. Any network attacker can intercept and modify traffic.",
            severity: .critical, category: .network, control: "MASVS-NETWORK-1",
            mastg: "MASTG-TEST-0021 (Testing Endpoint Identify Verification)", cwe: "CWE-295",
            remediation: "Remove the custom TrustManager and rely on the platform default. For custom CAs or pinning use Network Security Configuration.",
            kinds: code, prefilter: ["checkServerTrusted"],
            matcher: .file({ content, _ in
                multilineHits(content, rx("void\\s+checkServerTrusted\\s*\\([^)]*\\)\\s*(throws\\s+[\\w.,\\s]+)?\\{\\s*(//[^\\n]*\\s*)*\\}"))
            }),
            includeThirdParty: true),
        CodeRule(
            id: "NETWORK_HOSTNAME_VERIFIER", title: "Hostname verification disabled",
            description: "A `HostnameVerifier` always returns true or `ALLOW_ALL_HOSTNAME_VERIFIER` / `NoopHostnameVerifier` is used, so any valid certificate for any host is accepted.",
            severity: .high, category: .network, control: "MASVS-NETWORK-1",
            mastg: "MASTG-TEST-0021 (Testing Endpoint Identify Verification)", cwe: "CWE-297",
            remediation: "Use the default hostname verifier. Never override `verify()` to return true.",
            kinds: code, prefilter: ["HostnameVerifier", "SSLSession"],
            matcher: .file({ content, _ in
                multilineHits(content, rx("boolean\\s+verify\\s*\\(\\s*String\\s+\\w+\\s*,\\s*SSLSession\\s+\\w+\\s*\\)\\s*\\{\\s*return\\s+true;\\s*\\}|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|AllowAllHostnameVerifier"))
            }),
            includeThirdParty: true),
        CodeRule(
            id: "NETWORK_WEBVIEW_SSL_PROCEED", title: "WebView ignores TLS errors",
            description: "`onReceivedSslError` calls `handler.proceed()`, so the WebView loads pages despite invalid certificates.",
            severity: .high, category: .network, control: "MASVS-NETWORK-1",
            mastg: "MASTG-TEST-0021 (Testing Endpoint Identify Verification)", cwe: "CWE-295",
            remediation: "Call `handler.cancel()` (the default) and fix the server certificate instead.",
            kinds: code, prefilter: ["onReceivedSslError"],
            matcher: .file({ content, _ in
                multilineHits(content, rx("onReceivedSslError\\s*\\([^)]*\\)\\s*\\{[^}]*?\\.proceed\\(\\)"))
            }),
            includeThirdParty: true),
        CodeRule(
            id: "NETWORK_CLEARTEXT_URL", title: "Hardcoded cleartext (http://) endpoints",
            description: "The app contains plain-HTTP URLs. Traffic to these endpoints can be read and modified by network attackers.",
            severity: .low, category: .network, control: "MASVS-NETWORK-1",
            mastg: "MASTG-TEST-0019 (Testing Data Encryption on the Network)", cwe: "CWE-319",
            remediation: "Use HTTPS for every endpoint and disable cleartext traffic in the Network Security Configuration.",
            kinds: everything, prefilter: ["http://"],
            matcher: .line(rx("[\"'>]http://[^\"'<\\s]{4,}"),
                           exclude: rx("http://(schemas\\.android\\.com|www\\.w3\\.org|ns\\.adobe\\.com|xml\\.org|xmlpull\\.org|apache\\.org|www\\.apache\\.org|localhost|127\\.0\\.0\\.1|10\\.0\\.2\\.2|json-schema\\.org|purl\\.org|schemas\\.xmlsoap\\.org|www\\.example\\.com|example\\.com|java\\.sun\\.com|xmlns\\.)"))),
    ]

    // MARK: Logging (MASVS-STORAGE-2)

    static let logging: [CodeRule] = [
        CodeRule(
            id: "STORAGE_LOG_SENSITIVE", title: "Sensitive data written to logs",
            description: "Log statements include values whose names suggest credentials or personal data. Logcat output is readable by privileged apps, bug-report tooling, and attackers with ADB access.",
            severity: .medium, category: .storage, control: "MASVS-STORAGE-2",
            mastg: "MASTG-TEST-0003 (Testing Logs for Sensitive Data)", cwe: "CWE-532",
            remediation: "Remove sensitive values from log calls and strip debug logging from release builds (e.g. R8 `-assumenosideeffects` for `android.util.Log`).",
            kinds: code, prefilter: ["Log.", "println", "Timber"],
            matcher: .line(rx("(Log\\.[vdiwe]|System\\.(out|err)\\.print(ln)?|Timber\\.[vdiwe])\\(.*(pass(word|wd)?|pwd|token|secret|api_?key|pin\\b|otp|credential|session|cookie|authorization|bearer|card|cvv|ssn|private_?key)", [.caseInsensitive]))),
        CodeRule(
            id: "CODE_DEBUG_LOGGING", title: "Verbose/debug logging present",
            description: "Debug-level logging calls remain in first-party code. They can leak internal state and should be stripped from release builds.",
            severity: .info, category: .storage, control: "MASVS-STORAGE-2",
            mastg: "MASTG-TEST-0003 (Testing Logs for Sensitive Data)", cwe: "CWE-532",
            remediation: "Remove verbose/debug logging in release builds via R8 rules or a logging wrapper gated on `BuildConfig.DEBUG`.",
            kinds: code, prefilter: ["Log.d(", "Log.v("],
            matcher: .line(rx("\\bLog\\.[dv]\\("))),
    ]

    // MARK: WebView (MASVS-PLATFORM-2)

    static let webview: [CodeRule] = [
        CodeRule(
            id: "PLATFORM_WEBVIEW_JS_BRIDGE", title: "JavaScript bridge exposed in WebView",
            description: "A WebView enables JavaScript and registers a Java object via `addJavascriptInterface`. If the WebView ever loads untrusted or attacker-influenced content, that content can invoke the exposed methods.",
            severity: .high, category: .platform, control: "MASVS-PLATFORM-2",
            mastg: "MASTG-TEST-0033 (Testing for Java Objects Exposed Through WebViews)", cwe: "CWE-749",
            remediation: "Load only trusted, HTTPS content in WebViews with a bridge; restrict exposed methods (`@JavascriptInterface`) to the minimum; consider `WebViewCompat.addWebMessageListener` with an origin allow-list.",
            kinds: code, prefilter: ["addJavascriptInterface"],
            matcher: .file({ content, lines in
                guard content.contains("setJavaScriptEnabled(true)") else { return [] }
                return lines.enumerated().compactMap { i, l in
                    (l.contains("addJavascriptInterface(") || l.contains("setJavaScriptEnabled(true)")) ? RuleHit(line: i + 1, snippet: String(l)) : nil
                }
            })),
        CodeRule(
            id: "PLATFORM_WEBVIEW_JS_ENABLED", title: "JavaScript enabled in WebView",
            description: "JavaScript is enabled in a WebView. This is not a vulnerability on its own but increases the impact of XSS or loading untrusted content.",
            severity: .low, category: .platform, control: "MASVS-PLATFORM-2",
            mastg: "MASTG-TEST-0031 (Testing JavaScript Execution in WebViews)", cwe: "CWE-79",
            remediation: "Only enable JavaScript when required and only load trusted HTTPS content.",
            kinds: code, prefilter: ["setJavaScriptEnabled(true)"],
            matcher: .file({ content, lines in
                guard !content.contains("addJavascriptInterface(") else { return [] } // covered by the bridge rule
                return lines.enumerated().compactMap { i, l in
                    l.contains("setJavaScriptEnabled(true)") ? RuleHit(line: i + 1, snippet: String(l)) : nil
                }
            })),
        CodeRule(
            id: "PLATFORM_WEBVIEW_FILE_ACCESS", title: "WebView file access enabled",
            description: "The WebView allows file:// access (`setAllowFileAccess`, `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs`). Malicious content could read local files or app data.",
            severity: .medium, category: .platform, control: "MASVS-PLATFORM-2",
            mastg: "MASTG-TEST-0032 (Testing WebView Protocol Handlers)", cwe: "CWE-200",
            remediation: "Set these to false and serve local content with `WebViewAssetLoader` over https://appassets.androidplatform.net.",
            kinds: code, prefilter: ["setAllow"],
            matcher: .line(rx("setAllow(File|Content)Access(FromFileURLs)?\\(\\s*true\\s*\\)|setAllowUniversalAccessFromFileURLs\\(\\s*true\\s*\\)"))),
        CodeRule(
            id: "RESILIENCE_WEBVIEW_DEBUGGING", title: "WebView remote debugging enabled",
            description: "`WebView.setWebContentsDebuggingEnabled(true)` allows anyone with ADB access to inspect and script WebView content via Chrome DevTools.",
            severity: .medium, category: .resilience, control: "MASVS-RESILIENCE-4",
            mastg: "MASTG-TEST-0039 (Testing whether the App is Debuggable)", cwe: "CWE-489",
            remediation: "Only enable WebView debugging in debug builds (`if (BuildConfig.DEBUG)`).",
            kinds: code, prefilter: ["setWebContentsDebuggingEnabled"],
            matcher: .line(rx("setWebContentsDebuggingEnabled\\(\\s*true\\s*\\)"))),
    ]

    // MARK: Secrets (MASVS-STORAGE / MASVS-CRYPTO-2)

    /// High-confidence token formats.
    static let secretPatterns: [(String, String)] = [
        ("AWS access key ID", "\\b(AKIA|ASIA)[0-9A-Z]{16}\\b"),
        ("Google API key", "\\bAIza[0-9A-Za-z_\\-]{35}\\b"),
        ("Google OAuth client secret", "\\bGOCSPX-[0-9A-Za-z_\\-]{28}\\b"),
        ("Private key block", "-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        ("Slack token", "\\bxox[baprs]-[0-9A-Za-z\\-]{10,}"),
        ("GitHub token", "\\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\\b"),
        ("Stripe secret key", "\\b(sk|rk)_live_[0-9A-Za-z]{20,}"),
        ("Twilio API key", "\\bSK[0-9a-f]{32}\\b"),
        ("SendGrid API key", "\\bSG\\.[0-9A-Za-z_\\-]{22}\\.[0-9A-Za-z_\\-]{43}\\b"),
        ("JSON Web Token", "\\beyJ[0-9A-Za-z_\\-]{10,}\\.eyJ[0-9A-Za-z_\\-]{10,}\\.[0-9A-Za-z_\\-]{10,}"),
        ("Basic-auth credentials in URL", "[a-z]+://[^/\\s:@\"]{3,}:[^/\\s:@\"]{3,}@[^\\s\"]+"),
    ]

    private static let secretRegex: NSRegularExpression =
        rx(secretPatterns.map { "(?:\($0.1))" }.joined(separator: "|"))

    /// Assignments of credential-like names to string literals (Java fields / XML string resources).
    private static let genericSecretRegex = rx(
        "(?:(?:api|access|auth|client|secret|private|app)_?(?:key|secret|token)|password|passwd|secret|bearer)[A-Za-z0-9_]*\"?\\s*(?:=|:|>)\\s*\"?([A-Za-z0-9+/=_\\-\\.]{12,})",
        [.caseInsensitive])

    private static let literalRegex = rx("\"([A-Za-z0-9+/=_\\-]{20,200})\"")

    static let secrets: [CodeRule] = [
        CodeRule(
            id: "STORAGE_HARDCODED_SECRET", title: "Hardcoded credential or API token",
            description: "A value matching a known credential format (cloud API key, private key, OAuth secret, JWT…) is embedded in the app. Anything shipped in the APK must be considered public.",
            severity: .high, category: .storage, control: "MASVS-STORAGE-1",
            mastg: "MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)", cwe: "CWE-798",
            remediation: "Remove the secret from the client, rotate it, and move privileged operations behind your backend. Restrict client-side keys (e.g. Google API keys) by package name and signing certificate.",
            kinds: everything, prefilter: [],
            matcher: .line(secretRegex),
            masksSecrets: true),
        CodeRule(
            id: "STORAGE_GENERIC_SECRET", title: "Possible hardcoded secret (credential-like name)",
            description: "A string literal assigned to a credential-like identifier (password, api_key, client_secret…) has high entropy and may be a real secret.",
            severity: .medium, category: .storage, control: "MASVS-STORAGE-1",
            mastg: "MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)", cwe: "CWE-798",
            remediation: "Verify whether the value is a real secret. If so, remove it from the app, rotate it, and fetch short-lived credentials from your backend at runtime.",
            kinds: [.java, .xml, .asset], prefilter: [],
            matcher: .file({ _, lines in
                var out: [RuleHit] = []
                for (i, l) in lines.enumerated() {
                    let s = String(l)
                    for value in s.allGroups(genericSecretRegex.pattern, options: [.caseInsensitive])
                    where Entropy.shannon(value) >= 3.5 && !looksBenign(value) {
                        out.append(RuleHit(line: i + 1, snippet: s)); break
                    }
                }
                return out
            }),
            masksSecrets: true),
        CodeRule(
            id: "STORAGE_HIGH_ENTROPY_STRING", title: "High-entropy string literals",
            description: "String literals with high Shannon entropy were found in first-party code. These are often keys, tokens or encoded credentials. Review each to confirm.",
            severity: .low, category: .storage, control: "MASVS-STORAGE-1",
            mastg: "MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)", cwe: "CWE-798",
            remediation: "Review the listed literals; move genuine secrets out of the client.",
            kinds: [.java], prefilter: ["\""],
            matcher: .file({ _, lines in
                var out: [RuleHit] = []
                for (i, l) in lines.enumerated() where l.contains("\"") {
                    let s = String(l)
                    for value in s.allGroups(literalRegex.pattern) where isHighEntropyCandidate(value) {
                        out.append(RuleHit(line: i + 1, snippet: s)); break
                    }
                }
                return out
            }),
            masksSecrets: true),
    ]

    // MARK: Helpers

    static func multilineHits(_ content: String, _ re: NSRegularExpression) -> [RuleHit] {
        let ns = content as NSString
        return re.matches(in: content, range: NSRange(location: 0, length: ns.length)).map { m in
            let prefix = ns.substring(to: m.range.location)
            let line = prefix.reduce(0) { $1 == "\n" ? $0 + 1 : $0 } + 1
            let firstLine = ns.substring(with: m.range).split(separator: "\n").first.map(String.init) ?? ""
            return RuleHit(line: line, snippet: firstLine)
        }
    }

    static func looksBenign(_ v: String) -> Bool {
        let lower = v.lowercased()
        if lower.hasPrefix("http") || lower.contains("example") || lower.contains("placeholder") { return true }
        if v.allSatisfy({ $0.isLetter && $0.isLowercase || $0 == "_" || $0 == "." }) { return true } // identifiers
        if v.allSatisfy({ $0.isLetter && $0.isUppercase || $0 == "_" }) { return true } // CONSTANT_NAMES
        return false
    }

    static func isHighEntropyCandidate(_ v: String) -> Bool {
        guard v.count >= 20, !looksBenign(v) else { return false }
        let hasDigit = v.contains(where: \.isNumber)
        let hasUpper = v.contains(where: \.isUppercase)
        let hasLower = v.contains(where: \.isLowercase)
        guard hasDigit && (hasUpper || hasLower) else { return false }
        // Skip class/package-like strings and common encodings of nothing interesting.
        if v.contains("/") && v.split(separator: "/").count > 3 { return false }
        let threshold = v.count >= 32 ? 4.3 : 4.0
        return Entropy.shannon(v) >= threshold
    }
}

/// Maps dangerous permissions to the APIs that justify them (permission-vs-usage check).
enum PermissionUsage {
    static let map: [String: [String]] = [
        "android.permission.CAMERA": ["android.hardware.Camera", "CameraManager", "androidx.camera", "CameraX", "MediaStore.ACTION_IMAGE_CAPTURE", "Landroid/hardware/Camera", "Landroid/hardware/camera2"],
        "android.permission.RECORD_AUDIO": ["AudioRecord", "MediaRecorder", "SpeechRecognizer", "Landroid/media/AudioRecord"],
        "android.permission.ACCESS_FINE_LOCATION": ["LocationManager", "FusedLocationProviderClient", "LocationServices", "requestLocationUpdates"],
        "android.permission.ACCESS_COARSE_LOCATION": ["LocationManager", "FusedLocationProviderClient", "LocationServices", "requestLocationUpdates"],
        "android.permission.ACCESS_BACKGROUND_LOCATION": ["LocationManager", "FusedLocationProviderClient", "GeofencingClient"],
        "android.permission.READ_CONTACTS": ["ContactsContract"],
        "android.permission.WRITE_CONTACTS": ["ContactsContract"],
        "android.permission.READ_SMS": ["Telephony.Sms", "content://sms", "SmsMessage"],
        "android.permission.RECEIVE_SMS": ["SMS_RECEIVED", "SmsMessage", "Telephony.Sms"],
        "android.permission.SEND_SMS": ["SmsManager"],
        "android.permission.READ_CALL_LOG": ["CallLog"],
        "android.permission.READ_PHONE_STATE": ["TelephonyManager"],
        "android.permission.CALL_PHONE": ["ACTION_CALL", "android.intent.action.CALL"],
        "android.permission.READ_CALENDAR": ["CalendarContract"],
        "android.permission.WRITE_CALENDAR": ["CalendarContract"],
        "android.permission.BODY_SENSORS": ["SensorManager"],
        "android.permission.BLUETOOTH_CONNECT": ["BluetoothAdapter", "BluetoothDevice", "BluetoothManager"],
        "android.permission.BLUETOOTH_SCAN": ["BluetoothLeScanner", "BluetoothAdapter", "startDiscovery"],
        "android.permission.READ_MEDIA_IMAGES": ["MediaStore"],
        "android.permission.READ_MEDIA_VIDEO": ["MediaStore"],
        "android.permission.READ_EXTERNAL_STORAGE": ["getExternal", "MediaStore", "Environment.getExternalStorage"],
        "android.permission.WRITE_EXTERNAL_STORAGE": ["getExternal", "MediaStore", "Environment.getExternalStorage"],
        "android.permission.GET_ACCOUNTS": ["AccountManager"],
        "android.permission.USE_BIOMETRIC": ["BiometricPrompt", "BiometricManager"],
        "android.permission.USE_FINGERPRINT": ["FingerprintManager", "BiometricPrompt"],
        "android.permission.NFC": ["NfcAdapter"],
    ]

    static var allTokens: [String] { Array(Set(map.values.flatMap { $0 })).sorted() }
}
