import Foundation

/// Signature scheme detection, certificate extraction and signing checks.
enum SignatureAnalyzer {

    // MARK: - Collection

    static func collect(apk: URL, entries: [String], tools: ToolEnvironment) async -> SignatureInfo {
        var info = SignatureInfo()
        let env = tools.processEnvironment

        // Native detection — works without any external tools.
        let hasV1 = entries.contains { e in
            let u = e.uppercased()
            return u.hasPrefix("META-INF/") && (u.hasSuffix(".RSA") || u.hasSuffix(".DSA") || u.hasSuffix(".EC"))
        }
        info.schemes["v1"] = hasV1
        for (k, v) in APKSigningBlock.schemes(in: apk) { info.schemes[k] = v }

        var pems: [String] = []
        if let apksigner = tools.path(.apksigner) {
            info.source = "apksigner"
            if let r = try? await ProcessRunner.run(apksigner, arguments: ["verify", "--verbose", "--print-certs", apk.path],
                                                    environment: env, timeout: 180) {
                let text = r.stdout + "\n" + r.stderr
                info.rawOutput = String(text.prefix(8000))
                info.verified = r.succeeded && !text.contains("DOES NOT VERIFY")
                for line in text.split(separator: "\n") {
                    if let m = String(line).firstGroup("^Verified using (v[0-9.]+) scheme[^:]*: (true|false)") {
                        info.schemes[m] = line.hasSuffix("true")
                    }
                }
                info.certificates = parseApksignerCerts(text)
            }
            if let r = try? await ProcessRunner.run(apksigner, arguments: ["verify", "--print-certs-pem", apk.path],
                                                    environment: env, timeout: 180), r.succeeded {
                pems = extractPEMs(r.stdout)
            }
        }
        if pems.isEmpty, hasV1, let keytool = tools.path(.keytool),
           let r = try? await ProcessRunner.run(keytool, arguments: ["-printcert", "-rfc", "-jarfile", apk.path],
                                                environment: env, timeout: 120) {
            pems = extractPEMs(r.stdout)
            if info.source == "none" { info.source = "keytool" }
        }

        // Enrich with openssl (validity window, signature algorithm, key size).
        if let openssl = tools.path(.openssl), !pems.isEmpty {
            var detailed: [SignerCertificate] = []
            for pem in pems.prefix(4) {
                if let cert = await parseWithOpenSSL(pem, openssl: openssl) { detailed.append(cert) }
            }
            if !detailed.isEmpty {
                // Keep SHA-256 digests from apksigner if available.
                for i in detailed.indices where i < info.certificates.count {
                    detailed[i].sha256 = detailed[i].sha256 ?? info.certificates[i].sha256
                }
                info.certificates = detailed
            }
        }
        return info
    }

    static func parseApksignerCerts(_ text: String) -> [SignerCertificate] {
        var certs: [Int: SignerCertificate] = [:]
        for raw in text.split(separator: "\n") {
            let line = String(raw)
            guard let idx = line.firstGroup("^Signer #(\\d+)").flatMap(Int.init) else { continue }
            var c = certs[idx] ?? SignerCertificate(subject: "")
            if let v = line.firstGroup("certificate DN: (.+)$") { c.subject = v }
            if let v = line.firstGroup("certificate SHA-256 digest: ([0-9a-f]+)") { c.sha256 = v }
            if let v = line.firstGroup("key algorithm: (\\w+)") { c.keyAlgorithm = v }
            if let v = line.firstGroup("key size \\(bits\\): (\\d+)").flatMap(Int.init) { c.keySize = v }
            certs[idx] = c
        }
        return certs.keys.sorted().compactMap { certs[$0] }
    }

    static func extractPEMs(_ text: String) -> [String] {
        text.allGroups("(-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----)")
    }

    static func parseWithOpenSSL(_ pem: String, openssl: URL) async -> SignerCertificate? {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("audithor-\(UUID().uuidString).pem")
        guard (try? pem.write(to: tmp, atomically: true, encoding: .utf8)) != nil else { return nil }
        defer { try? FileManager.default.removeItem(at: tmp) }
        guard let r = try? await ProcessRunner.run(openssl, arguments: [
            "x509", "-in", tmp.path, "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256",
            "-text", "-nameopt", "RFC2253"], timeout: 30), r.succeeded else { return nil }
        let t = r.stdout
        var c = SignerCertificate(subject: t.firstGroup("(?m)^subject=\\s*(.+)$") ?? "?")
        c.issuer = t.firstGroup("(?m)^issuer=\\s*(.+)$")
        c.sha256 = t.firstGroup("(?m)Fingerprint=([0-9A-F:]+)")?.replacingOccurrences(of: ":", with: "").lowercased()
        c.signatureAlgorithm = t.firstGroup("Signature Algorithm: ([\\w-]+)")
        c.keyAlgorithm = t.firstGroup("Public Key Algorithm: ([\\w-]+)")
        c.keySize = t.firstGroup("Public-Key: \\((\\d+) bit\\)").flatMap(Int.init)
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = TimeZone(identifier: "GMT")
        df.dateFormat = "MMM d HH:mm:ss yyyy zzz"
        func date(_ key: String) -> Date? {
            guard let s = t.firstGroup("(?m)^\(key)=(.+)$") else { return nil }
            return df.date(from: s.replacingOccurrences(of: "  ", with: " "))
        }
        c.notBefore = date("notBefore")
        c.notAfter = date("notAfter")
        return c
    }

    // MARK: - Checks

    static func findings(_ sig: SignatureInfo, minSdk: Int?) -> [Finding] {
        var out: [Finding] = []
        let file = "input.apk (signature)"
        let schemesText = sig.schemes.keys.sorted().map { "\($0)=\(sig.schemes[$0]! ? "yes" : "no")" }.joined(separator: ", ")
        let any = sig.schemes.values.contains(true)

        if !any {
            out.append(Finding(
                ruleID: "SIGNATURE_UNSIGNED", title: "APK does not appear to be signed",
                description: "No v1 JAR signature or APK Signing Block was found. Unsigned APKs cannot be installed and indicate a broken or tampered build.",
                severity: .high, category: .resilience, control: "MASVS-RESILIENCE-2",
                mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-347",
                remediation: "Sign release builds with apksigner using v2+ schemes.",
                evidence: [Evidence(file: file, line: nil, snippet: schemesText)]))
            return out
        }

        if sig.verified == false {
            out.append(Finding(
                ruleID: "SIGNATURE_VERIFY_FAILED", title: "Signature verification failed",
                description: "apksigner reported that the APK signature does not verify. The file may be corrupted or modified after signing.",
                severity: .high, category: .resilience, control: "MASVS-RESILIENCE-2",
                mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-347",
                remediation: "Obtain the APK from a trusted source and re-run the analysis.",
                evidence: [Evidence(file: file, line: nil, snippet: String((sig.rawOutput ?? "").prefix(300)))]))
        }

        let hasModern = sig.schemes["v2"] == true || sig.schemes["v3"] == true || sig.schemes["v3.1"] == true
        if sig.schemes["v1"] == true && !hasModern {
            let low = (minSdk ?? 0) < 24
            out.append(Finding(
                ruleID: "SIGNATURE_V1_ONLY", title: "Signed with v1 (JAR) scheme only",
                description: "The APK uses only the legacy JAR signature scheme, which does not protect the whole file." + (low ? " On Android 5.0–8.0 devices this exposes the app to the Janus vulnerability (CVE-2017-13156), allowing code injection without invalidating the signature." : ""),
                severity: low ? .high : .medium, category: .resilience, control: "MASVS-RESILIENCE-2",
                mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-347",
                remediation: "Sign with APK Signature Scheme v2 and v3 (default in current Android Gradle Plugin / apksigner).",
                evidence: [Evidence(file: file, line: nil, snippet: schemesText)]))
        }

        for cert in sig.certificates {
            let ev = [Evidence(file: file, line: nil, snippet: cert.subject)]
            if cert.subject.contains("CN=Android Debug") {
                out.append(Finding(
                    ruleID: "SIGNATURE_DEBUG_CERT", title: "Signed with the Android debug certificate",
                    description: "The APK is signed with the auto-generated Android debug key. Its private key is available on every developer machine, so anyone can produce updates that the OS accepts as genuine.",
                    severity: .critical, category: .resilience, control: "MASVS-RESILIENCE-2",
                    mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-321",
                    remediation: "Sign release builds with a dedicated release key (ideally via Play App Signing) and never distribute debug-signed builds.",
                    evidence: ev))
            }
            if let alg = cert.signatureAlgorithm?.lowercased(), alg.contains("sha1") || alg.contains("md5") {
                out.append(Finding(
                    ruleID: "SIGNATURE_WEAK_ALGORITHM", title: "Signing certificate uses a weak signature algorithm",
                    description: "The signing certificate is signed with \(cert.signatureAlgorithm ?? "?"). SHA-1 and MD5 are vulnerable to collision attacks.",
                    severity: .medium, category: .crypto, control: "MASVS-CRYPTO-1",
                    mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-327",
                    remediation: "Rotate to a SHA-256-based signing certificate using APK Signature Scheme v3 key rotation.",
                    evidence: ev))
            }
            if let size = cert.keySize, (cert.keyAlgorithm ?? "").lowercased().contains("rsa"), size < 2048 {
                out.append(Finding(
                    ruleID: "SIGNATURE_WEAK_KEY", title: "Signing key is too short (\(size)-bit RSA)",
                    description: "RSA keys shorter than 2048 bits are considered breakable.",
                    severity: .medium, category: .crypto, control: "MASVS-CRYPTO-1",
                    mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-326",
                    remediation: "Rotate to an RSA-3072+ or EC P-256 signing key (APK Signature Scheme v3 key rotation).",
                    evidence: ev))
            }
            if let nb = cert.notBefore, let na = cert.notAfter {
                let df = DateFormatter(); df.dateStyle = .medium
                let window = "\(df.string(from: nb)) → \(df.string(from: na))"
                let playMinimum = ISO8601DateFormatter.dateOnly.date(from: "2033-10-22")!
                if na < Date() {
                    out.append(Finding(
                        ruleID: "SIGNATURE_CERT_EXPIRED", title: "Signing certificate has expired",
                        description: "The certificate validity window is \(window). Android does not enforce expiry for installed apps, but an expired certificate suggests a poorly managed signing key.",
                        severity: .low, category: .resilience, control: "MASVS-RESILIENCE-2",
                        mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-298",
                        remediation: "Plan a key rotation via APK Signature Scheme v3.", evidence: ev))
                } else if nb > Date() {
                    out.append(Finding(
                        ruleID: "SIGNATURE_CERT_NOT_YET_VALID", title: "Signing certificate is not yet valid",
                        description: "The certificate validity starts in the future (\(window)).",
                        severity: .low, category: .resilience, control: "MASVS-RESILIENCE-2",
                        mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: "CWE-298",
                        remediation: "Check the signing infrastructure's clock and re-issue the certificate.", evidence: ev))
                } else if na < playMinimum {
                    out.append(Finding(
                        ruleID: "SIGNATURE_CERT_SHORT_VALIDITY", title: "Signing certificate expires before 2033",
                        description: "Validity window: \(window). Google Play requires signing certificates for new apps to be valid until at least 22 October 2033.",
                        severity: .low, category: .resilience, control: "MASVS-RESILIENCE-2",
                        mastg: "MASTG-TEST-0038 (Making Sure that the App is Properly Signed)", cwe: nil,
                        remediation: "Use a signing key with a validity of 25+ years.", evidence: ev))
                }
            }
        }
        return out
    }
}

/// Minimal parser for the APK Signing Block (v2/v3/v3.1 schemes).
/// Reads only the tail of the file; never writes.
enum APKSigningBlock {
    static let ids: [UInt32: String] = [0x7109871a: "v2", 0xf05368c0: "v3", 0x1b93ad61: "v3.1"]

    static func schemes(in url: URL) -> [String: Bool] {
        var result: [String: Bool] = ["v2": false, "v3": false]
        guard let h = try? FileHandle(forReadingFrom: url) else { return result }
        defer { try? h.close() }
        guard let size = try? h.seekToEnd(), size > 22 else { return result }

        // Find End Of Central Directory (EOCD) in the last 64 KiB + 22 bytes.
        let tailLen = min(size, 65_557)
        try? h.seek(toOffset: size - tailLen)
        guard let tail = try? h.read(upToCount: Int(tailLen)), tail.count >= 22 else { return result }
        let bytes = [UInt8](tail)
        var eocd: Int?
        var i = bytes.count - 22
        while i >= 0 {
            if bytes[i] == 0x50, bytes[i + 1] == 0x4b, bytes[i + 2] == 0x05, bytes[i + 3] == 0x06 { eocd = i; break }
            i -= 1
        }
        guard let e = eocd else { return result }
        let cdOffset = UInt64(le32(bytes, e + 16))
        guard cdOffset >= 24 else { return result }

        // 8-byte size + 16-byte magic immediately before the central directory.
        try? h.seek(toOffset: cdOffset - 24)
        guard let footer = try? h.read(upToCount: 24), footer.count == 24 else { return result }
        guard String(data: footer.suffix(16), encoding: .ascii) == "APK Sig Block 42" else { return result }
        let blockSize = le64([UInt8](footer), 0)
        guard blockSize < size, cdOffset >= blockSize + 8 else { return result }

        let start = cdOffset - blockSize - 8 + 8 // skip leading size field
        try? h.seek(toOffset: start)
        let pairsLen = Int(blockSize) - 24
        guard pairsLen > 0, pairsLen < 64 * 1024 * 1024,
              let pairs = try? h.read(upToCount: pairsLen) else { return result }
        let p = [UInt8](pairs)
        var off = 0
        while off + 12 <= p.count {
            let len = Int(le64(p, off))
            guard len >= 4, off + 8 + len <= p.count else { break }
            let id = le32(p, off + 8)
            if let name = ids[id] { result[name] = true }
            off += 8 + len
        }
        return result
    }

    private static func le32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
    }

    private static func le64(_ b: [UInt8], _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for k in 0..<8 { v |= UInt64(b[o + k]) << (8 * UInt64(k)) }
        return v
    }
}
