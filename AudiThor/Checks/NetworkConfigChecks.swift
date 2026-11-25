import Foundation

/// Cleartext traffic, Network Security Configuration and certificate pinning.
enum NetworkConfigChecks {
    static func run(app: XMLNode?, info: AppInfo, apktoolDir: URL, workspace: Workspace,
                    presentTokens: Set<String>) -> [Finding] {
        var out: [Finding] = []
        let target = info.targetSdk ?? 0
        let manifest = ManifestChecks.manifestPath

        let nscRef = app?.attr("networkSecurityConfig")
        let nscURL = ManifestParser.resolveXMLResource(nscRef, apktoolDir: apktoolDir)
        let nsc = nscURL.flatMap { SimpleXMLParser.parse($0) }
        let nscPath = nscURL.map { workspace.relativePath($0) } ?? ""

        // --- Cleartext ------------------------------------------------------
        let manifestCleartext = app?.boolAttr("usesCleartextTraffic")
        let baseConfig = nsc?.children(named: "base-config").first
        let baseCleartext = baseConfig?.boolAttr("cleartextTrafficPermitted")
        var cleartextEvidence: [Evidence] = []
        var cleartextGlobal = false

        if let baseCleartext {
            if baseCleartext {
                cleartextGlobal = true
                cleartextEvidence.append(Evidence(file: nscPath, line: baseConfig?.line,
                                                  snippet: "<base-config cleartextTrafficPermitted=\"true\">"))
            }
        } else if manifestCleartext == true {
            cleartextGlobal = true
            cleartextEvidence.append(Evidence(file: manifest, line: app?.line, snippet: "android:usesCleartextTraffic=\"true\""))
        } else if manifestCleartext == nil && nsc == nil && target < 28 {
            cleartextGlobal = true
            cleartextEvidence.append(Evidence(file: manifest, line: app?.line,
                                              snippet: "usesCleartextTraffic not set; defaults to true for targetSdk \(target) < 28"))
        }
        if cleartextGlobal {
            out.append(Finding(
                ruleID: "NETWORK_CLEARTEXT_ALLOWED", title: "Cleartext traffic permitted app-wide",
                description: "The app allows unencrypted HTTP connections to any host. Credentials, session tokens and personal data sent over HTTP can be intercepted or modified on hostile networks.",
                severity: .high, category: .network, control: "MASVS-NETWORK-1",
                mastg: "MASTG-TEST-0019 (Testing Data Encryption on the Network)", cwe: "CWE-319",
                remediation: "Set `cleartextTrafficPermitted=\"false\"` in the Network Security Configuration base-config (and remove `usesCleartextTraffic=\"true\"`). Allow cleartext only for specific, non-sensitive domains if strictly necessary.",
                evidence: cleartextEvidence))
        }

        if let nsc {
            // Domain-level cleartext exceptions.
            let domainCleartext = nsc.descendants(named: "domain-config").filter { $0.boolAttr("cleartextTrafficPermitted") == true }
            if !domainCleartext.isEmpty {
                let ev = domainCleartext.map { dc -> Evidence in
                    let domains = dc.children(named: "domain").map { $0.text.trimmingCharacters(in: .whitespacesAndNewlines) }
                    return Evidence(file: nscPath, line: dc.line,
                                    snippet: "cleartextTrafficPermitted=\"true\" for: \(domains.joined(separator: ", "))")
                }
                out.append(Finding(
                    ruleID: "NETWORK_CLEARTEXT_DOMAINS", title: "Cleartext traffic permitted for specific domains",
                    description: "The Network Security Configuration allows HTTP for one or more domains. Make sure no sensitive data is exchanged with them.",
                    severity: .low, category: .network, control: "MASVS-NETWORK-1",
                    mastg: "MASTG-TEST-0019 (Testing Data Encryption on the Network)", cwe: "CWE-319",
                    remediation: "Migrate these domains to HTTPS and remove the exception.", evidence: ev))
            }

            // User CA trust outside debug-overrides.
            let userTrust = nsc.descendants(named: "certificates").filter { c in
                c.attr("src") == "user" && !isInside(c, "debug-overrides")
            }
            if !userTrust.isEmpty {
                out.append(Finding(
                    ruleID: "NETWORK_TRUSTS_USER_CA", title: "User-installed CA certificates are trusted",
                    description: "The Network Security Configuration trusts user-added certificate authorities in release builds. An attacker (or MDM/corporate proxy) who installs a CA can intercept the app's TLS traffic.",
                    severity: .medium, category: .network, control: "MASVS-NETWORK-1",
                    mastg: "MASTG-TEST-0022 (Testing Custom Certificate Stores and Certificate Pinning)", cwe: "CWE-295",
                    remediation: "Trust only `system` CAs in base-config; move `src=\"user\"` into `<debug-overrides>`.",
                    evidence: userTrust.map { Evidence(file: nscPath, line: $0.line, snippet: "<certificates src=\"user\"/>") }))
            }

            // Pin-set expiry.
            for pinSet in nsc.descendants(named: "pin-set") {
                if let exp = pinSet.attributes["expiration"], let date = ISO8601DateFormatter.dateOnly.date(from: exp), date < Date() {
                    out.append(Finding(
                        ruleID: "NETWORK_PIN_EXPIRED", title: "Certificate pin-set has expired",
                        description: "A `<pin-set>` expiration date (\(exp)) is in the past, so pinning is no longer enforced for those domains.",
                        severity: .medium, category: .network, control: "MASVS-NETWORK-2",
                        mastg: "MASTG-TEST-0022 (Testing Custom Certificate Stores and Certificate Pinning)", cwe: "CWE-295",
                        remediation: "Update the pins and extend the expiration, and ship backup pins.",
                        evidence: [Evidence(file: nscPath, line: pinSet.line, snippet: "<pin-set expiration=\"\(exp)\">")]))
                }
            }
        }

        // --- Pinning --------------------------------------------------------
        let nscPins = nsc.map { !$0.descendants(named: "pin-set").isEmpty } ?? false
        let codePins = presentTokens.contains("CertificatePinner") || presentTokens.contains("TrustKit")
            || presentTokens.contains("PinningTrustManager")
        if nscPins || codePins {
            var ev: [Evidence] = []
            if nscPins { ev.append(Evidence(file: nscPath, line: nil, snippet: "<pin-set> declared")) }
            if codePins { ev.append(Evidence(file: "jadx/sources", line: nil, snippet: "Pinning API referenced (OkHttp CertificatePinner / TrustKit)")) }
            out.append(Finding(
                ruleID: "NETWORK_PINNING_PRESENT", title: "Certificate pinning detected",
                description: "The app appears to implement certificate pinning. Confirm pins cover all sensitive endpoints, include backup pins, and that pinning cannot be bypassed via user CAs.",
                severity: .info, category: .network, control: "MASVS-NETWORK-2",
                mastg: "MASTG-TEST-0022 (Testing Custom Certificate Stores and Certificate Pinning)", cwe: nil,
                remediation: "No action required. Verify pin rotation procedures are documented.",
                evidence: ev))
        } else {
            out.append(Finding(
                ruleID: "NETWORK_NO_PINNING", title: "No certificate pinning detected",
                description: "No Network Security Configuration pin-set or common pinning library usage was found. Without pinning, a compromised or mis-issued CA certificate allows interception of TLS traffic. Pinning is recommended for apps handling high-value data (MASVS-L2).",
                severity: .low, category: .network, control: "MASVS-NETWORK-2",
                mastg: "MASTG-TEST-0022 (Testing Custom Certificate Stores and Certificate Pinning)", cwe: "CWE-295",
                remediation: "Add a `<pin-set>` to the Network Security Configuration (with a backup pin and an expiration) for your API domains, or use OkHttp `CertificatePinner`.",
                evidence: [Evidence(file: manifest, line: app?.line, snippet: nscRef.map { "networkSecurityConfig=\($0) (no pin-set)" } ?? "no networkSecurityConfig")]))
        }
        return out
    }

    private static func isInside(_ node: XMLNode, _ ancestor: String) -> Bool {
        var p = node.parent
        while let n = p {
            if n.name == ancestor { return true }
            p = n.parent
        }
        return false
    }
}

extension ISO8601DateFormatter {
    static let dateOnly: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withFullDate]
        return f
    }()
}
