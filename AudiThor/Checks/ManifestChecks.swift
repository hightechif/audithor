import Foundation

/// Checks driven by AndroidManifest.xml and the Network Security Configuration.
enum ManifestChecks {
    static let manifestPath = "apktool/AndroidManifest.xml"

    static func run(parsed: ManifestParser.Parsed, apktoolDir: URL, workspace: Workspace,
                    presentTokens: Set<String>, hasJavaSources: Bool) -> [Finding] {
        var findings: [Finding] = []
        let root = parsed.root
        let info = parsed.info
        let app = root.children(named: "application").first
        let target = info.targetSdk ?? 0

        func ev(_ node: XMLNode?, _ snippet: String) -> Evidence {
            Evidence(file: manifestPath, line: node?.line, snippet: snippet)
        }

        // --- debuggable -----------------------------------------------------
        if let app, app.boolAttr("debuggable") == true {
            findings.append(Finding(
                ruleID: "MANIFEST_DEBUGGABLE", title: "Application is debuggable",
                description: "`android:debuggable=\"true\"` lets anyone with ADB access attach a debugger, run code as the app (`run-as`), and read its private data.",
                severity: .high, category: .resilience, control: "MASVS-RESILIENCE-4",
                mastg: "MASTG-TEST-0039 (Testing whether the App is Debuggable)", cwe: "CWE-489",
                remediation: "Remove `android:debuggable` from the manifest; the build system sets it only for debug builds.",
                evidence: [ev(app, "android:debuggable=\"true\"")]))
        }

        // --- allowBackup ----------------------------------------------------
        if let app {
            let backup = app.boolAttr("allowBackup")
            let hasRules = app.attr("fullBackupContent") != nil || app.attr("dataExtractionRules") != nil
            if backup == true || (backup == nil && !hasRules) {
                findings.append(Finding(
                    ruleID: "MANIFEST_ALLOW_BACKUP", title: "Application data can be backed up",
                    description: backup == true
                        ? "`android:allowBackup=\"true\"` allows app data to be extracted via ADB backup (API < 31) and copied to cloud / device-to-device transfer."
                        : "`android:allowBackup` is not set, so it defaults to true. App data may be included in ADB and cloud backups.",
                    severity: hasRules ? .low : .medium, category: .storage, control: "MASVS-STORAGE-2",
                    mastg: "MASTG-TEST-0009 (Testing Backups for Sensitive Data)", cwe: "CWE-530",
                    remediation: "Set `android:allowBackup=\"false\"`, or provide `dataExtractionRules` / `fullBackupContent` that exclude credentials, tokens and personal data.",
                    evidence: [ev(app, "android:allowBackup=\"\(backup.map { String($0) } ?? "(default true)")\"")]))
            }
        }

        // --- SDK levels -----------------------------------------------------
        if let t = info.targetSdk {
            var notes: [String] = []
            if t < 24 { notes.append("user-installed CA certificates are trusted by default (API < 24)") }
            if t < 28 { notes.append("cleartext HTTP is permitted by default (API < 28)") }
            if t < 31 { notes.append("components with intent filters are implicitly exported (API < 31)") }
            if t < 17 { notes.append("content providers are exported by default (API < 17)") }
            let sev: Severity = t < 24 ? .high : (t < 30 ? .medium : (t < 34 ? .low : .info))
            if sev != .info {
                findings.append(Finding(
                    ruleID: "MANIFEST_LOW_TARGET_SDK", title: "Outdated targetSdkVersion (\(t))",
                    description: "The app targets API level \(t). Android keeps legacy, less secure behaviour for apps targeting older levels" + (notes.isEmpty ? "." : ": " + notes.joined(separator: "; ") + ".") + " Google Play also requires a recent target API level for new releases.",
                    severity: sev, category: .code, control: "MASVS-CODE-1",
                    mastg: "MASTG-TEST-0036 (Testing Enforced Updating)", cwe: "CWE-1104",
                    remediation: "Raise targetSdkVersion to the latest stable API level and address behaviour changes.",
                    evidence: [Evidence(file: "apktool/apktool.yml", line: nil, snippet: "targetSdkVersion: \(t)")]))
            }
        }
        if let m = info.minSdk, m < 23 {
            findings.append(Finding(
                ruleID: "MANIFEST_LOW_MIN_SDK", title: "Low minSdkVersion (\(m))",
                description: "The app supports API level \(m). Devices on these versions no longer receive security patches and lack platform protections (runtime permissions, hardware-backed Keystore guarantees, TLS 1.2 by default on < 20).",
                severity: m < 21 ? .medium : .low, category: .code, control: "MASVS-CODE-1",
                mastg: nil, cwe: "CWE-1104",
                remediation: "Raise minSdkVersion to at least 23 where business requirements allow, or apply compensating controls for legacy devices.",
                evidence: [Evidence(file: "apktool/apktool.yml", line: nil, snippet: "minSdkVersion: \(m)")]))
        }

        // --- Exported components -------------------------------------------
        findings += exportedComponentFindings(root: root, app: app, info: info, target: target)

        // --- Deep links -----------------------------------------------------
        findings += deepLinkFindings(app: app)

        // --- Permissions ----------------------------------------------------
        findings += permissionFindings(info: info, presentTokens: presentTokens, hasJavaSources: hasJavaSources,
                                       root: root)

        // --- Cleartext & Network Security Config -----------------------------
        findings += NetworkConfigChecks.run(app: app, info: info, apktoolDir: apktoolDir, workspace: workspace,
                                            presentTokens: presentTokens)
        return findings
    }

    // MARK: - Exported components

    private static func exportedComponentFindings(root: XMLNode, app: XMLNode?, info: AppInfo, target: Int) -> [Finding] {
        guard let app else { return [] }
        var byKind: [ComponentInfo.Kind: [Evidence]] = [:]
        var weakGuard: [Evidence] = []

        for kind in [ComponentInfo.Kind.activity, .activityAlias, .service, .receiver, .provider] {
            for node in app.children(named: kind.rawValue) {
                guard let raw = node.attr("name") else { continue }
                let qualified = ManifestParser.qualifiedName(raw, package: info.packageName)
                guard let comp = info.components.first(where: { $0.kind == kind && $0.name == qualified }),
                      comp.exported else { continue }

                // The launcher activity must be exported; don't flag it.
                let isLauncher = node.children(named: "intent-filter").contains { f in
                    f.children(named: "category").contains { $0.attr("name") == "android.intent.category.LAUNCHER" }
                }
                if isLauncher { continue }

                // System-protected actions (e.g. BOOT_COMPLETED only from the system) are lower risk but still flagged.
                let implicit = comp.exportedExplicit ? "" : " (implicitly exported via intent-filter)"
                let snippet = "<\(kind.rawValue) android:name=\"\(comp.name)\" exported=true\(implicit)>"

                if let perm = comp.permission {
                    // Guarded — but is the guard strong?
                    if let level = info.customPermissions[perm], !level.contains("signature") {
                        weakGuard.append(Evidence(file: manifestPath, line: node.line,
                                                  snippet: "\(snippet) guarded by \(perm) (protectionLevel=\(level))"))
                    }
                    continue
                }
                byKind[kind, default: []].append(Evidence(file: manifestPath, line: node.line, snippet: snippet))
            }
        }

        var out: [Finding] = []
        let common = "Exported components can be started or queried by any app on the device. Without a permission guard, a malicious app can invoke internal functionality, inject data, or (for providers) read and write app data."
        let remediation = "Set `android:exported=\"false\"` unless the component must be reachable by other apps. If it must be exported, protect it with a `signature`-level permission and validate all incoming Intent data."

        let order: [(ComponentInfo.Kind, String, Severity)] = [
            (.provider, "Exported content providers without permission", .high),
            (.service, "Exported services without permission", .medium),
            (.receiver, "Exported broadcast receivers without permission", .medium),
            (.activity, "Exported activities without permission", .low),
            (.activityAlias, "Exported activity aliases without permission", .low),
        ]
        for (kind, title, sev) in order {
            guard let ev = byKind[kind], !ev.isEmpty else { continue }
            out.append(Finding(
                ruleID: "MANIFEST_EXPORTED_\(kind.rawValue.uppercased().replacingOccurrences(of: "-", with: "_"))",
                title: "\(title) (\(ev.count))", description: common,
                severity: sev, category: .platform, control: "MASVS-PLATFORM-1",
                mastg: "MASTG-TEST-0029 (Testing for Sensitive Functionality Exposure Through IPC)", cwe: "CWE-926",
                remediation: remediation, evidence: ev))
        }
        if !weakGuard.isEmpty {
            out.append(Finding(
                ruleID: "MANIFEST_WEAK_PERMISSION_GUARD", title: "Exported components guarded by non-signature permissions",
                description: "These components are protected by custom permissions with `normal` or `dangerous` protection level. Any app can request such permissions, so the guard provides little protection.",
                severity: .medium, category: .platform, control: "MASVS-PLATFORM-1",
                mastg: "MASTG-TEST-0024 (Testing for App Permissions)", cwe: "CWE-926",
                remediation: "Use `android:protectionLevel=\"signature\"` for permissions that guard internal components.",
                evidence: weakGuard))
        }
        return out
    }

    // MARK: - Deep links

    private static func deepLinkFindings(app: XMLNode?) -> [Finding] {
        guard let app else { return [] }
        var custom: [Evidence] = [], unverified: [Evidence] = []
        let webSchemes: Set<String> = ["http", "https"]

        for kind in ["activity", "activity-alias"] {
            for node in app.children(named: kind) {
                for filter in node.children(named: "intent-filter") {
                    let actions = filter.children(named: "action").compactMap { $0.attr("name") }
                    let categories = filter.children(named: "category").compactMap { $0.attr("name") }
                    guard actions.contains("android.intent.action.VIEW"),
                          categories.contains("android.intent.category.BROWSABLE") else { continue }
                    let datas = filter.children(named: "data")
                    let schemes = Set(datas.compactMap { $0.attr("scheme") })
                    let hosts = datas.compactMap { $0.attr("host") }
                    let comp = node.attr("name") ?? "?"
                    for scheme in schemes.sorted() {
                        let uri = "\(scheme)://\(hosts.first ?? "*")"
                        let e = Evidence(file: manifestPath, line: filter.line, snippet: "\(comp) handles \(uri)")
                        if webSchemes.contains(scheme) {
                            if filter.boolAttr("autoVerify") != true { unverified.append(e) }
                        } else {
                            custom.append(e)
                        }
                    }
                }
            }
        }
        var out: [Finding] = []
        if !custom.isEmpty {
            out.append(Finding(
                ruleID: "MANIFEST_CUSTOM_SCHEME_DEEPLINK", title: "Custom URL scheme deep links (\(custom.count))",
                description: "The app registers custom-scheme deep links. Any app can register the same scheme and intercept these links (e.g. OAuth redirects), and any web page can trigger them with attacker-controlled parameters.",
                severity: .medium, category: .platform, control: "MASVS-PLATFORM-1",
                mastg: "MASTG-TEST-0028 (Testing Deep Links)", cwe: "CWE-939",
                remediation: "Prefer verified Android App Links (https + autoVerify). Treat all deep-link parameters as untrusted input and never perform sensitive actions without user confirmation.",
                evidence: custom))
        }
        if !unverified.isEmpty {
            out.append(Finding(
                ruleID: "MANIFEST_UNVERIFIED_APP_LINK", title: "HTTP(S) deep links without autoVerify (\(unverified.count))",
                description: "Web deep links are declared without `android:autoVerify=\"true\"`, so other apps can claim the same URLs and the user may be shown a disambiguation dialog.",
                severity: .low, category: .platform, control: "MASVS-PLATFORM-1",
                mastg: "MASTG-TEST-0028 (Testing Deep Links)", cwe: "CWE-939",
                remediation: "Add `android:autoVerify=\"true\"` and publish a matching `/.well-known/assetlinks.json` on each host.",
                evidence: unverified))
        }
        return out
    }

    // MARK: - Permissions

    static let dangerousPermissions: Set<String> = [
        "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO",
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CALL_LOG",
        "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS", "BODY_SENSORS",
        "BODY_SENSORS_BACKGROUND", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "ACCESS_MEDIA_LOCATION", "ACTIVITY_RECOGNITION",
        "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES",
        "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO", "POST_NOTIFICATIONS", "UWB_RANGING",
    ]

    /// Permissions that grant unusually broad capabilities and deserve justification.
    static let highRiskPermissions: Set<String> = [
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        "ACCESS_BACKGROUND_LOCATION", "MANAGE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES",
        "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
        "READ_PHONE_NUMBERS", "WRITE_SETTINGS", "PACKAGE_USAGE_STATS", "BIND_NOTIFICATION_LISTENER_SERVICE",
    ]

    private static func permissionFindings(info: AppInfo, presentTokens: Set<String>, hasJavaSources: Bool,
                                           root: XMLNode) -> [Finding] {
        var out: [Finding] = []
        let lineFor: (String) -> Int? = { name in
            root.children(named: "uses-permission").first(where: { $0.attr("name") == name })?.line
        }
        func short(_ p: String) -> String { p.components(separatedBy: ".").last ?? p }

        let dangerous = info.permissions.filter { $0.hasPrefix("android.permission.") && dangerousPermissions.contains(short($0)) }
        if !dangerous.isEmpty {
            out.append(Finding(
                ruleID: "MANIFEST_DANGEROUS_PERMISSIONS", title: "Dangerous permissions requested (\(dangerous.count))",
                description: "The app requests runtime (\"dangerous\") permissions that grant access to personal data or device capabilities. Each should be justified by a user-facing feature.",
                severity: .info, category: .privacy, control: "MASVS-PRIVACY-1",
                mastg: "MASTG-TEST-0024 (Testing for App Permissions)", cwe: "CWE-250",
                remediation: "Request only the permissions needed, at the time they are needed, and explain why to the user.",
                evidence: dangerous.map { Evidence(file: manifestPath, line: lineFor($0), snippet: $0) }))
        }

        let highRisk = info.permissions.filter { highRiskPermissions.contains(short($0)) }
        if !highRisk.isEmpty {
            out.append(Finding(
                ruleID: "MANIFEST_HIGH_RISK_PERMISSIONS", title: "High-risk permissions requested (\(highRisk.count))",
                description: "These permissions grant broad access (SMS, call logs, background location, all-files access, overlay, package installation…) and are frequently abused by malware. Google Play restricts most of them to specific use cases.",
                severity: .medium, category: .privacy, control: "MASVS-PRIVACY-1",
                mastg: "MASTG-TEST-0024 (Testing for App Permissions)", cwe: "CWE-250",
                remediation: "Remove the permission or replace it with a narrower API (e.g. SMS Retriever API, Photo Picker, scoped storage, package visibility `<queries>`).",
                evidence: highRisk.map { Evidence(file: manifestPath, line: lineFor($0), snippet: $0) }))
        }

        // Requested vs. used (needs decompiled code to be meaningful).
        if hasJavaSources {
            let unused = info.permissions.filter { p in
                guard let tokens = PermissionUsage.map[p] else { return false }
                return !tokens.contains(where: presentTokens.contains)
            }
            if !unused.isEmpty {
                out.append(Finding(
                    ruleID: "MANIFEST_UNUSED_PERMISSIONS", title: "Permissions without matching API usage (\(unused.count))",
                    description: "No references to the APIs normally associated with these permissions were found in the decompiled code. The app may be over-privileged (or uses the API via reflection / native code).",
                    severity: .low, category: .privacy, control: "MASVS-PRIVACY-1",
                    mastg: "MASTG-TEST-0024 (Testing for App Permissions)", cwe: "CWE-250",
                    remediation: "Remove permissions that aren't required. Check merged manifests from libraries (`tools:node=\"remove\"`).",
                    evidence: unused.map { Evidence(file: manifestPath, line: lineFor($0), snippet: $0) }))
            }
        }

        // Custom permissions defined with weak protection levels.
        let weakCustom = info.customPermissions.filter { !$0.value.contains("signature") }
        if !weakCustom.isEmpty {
            out.append(Finding(
                ruleID: "MANIFEST_WEAK_CUSTOM_PERMISSION", title: "Custom permissions without signature protection (\(weakCustom.count))",
                description: "The app defines custom permissions with `normal` or `dangerous` protection levels. Any installed app can obtain them.",
                severity: .low, category: .platform, control: "MASVS-PLATFORM-1",
                mastg: "MASTG-TEST-0024 (Testing for App Permissions)", cwe: "CWE-276",
                remediation: "Use `signature` protection for permissions that protect internal functionality.",
                evidence: weakCustom.keys.sorted().map { Evidence(file: manifestPath, line: nil, snippet: "\($0) protectionLevel=\(weakCustom[$0] ?? "")") }))
        }
        return out
    }
}
