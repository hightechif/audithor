import Foundation

struct ScanOptions: Codable, Hashable, Sendable {
    var cveMode: CVEMode = .off
    var runJadx: Bool = true
    var scanThirdPartyCode: Bool = false
    var maxEvidencePerFinding: Int = 25
    var keepWorkspace: Bool = false
    var jadxTimeoutMinutes: Int = 20
}

enum PipelineStage: String, CaseIterable, Identifiable, Sendable {
    case hashing = "Hashing & metadata"
    case unpacking = "Preparing input"
    case decoding = "Decoding manifest & resources (apktool)"
    case decompiling = "Decompiling DEX (jadx)"
    case signature = "Verifying signature"
    case scanning = "Running static checks"
    case libraries = "Inventorying SDKs"
    case finishing = "Scoring & saving"

    var id: String { rawValue }
}

struct PipelineProgress: Sendable {
    var stage: PipelineStage
    /// Overall progress 0…1.
    var fraction: Double
    var message: String
}

enum PipelineError: LocalizedError {
    case unsupportedFile(String)
    case missingTools([ExternalTool])
    case bundleWithoutBaseAPK
    case apktoolFailed(String)
    case manifestUnreadable

    var errorDescription: String? {
        switch self {
        case let .unsupportedFile(ext): return "Unsupported file type “.\(ext)”. Choose an .apk, .xapk or .apks file."
        case let .missingTools(t): return "Required tools are missing: \(t.map(\.displayName).joined(separator: ", ")). Open Tool Setup for install instructions."
        case .bundleWithoutBaseAPK: return "No base APK was found inside the bundle."
        case let .apktoolFailed(msg): return "apktool could not decode the APK:\n\(msg)"
        case .manifestUnreadable: return "The decoded AndroidManifest.xml could not be parsed."
        }
    }
}

/// Orchestrates the analysis. All work runs off the main thread; progress is
/// delivered through the `progress` callback (which callers hop to the main actor).
///
/// The input file is opened read-only and is never modified, repackaged or re-signed.
struct AnalysisPipeline: Sendable {
    let tools: ToolEnvironment
    let options: ScanOptions
    let progress: @Sendable (PipelineProgress) -> Void

    private static let weights: [PipelineStage: (Double, Double)] = [
        .hashing: (0.00, 0.04), .unpacking: (0.04, 0.08), .decoding: (0.08, 0.30),
        .decompiling: (0.30, 0.65), .signature: (0.65, 0.70), .scanning: (0.70, 0.92),
        .libraries: (0.92, 0.97), .finishing: (0.97, 1.0),
    ]

    private func report(_ stage: PipelineStage, _ within: Double = 0, _ message: String? = nil) {
        let (a, b) = Self.weights[stage] ?? (0, 1)
        progress(PipelineProgress(stage: stage, fraction: a + (b - a) * min(max(within, 0), 1),
                                  message: message ?? stage.rawValue))
    }

    func run(input: URL) async throws -> ScanResult {
        let started = Date()
        let scanID = UUID()
        var warnings: [String] = []

        let ext = input.pathExtension.lowercased()
        guard ["apk", "xapk", "apks", "apkm"].contains(ext) else { throw PipelineError.unsupportedFile(ext) }
        guard tools.missingRequired.isEmpty else { throw PipelineError.missingTools(tools.missingRequired) }
        let env = tools.processEnvironment
        let unzip = tools.path(.unzip)!

        // 1. Hash + metadata ------------------------------------------------
        report(.hashing, 0, "Computing SHA-256…")
        let attrs = try FileManager.default.attributesOfItem(atPath: input.path)
        let size = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        let sha = try FileHasher.sha256(of: input)
        try Task.checkCancellation()

        let workspace = try Workspace.create(scanID: scanID)
        defer { if !options.keepWorkspace { workspace.remove() } }

        // 2. Unpack bundles ----------------------------------------------
        report(.unpacking)
        var apk = input
        var bundled: [String] = []
        if ext != "apk" {
            // .xapk / .apks are zip containers of split APKs. Extract to the workspace (input untouched).
            let r = try await ProcessRunner.run(unzip, arguments: ["-q", "-o", input.path, "*.apk", "-d", workspace.bundleDir.path],
                                                environment: env, timeout: 300)
            if !r.succeeded && r.exitCode != 1 { warnings.append("unzip reported: \(r.stderr.prefix(300))") }
            let apks = Self.findAPKs(in: workspace.bundleDir)
            bundled = apks.map { workspace.relativePath($0).replacingOccurrences(of: "bundle/", with: "") }.sorted()
            let base = apks.first(where: { $0.lastPathComponent == "base.apk" || $0.lastPathComponent.hasPrefix("base-master") })
                ?? apks.first(where: { !$0.lastPathComponent.lowercased().contains("config.") && !$0.lastPathComponent.contains("split_") })
                ?? apks.max(by: { (fileSize($0)) < (fileSize($1)) })
            guard let base else { throw PipelineError.bundleWithoutBaseAPK }
            apk = base
            warnings.append("Bundle contains \(apks.count) APK(s); analysed base APK “\(base.lastPathComponent)”. Split APKs (resources/ABI) were not decompiled.")
        }

        // Entry listing (for v1 signature files, native libs) and META-INF metadata.
        let listing = try await ProcessRunner.run(unzip, arguments: ["-Z1", apk.path], environment: env, timeout: 120)
        let entries = listing.stdout.split(separator: "\n").map(String.init)
        _ = try? await ProcessRunner.run(unzip, arguments: ["-q", "-o", apk.path, "META-INF/*.version", "META-INF/maven/*",
                                                            "-d", workspace.metaInfDir.path], environment: env, timeout: 120)
        try Task.checkCancellation()

        // 3. apktool -----------------------------------------------------
        report(.decoding, 0.1, "Decoding with apktool…")
        let apktoolArgs = ["d", "-f", "-o", workspace.apktoolDir.path, "-p", workspace.frameworkDir.path, apk.path]
        let apktool = try await ProcessRunner.run(tools.path(.apktool)!, arguments: apktoolArgs, environment: env,
                                                  workingDirectory: workspace.root, timeout: 900)
        let manifestURL = workspace.apktoolDir.appendingPathComponent("AndroidManifest.xml")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw PipelineError.apktoolFailed(String((apktool.stderr + apktool.stdout).suffix(1500)))
        }
        if !apktool.succeeded { warnings.append("apktool exited with code \(apktool.exitCode); results may be partial.") }
        guard let parsed = ManifestParser.parse(apktoolDir: workspace.apktoolDir) else { throw PipelineError.manifestUnreadable }
        var appInfo = parsed.info
        report(.decoding, 1, "Manifest decoded: \(appInfo.packageName)")
        try Task.checkCancellation()

        // aapt2 badging cross-check (optional).
        if let aapt2 = tools.path(.aapt2),
           let r = try? await ProcessRunner.run(aapt2, arguments: ["dump", "badging", apk.path], environment: env, timeout: 120),
           r.succeeded {
            let b = r.stdout
            if appInfo.appLabel == nil { appInfo.appLabel = b.firstGroup("application-label:'([^']*)'") }
            if appInfo.minSdk == nil { appInfo.minSdk = b.firstGroup("sdkVersion:'(\\d+)'").flatMap(Int.init) }
            if appInfo.targetSdk == nil { appInfo.targetSdk = b.firstGroup("targetSdkVersion:'(\\d+)'").flatMap(Int.init) }
            if appInfo.compileSdk == nil { appInfo.compileSdk = b.firstGroup("compileSdkVersion='(\\d+)'").flatMap(Int.init) }
        }

        // 4. jadx (optional) ----------------------------------------------
        if options.runJadx, let jadx = tools.path(.jadx) {
            report(.decompiling, 0.05, "Decompiling with jadx (this can take a few minutes)…")
            let threads = max(2, ProcessInfo.processInfo.activeProcessorCount - 1)
            do {
                let r = try await ProcessRunner.run(jadx, arguments: [
                    "-d", workspace.jadxDir.path, "--no-res", "--show-bad-code", "--no-debug-info",
                    "-j", String(threads), apk.path,
                ], environment: env, workingDirectory: workspace.root, timeout: TimeInterval(options.jadxTimeoutMinutes * 60))
                if !r.succeeded {
                    // jadx returns non-zero when some methods fail to decompile; output is still usable.
                    let errs = r.stdout.components(separatedBy: "\n").last(where: { $0.contains("ERROR") && $0.contains("count") })
                    warnings.append("jadx finished with errors (exit \(r.exitCode))\(errs.map { ": \($0)" } ?? ""). Some classes may be missing.")
                }
            } catch let e as ProcessRunnerError {
                warnings.append("\(e.localizedDescription) Falling back to smali for code checks.")
            }
        } else if options.runJadx {
            warnings.append("jadx not installed — code checks ran against smali and are less precise.")
        }
        try Task.checkCancellation()

        // 5. Signature ----------------------------------------------------
        report(.signature)
        let signature = await SignatureAnalyzer.collect(apk: apk, entries: entries, tools: tools)
        if !tools.has(.apksigner) { warnings.append("apksigner not installed — signature schemes detected natively but not cryptographically verified.") }
        try Task.checkCancellation()

        // 6. Static checks ---------------------------------------------------
        report(.scanning, 0, "Indexing sources…")
        let index = SourceIndex.build(workspace: workspace, appPackage: appInfo.packageName)
        report(.scanning, 0.05, "Scanning \(index.files.count) files…")
        let engine = RuleEngine(rules: CodeRules.all(), probes: CodeRules.probes,
                                maxEvidence: options.maxEvidencePerFinding, includeThirdParty: options.scanThirdPartyCode)
        let progressCopy = progress
        let w = Self.weights[.scanning]!
        let engineResult = engine.run(index: index) { f in
            progressCopy(PipelineProgress(stage: .scanning, fraction: w.0 + (w.1 - w.0) * (0.05 + 0.85 * f),
                                          message: "Scanning sources… \(Int(f * 100))%"))
        }
        try Task.checkCancellation()

        var findings = engineResult.findings
        findings += ManifestChecks.run(parsed: ManifestParser.Parsed(root: parsed.root, info: appInfo, manifestURL: parsed.manifestURL),
                                       apktoolDir: workspace.apktoolDir, workspace: workspace,
                                       presentTokens: engineResult.presentTokens, hasJavaSources: index.hasJavaSources)
        findings += SignatureAnalyzer.findings(signature, minSdk: appInfo.minSdk)

        // External storage permission + usage combo raises confidence.
        if appInfo.permissions.contains("android.permission.WRITE_EXTERNAL_STORAGE"),
           let i = findings.firstIndex(where: { $0.ruleID == "STORAGE_EXTERNAL" }) {
            findings[i].description += "\n\nThe app also requests WRITE_EXTERNAL_STORAGE."
        }

        // 7. Libraries ---------------------------------------------------------
        report(.libraries)
        let libs = LibraryDetector.detect(entries: entries, metaInfDir: workspace.metaInfDir, workspace: workspace, sources: index)
        let db = LibraryDatabase.loadBundled()
        findings += VulnerabilityMatcher.outdatedFindings(libs, db: db)
        if options.cveMode != .off {
            findings += VulnerabilityMatcher.localCVEFindings(libs, db: db)
        }
        if options.cveMode == .online {
            report(.libraries, 0.5, "Querying OSV.dev (library coordinates only)…")
            let (online, warning) = await VulnerabilityMatcher.onlineFindings(libs)
            // Avoid duplicating CVEs already matched locally.
            let existing = Set(findings.map(\.ruleID))
            findings += online.filter { !existing.contains($0.ruleID) }
            if let warning { warnings.append(warning) }
        }
        if !libs.isEmpty {
            findings.append(Finding(
                ruleID: "CODE_SDK_INVENTORY", title: "Third-party SDK inventory (\(libs.count))",
                description: "Libraries and SDKs detected in the APK. Review each for necessity, data collection (privacy labels / Data safety form) and update status.",
                severity: .info, category: .code, control: "MASVS-CODE-3",
                mastg: "MASTG-TEST-0042 (Checking for Weaknesses in Third Party Libraries)", cwe: nil,
                remediation: "Keep an SBOM, remove unused SDKs, and monitor them for advisories.",
                evidence: libs.prefix(options.maxEvidencePerFinding * 4).map {
                    Evidence(file: $0.source, line: nil, snippet: "\($0.displayName)  \($0.coordinate)\($0.version.map { " " + $0 } ?? "")")
                }, occurrenceCount: libs.count))
        }

        // Deduplicate by fingerprint (rare, but rules can overlap).
        var seen = Set<String>()
        findings = findings.filter { seen.insert($0.fingerprint).inserted }

        // 8. Finish -----------------------------------------------------------
        report(.finishing)
        let result = ScanResult(
            id: scanID, startedAt: started, durationSeconds: Date().timeIntervalSince(started),
            input: InputFileInfo(fileName: input.lastPathComponent, fileSize: size, sha256: sha,
                                 containerType: ext, bundledAPKs: bundled),
            app: appInfo, signature: signature, libraries: libs, findings: findings,
            tools: tools.toolVersions,
            warnings: warnings + ["Scanned \(engineResult.filesScanned) files (\(index.javaCount) Java, \(index.smaliCount) smali)."],
            cveMode: options.cveMode.rawValue, riskScore: ScanResult.computeRiskScore(findings))
        report(.finishing, 1, "Done")
        return result
    }

    private static func findAPKs(in dir: URL) -> [URL] {
        var apks: [URL] = []
        if let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.fileSizeKey]) {
            for case let u as URL in e where u.pathExtension.lowercased() == "apk" { apks.append(u) }
        }
        return apks
    }

    private func fileSize(_ u: URL) -> Int {
        (try? u.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
    }
}
