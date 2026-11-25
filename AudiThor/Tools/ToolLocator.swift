import Foundation

/// External tools AudiThor orchestrates. Nothing is ever downloaded automatically;
/// missing tools are surfaced in the setup screen with Homebrew instructions.
enum ExternalTool: String, CaseIterable, Identifiable, Sendable {
    case java, apktool, jadx, aapt2, apksigner, keytool, openssl, unzip

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .java: return "Java runtime"
        case .apktool: return "apktool"
        case .jadx: return "jadx"
        case .aapt2: return "aapt2"
        case .apksigner: return "apksigner"
        case .keytool: return "keytool"
        case .openssl: return "openssl"
        case .unzip: return "unzip"
        }
    }

    var purpose: String {
        switch self {
        case .java: return "Required by apktool, jadx and apksigner."
        case .apktool: return "Decodes AndroidManifest.xml and resources."
        case .jadx: return "Decompiles DEX bytecode to Java for source-level checks."
        case .aapt2: return "Cross-checks package metadata (badging)."
        case .apksigner: return "Verifies signature schemes v1–v4 and extracts certificates."
        case .keytool: return "Fallback certificate extraction for v1-signed APKs."
        case .openssl: return "Parses signing certificates (validity, algorithm, key size)."
        case .unzip: return "Reads APK entries and unpacks .xapk/.apks bundles."
        }
    }

    /// Required tools block scanning; optional ones degrade gracefully.
    var isRequired: Bool { self == .java || self == .apktool || self == .unzip }

    var installHint: String {
        switch self {
        case .java: return "brew install --cask temurin"
        case .apktool: return "brew install apktool"
        case .jadx: return "brew install jadx"
        case .aapt2, .apksigner:
            return "brew install --cask android-commandlinetools && sdkmanager \"build-tools;35.0.0\""
        case .keytool: return "Included with the Java runtime (brew install --cask temurin)"
        case .openssl: return "Pre-installed on macOS (/usr/bin/openssl)"
        case .unzip: return "Pre-installed on macOS (/usr/bin/unzip)"
        }
    }

    var versionArguments: [String] {
        switch self {
        case .java: return ["-version"]
        case .apktool: return ["--version"]
        case .jadx: return ["--version"]
        case .aapt2: return ["version"]
        case .apksigner: return ["--version"]
        case .keytool: return ["-help"]
        case .openssl: return ["version"]
        case .unzip: return ["-v"]
        }
    }
}

struct ToolStatus: Identifiable, Hashable, Sendable {
    var tool: ExternalTool
    var path: URL?
    var version: String?
    var id: String { tool.rawValue }
    var isAvailable: Bool { path != nil }
}

/// Snapshot of which tools are installed, plus the environment used to run them.
struct ToolEnvironment: Sendable {
    var statuses: [ExternalTool: ToolStatus]
    var searchPaths: [String]

    func path(_ tool: ExternalTool) -> URL? { statuses[tool]?.path }
    func has(_ tool: ExternalTool) -> Bool { path(tool) != nil }

    var missingRequired: [ExternalTool] {
        ExternalTool.allCases.filter { $0.isRequired && !has($0) }
    }

    /// Environment for child processes. GUI apps launched from Finder don't inherit the
    /// shell PATH, so Homebrew/SDK directories are prepended explicitly (apktool and jadx
    /// are wrapper scripts that need `java` on PATH).
    var processEnvironment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        let existing = env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
        env["PATH"] = (searchPaths + [existing]).joined(separator: ":")
        if env["JAVA_HOME"] == nil, let java = path(.java),
           java.path.contains("/Contents/Home/bin/") {
            env["JAVA_HOME"] = java.deletingLastPathComponent().deletingLastPathComponent().path
        }
        // Keep the JVM from stealing focus with a Dock icon.
        env["JAVA_TOOL_OPTIONS"] = (env["JAVA_TOOL_OPTIONS"].map { $0 + " " } ?? "") + "-Djava.awt.headless=true"
        return env
    }

    var toolVersions: [ToolVersion] {
        ExternalTool.allCases.compactMap { t in
            guard let s = statuses[t], s.isAvailable else { return nil }
            return ToolVersion(name: t.rawValue, version: s.version, path: s.path?.path)
        }
    }
}

enum ToolLocator {
    /// Directories searched in order, in addition to the inherited PATH.
    static func candidateDirectories() -> [String] {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path
        var dirs = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]

        // Homebrew OpenJDK / Temurin
        dirs += ["/opt/homebrew/opt/openjdk/bin", "/usr/local/opt/openjdk/bin"]
        if let jvms = try? fm.contentsOfDirectory(atPath: "/Library/Java/JavaVirtualMachines") {
            dirs += jvms.sorted(by: >).map { "/Library/Java/JavaVirtualMachines/\($0)/Contents/Home/bin" }
        }

        // Android SDK build-tools (aapt2, apksigner) — newest first.
        var sdkRoots: [String] = []
        let env = ProcessInfo.processInfo.environment
        if let v = env["ANDROID_HOME"] { sdkRoots.append(v) }
        if let v = env["ANDROID_SDK_ROOT"] { sdkRoots.append(v) }
        sdkRoots += ["\(home)/Library/Android/sdk",
                     "/opt/homebrew/share/android-commandlinetools",
                     "/usr/local/share/android-commandlinetools"]
        for root in sdkRoots {
            let bt = "\(root)/build-tools"
            if let versions = try? fm.contentsOfDirectory(atPath: bt) {
                let sorted = versions.sorted { $0.compare($1, options: .numeric) == .orderedDescending }
                dirs += sorted.map { "\(bt)/\($0)" }
            }
        }

        if let path = env["PATH"] { dirs += path.split(separator: ":").map(String.init) }

        var seen = Set<String>()
        return dirs.filter { seen.insert($0).inserted }
    }

    static func locate(_ tool: ExternalTool, in dirs: [String]) -> URL? {
        let fm = FileManager.default
        // /usr/bin/java is a stub that pops a dialog when no JDK is installed; only
        // accept it if a real JVM exists.
        for dir in dirs {
            let p = "\(dir)/\(tool.rawValue)"
            guard fm.isExecutableFile(atPath: p) else { continue }
            if tool == .java || tool == .keytool, dir == "/usr/bin" {
                let jvms = (try? fm.contentsOfDirectory(atPath: "/Library/Java/JavaVirtualMachines")) ?? []
                if jvms.isEmpty { continue }
            }
            return URL(fileURLWithPath: p)
        }
        return nil
    }

    /// Detects all tools and their versions. Runs version commands concurrently.
    static func detect() async -> ToolEnvironment {
        let dirs = candidateDirectories()
        var statuses: [ExternalTool: ToolStatus] = [:]
        for tool in ExternalTool.allCases {
            statuses[tool] = ToolStatus(tool: tool, path: locate(tool, in: dirs), version: nil)
        }
        var env = ToolEnvironment(statuses: statuses, searchPaths: dirs)
        let procEnv = env.processEnvironment

        await withTaskGroup(of: (ExternalTool, String?).self) { group in
            for tool in ExternalTool.allCases {
                guard let url = statuses[tool]?.path, tool != .keytool else { continue }
                group.addTask {
                    let result = try? await ProcessRunner.run(url, arguments: tool.versionArguments,
                                                              environment: procEnv, timeout: 30)
                    let text = ((result?.stdout ?? "") + "\n" + (result?.stderr ?? ""))
                    return (tool, parseVersion(text, tool: tool))
                }
            }
            for await (tool, version) in group { env.statuses[tool]?.version = version }
        }
        return env
    }

    static func parseVersion(_ text: String, tool: ExternalTool) -> String? {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("Picked up JAVA_TOOL_OPTIONS") }
        guard let first = lines.first else { return nil }
        if tool == .java, let m = first.firstMatch(of: #/"([^"]+)"/#) { return String(m.1) }
        if let m = first.firstMatch(of: #/\d+(\.\d+)+[\w.\-]*/#) { return String(m.0) }
        return String(first.prefix(60))
    }
}
