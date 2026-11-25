import Foundation

/// Metadata about the analysed input file.
struct InputFileInfo: Codable, Hashable, Sendable {
    var fileName: String
    var fileSize: Int64
    var sha256: String
    /// `apk`, `xapk` or `apks`.
    var containerType: String
    /// For bundles: the APK entries found inside the container.
    var bundledAPKs: [String]
}

struct ComponentInfo: Codable, Hashable, Identifiable, Sendable {
    var id: String { "\(kind.rawValue):\(name)" }
    enum Kind: String, Codable, Sendable { case activity, activityAlias = "activity-alias", service, receiver, provider }
    var kind: Kind
    var name: String
    var exported: Bool
    var exportedExplicit: Bool
    var permission: String?
    var hasIntentFilter: Bool
}

/// Application metadata extracted from the manifest / aapt2.
struct AppInfo: Codable, Hashable, Sendable {
    var packageName: String = "unknown"
    var appLabel: String?
    var versionName: String?
    var versionCode: String?
    var minSdk: Int?
    var targetSdk: Int?
    var compileSdk: Int?
    var permissions: [String] = []
    var customPermissions: [String: String] = [:] // name -> protectionLevel
    var components: [ComponentInfo] = []
}

struct SignerCertificate: Codable, Hashable, Sendable {
    var subject: String
    var issuer: String?
    var sha256: String?
    var signatureAlgorithm: String?
    var keyAlgorithm: String?
    var keySize: Int?
    var notBefore: Date?
    var notAfter: Date?
}

struct SignatureInfo: Codable, Hashable, Sendable {
    var verified: Bool?
    var schemes: [String: Bool] = [:] // "v1" -> true
    var certificates: [SignerCertificate] = []
    var rawOutput: String?
    var source: String = "none" // apksigner / keytool / none
}

/// A third-party library detected in the APK.
struct DetectedLibrary: Codable, Hashable, Identifiable, Sendable {
    /// Maven-style coordinate when known (`group:artifact`), otherwise a display name.
    var coordinate: String
    var displayName: String
    var version: String?
    /// How it was detected (META-INF version file, pom.properties, code signature…).
    var source: String
    var notes: [String] = []

    var id: String { coordinate }
}

struct ToolVersion: Codable, Hashable, Sendable {
    var name: String
    var version: String?
    var path: String?
}

/// The complete result of one scan. Persisted as JSON in SQLite and exported verbatim.
struct ScanResult: Codable, Hashable, Identifiable, Sendable {
    static let schemaVersion = 1

    var schemaVersion: Int = ScanResult.schemaVersion
    var id: UUID
    var startedAt: Date
    var durationSeconds: Double
    var input: InputFileInfo
    var app: AppInfo
    var signature: SignatureInfo
    var libraries: [DetectedLibrary]
    var findings: [Finding]
    var tools: [ToolVersion]
    var warnings: [String]
    var cveMode: String
    var riskScore: Int

    var counts: [Severity: Int] {
        var c: [Severity: Int] = [:]
        for f in findings { c[f.severity, default: 0] += 1 }
        return c
    }

    var sortedFindings: [Finding] {
        findings.sorted {
            if $0.severity.rank != $1.severity.rank { return $0.severity.rank < $1.severity.rank }
            if $0.category != $1.category { return $0.category.rawValue < $1.category.rawValue }
            return $0.title < $1.title
        }
    }

    var displayName: String { app.appLabel ?? app.packageName }

    /// 0 (no issues) – 100 (severe). Diminishing returns so many lows don't swamp the score.
    static func computeRiskScore(_ findings: [Finding]) -> Int {
        let raw = findings.reduce(0.0) { acc, f in
            // Additional occurrences add a little weight, logarithmically.
            acc + f.severity.weight * (1 + log10(Double(max(f.occurrenceCount, 1))) * 0.25)
        }
        // Map onto 0–100 with a soft cap.
        let score = 100 * (1 - exp(-raw / 80))
        return Int(score.rounded())
    }

    static func riskLabel(for score: Int) -> String {
        switch score {
        case 0..<15: return "Low"
        case 15..<40: return "Moderate"
        case 40..<70: return "High"
        default: return "Critical"
        }
    }
}

/// Lightweight row used for the history sidebar.
struct ScanSummary: Identifiable, Hashable, Sendable {
    var id: UUID
    var startedAt: Date
    var packageName: String
    var appLabel: String?
    var versionName: String?
    var fileName: String
    var sha256: String
    var riskScore: Int
    var findingCount: Int
}
