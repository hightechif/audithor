import Foundation
import CryptoKit

/// Severity levels, ordered from most to least severe.
enum Severity: String, Codable, CaseIterable, Identifiable, Comparable, Sendable {
    case critical, high, medium, low, info

    var id: String { rawValue }

    var title: String { rawValue.capitalized }

    /// Lower rank = more severe. Used for sorting.
    var rank: Int {
        switch self {
        case .critical: return 0
        case .high: return 1
        case .medium: return 2
        case .low: return 3
        case .info: return 4
        }
    }

    /// Weight contributed to the overall risk score.
    var weight: Double {
        switch self {
        case .critical: return 30
        case .high: return 12
        case .medium: return 5
        case .low: return 1.5
        case .info: return 0
        }
    }

    static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank > rhs.rank }
}

/// OWASP MASVS v2 control groups.
enum MASVSCategory: String, Codable, CaseIterable, Identifiable, Sendable {
    case storage = "MASVS-STORAGE"
    case crypto = "MASVS-CRYPTO"
    case auth = "MASVS-AUTH"
    case network = "MASVS-NETWORK"
    case platform = "MASVS-PLATFORM"
    case code = "MASVS-CODE"
    case resilience = "MASVS-RESILIENCE"
    case privacy = "MASVS-PRIVACY"

    var id: String { rawValue }

    var shortTitle: String {
        switch self {
        case .storage: return "Storage"
        case .crypto: return "Crypto"
        case .auth: return "Auth"
        case .network: return "Network"
        case .platform: return "Platform"
        case .code: return "Code"
        case .resilience: return "Resilience"
        case .privacy: return "Privacy"
        }
    }

    var referenceURL: URL? {
        let slug = rawValue.lowercased()
        return URL(string: "https://mas.owasp.org/MASVS/controls/\(slug)/")
    }
}

/// A location in the decoded/decompiled output that supports a finding.
struct Evidence: Codable, Hashable, Sendable {
    /// Path relative to the analysis workspace (e.g. `sources/com/foo/Bar.java`).
    var file: String
    var line: Int?
    var snippet: String?

    var locationLabel: String {
        if let line { return "\(file):\(line)" }
        return file
    }
}

/// A single static-analysis result.
struct Finding: Codable, Hashable, Identifiable, Sendable {
    /// Stable identifier for a rule (e.g. `MANIFEST_DEBUGGABLE`).
    var ruleID: String
    var title: String
    var description: String
    var severity: Severity
    var category: MASVSCategory
    /// Specific MASVS control, e.g. `MASVS-PLATFORM-1`.
    var masvsControl: String
    /// Related MASTG test / technique, if any.
    var mastgReference: String?
    /// CWE identifier, e.g. `CWE-926`.
    var cwe: String?
    var remediation: String
    var evidence: [Evidence]
    /// Total matches found; `evidence` may be truncated.
    var occurrenceCount: Int

    init(ruleID: String, title: String, description: String, severity: Severity,
         category: MASVSCategory, control masvsControl: String, mastg mastgReference: String? = nil,
         cwe: String? = nil, remediation: String, evidence: [Evidence] = [], occurrenceCount: Int? = nil) {
        self.ruleID = ruleID
        self.title = title
        self.description = description
        self.severity = severity
        self.category = category
        self.masvsControl = masvsControl
        self.mastgReference = mastgReference
        self.cwe = cwe
        self.remediation = remediation
        self.evidence = evidence
        self.occurrenceCount = occurrenceCount ?? max(evidence.count, 1)
    }

    /// Fingerprint used to match the same issue across scans (diff mode).
    /// Based on the rule and the *set of files* involved, ignoring line numbers,
    /// which shift between versions.
    var fingerprint: String {
        let files = Set(evidence.map { $0.file }).sorted().joined(separator: "|")
        let digest = SHA256.hash(data: Data("\(ruleID)#\(files)".utf8))
        return digest.prefix(12).map { String(format: "%02x", $0) }.joined()
    }

    var id: String { fingerprint }

    var cweURL: URL? {
        guard let cwe, let num = cwe.split(separator: "-").last else { return nil }
        return URL(string: "https://cwe.mitre.org/data/definitions/\(num).html")
    }
}
