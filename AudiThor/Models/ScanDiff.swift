import Foundation

/// Comparison between two scans (typically two versions of the same app).
struct ScanDiff: Sendable {
    struct SeverityChange: Hashable, Identifiable, Sendable {
        var before: Finding
        var after: Finding
        var id: String { after.fingerprint }
    }

    var baseline: ScanResult
    var comparison: ScanResult

    var newFindings: [Finding] = []
    var resolvedFindings: [Finding] = []
    var persistingFindings: [Finding] = []
    var severityChanges: [SeverityChange] = []

    var addedPermissions: [String] = []
    var removedPermissions: [String] = []
    var addedLibraries: [DetectedLibrary] = []
    var removedLibraries: [DetectedLibrary] = []
    var changedLibraries: [(name: String, from: String?, to: String?)] = []
    var metadataChanges: [(field: String, from: String, to: String)] = []

    var samePackage: Bool { baseline.app.packageName == comparison.app.packageName }

    init(baseline: ScanResult, comparison: ScanResult) {
        self.baseline = baseline
        self.comparison = comparison

        // Findings are matched first by fingerprint (rule + files), then loosely by
        // rule ID so that a finding whose evidence moved files is not double-counted.
        var unmatchedBefore = Dictionary(grouping: baseline.findings, by: { $0.fingerprint })
            .compactMapValues { $0.first }
        var remainingAfter: [Finding] = []
        for f in comparison.findings {
            if let b = unmatchedBefore.removeValue(forKey: f.fingerprint) {
                persistingFindings.append(f)
                if b.severity != f.severity { severityChanges.append(.init(before: b, after: f)) }
            } else {
                remainingAfter.append(f)
            }
        }
        var beforeByRule = Dictionary(grouping: unmatchedBefore.values, by: { $0.ruleID })
        for f in remainingAfter {
            if var list = beforeByRule[f.ruleID], !list.isEmpty {
                let b = list.removeFirst()
                beforeByRule[f.ruleID] = list
                persistingFindings.append(f)
                if b.severity != f.severity { severityChanges.append(.init(before: b, after: f)) }
            } else {
                newFindings.append(f)
            }
        }
        resolvedFindings = beforeByRule.values.flatMap { $0 }

        let sortFn: (Finding, Finding) -> Bool = { $0.severity.rank < $1.severity.rank }
        newFindings.sort(by: sortFn)
        resolvedFindings.sort(by: sortFn)
        persistingFindings.sort(by: sortFn)

        let p0 = Set(baseline.app.permissions), p1 = Set(comparison.app.permissions)
        addedPermissions = p1.subtracting(p0).sorted()
        removedPermissions = p0.subtracting(p1).sorted()

        let l0 = Dictionary(baseline.libraries.map { ($0.coordinate, $0) }, uniquingKeysWith: { a, _ in a })
        let l1 = Dictionary(comparison.libraries.map { ($0.coordinate, $0) }, uniquingKeysWith: { a, _ in a })
        addedLibraries = l1.keys.filter { l0[$0] == nil }.sorted().compactMap { l1[$0] }
        removedLibraries = l0.keys.filter { l1[$0] == nil }.sorted().compactMap { l0[$0] }
        changedLibraries = l1.keys.sorted().compactMap { key in
            guard let a = l0[key], let b = l1[key], a.version != b.version else { return nil }
            return (b.displayName, a.version, b.version)
        }

        func add(_ field: String, _ a: String?, _ b: String?) {
            let x = a ?? "—", y = b ?? "—"
            if x != y { metadataChanges.append((field, x, y)) }
        }
        add("Package", baseline.app.packageName, comparison.app.packageName)
        add("Version name", baseline.app.versionName, comparison.app.versionName)
        add("Version code", baseline.app.versionCode, comparison.app.versionCode)
        add("minSdk", baseline.app.minSdk.map(String.init), comparison.app.minSdk.map(String.init))
        add("targetSdk", baseline.app.targetSdk.map(String.init), comparison.app.targetSdk.map(String.init))
        add("Signing cert", baseline.signature.certificates.first?.sha256, comparison.signature.certificates.first?.sha256)
        add("Risk score", String(baseline.riskScore), String(comparison.riskScore))
    }
}
