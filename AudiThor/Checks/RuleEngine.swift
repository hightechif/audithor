import Foundation

/// A match produced by a code rule.
struct RuleHit: Sendable {
    var line: Int
    var snippet: String
}

/// Declarative description of a source-level check.
struct CodeRule: Sendable {
    enum Matcher: Sendable {
        /// Regex applied to each line. Optional `exclude` suppresses false positives.
        case line(NSRegularExpression, exclude: NSRegularExpression? = nil)
        /// Arbitrary whole-file logic returning hits (used for multi-line / co-occurrence checks).
        case file(@Sendable (_ content: String, _ lines: [Substring]) -> [RuleHit])
    }

    var id: String
    var title: String
    var description: String
    var severity: Severity
    var category: MASVSCategory
    var control: String
    var mastg: String? = nil
    var cwe: String? = nil
    var remediation: String
    var kinds: Set<SourceKind>
    /// Cheap substring pre-filter: the file must contain at least one of these
    /// before any regex runs. Keeps the scan fast on large apps.
    var prefilter: [String]
    var matcher: Matcher
    /// Mask the matched secret in evidence snippets.
    var masksSecrets: Bool = false
    /// Scan library code too (e.g. for SDK-wide insecure TrustManagers).
    var includeThirdParty: Bool = false

    func finding(evidence: [Evidence], count: Int, onlyThirdParty: Bool) -> Finding {
        var sev = severity
        var desc = description
        if onlyThirdParty {
            // Can't be fixed directly by the app owner; downgrade one level.
            sev = Severity.allCases.first(where: { $0.rank == min(severity.rank + 1, Severity.info.rank) }) ?? severity
            desc += "\n\nAll occurrences are inside third-party library code. Update or replace the library, or confirm the code path is unreachable."
        }
        return Finding(ruleID: id, title: title, description: desc, severity: sev, category: category,
                       control: control, mastg: mastg, cwe: cwe, remediation: remediation,
                       evidence: evidence, occurrenceCount: count)
    }
}

/// Single-pass, parallel scanner: each file is read once and every applicable
/// rule and presence probe is evaluated against it.
final class RuleEngine: @unchecked Sendable {
    struct Result: Sendable {
        var findings: [Finding]
        /// Presence probes that matched somewhere (e.g. "CertificatePinner").
        var presentTokens: Set<String>
        /// Presence probes that matched in first-party code.
        var presentTokensFirstParty: Set<String>
        var filesScanned: Int
    }

    private let rules: [CodeRule]
    private let probes: [String]
    private let maxEvidence: Int
    private let includeThirdParty: Bool
    private let lock = NSLock()

    private var hits: [String: (evidence: [Evidence], count: Int, thirdPartyOnly: Bool)] = [:]
    private var present = Set<String>()
    private var presentFirstParty = Set<String>()

    init(rules: [CodeRule], probes: [String], maxEvidence: Int, includeThirdParty: Bool) {
        self.rules = rules
        self.probes = probes
        self.maxEvidence = maxEvidence
        self.includeThirdParty = includeThirdParty
    }

    func run(index: SourceIndex, progress: @Sendable (Double) -> Void) -> Result {
        let files = index.files
        let total = max(files.count, 1)
        let chunk = 64
        let chunks = (files.count + chunk - 1) / chunk
        var done = 0
        let progressLock = NSLock()

        DispatchQueue.concurrentPerform(iterations: chunks) { ci in
            let start = ci * chunk, end = min(start + chunk, files.count)
            for i in start..<end { scan(files[i]) }
            progressLock.lock()
            done += end - start
            let d = done
            progressLock.unlock()
            progress(Double(d) / Double(total))
        }

        var findings: [Finding] = []
        for rule in rules {
            guard let h = hits[rule.id], h.count > 0 else { continue }
            findings.append(rule.finding(evidence: h.evidence, count: h.count, onlyThirdParty: h.thirdPartyOnly))
        }
        return Result(findings: findings, presentTokens: present, presentTokensFirstParty: presentFirstParty,
                      filesScanned: files.count)
    }

    private func scan(_ file: SourceFile) {
        guard let data = try? Data(contentsOf: file.url, options: .mappedIfSafe),
              let content = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { return }

        // Presence probes (cheap substring checks).
        var foundProbes: [String] = []
        for p in probes where content.contains(p) { foundProbes.append(p) }

        var localHits: [(CodeRule, [RuleHit])] = []
        var lines: [Substring]? = nil
        for rule in rules where rule.kinds.contains(file.kind) {
            if file.isThirdParty && !(includeThirdParty || rule.includeThirdParty) { continue }
            guard rule.prefilter.isEmpty || rule.prefilter.contains(where: { content.contains($0) }) else { continue }
            if lines == nil { lines = content.split(separator: "\n", omittingEmptySubsequences: false) }
            let ls = lines!
            var ruleHits: [RuleHit] = []
            switch rule.matcher {
            case let .line(re, exclude):
                for (i, line) in ls.enumerated() {
                    let s = String(line)
                    guard re.matches(s) else { continue }
                    if let exclude, exclude.matches(s) { continue }
                    ruleHits.append(RuleHit(line: i + 1, snippet: s))
                }
            case let .file(fn):
                ruleHits = fn(content, ls)
            }
            if !ruleHits.isEmpty { localHits.append((rule, ruleHits)) }
        }

        guard !foundProbes.isEmpty || !localHits.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        for p in foundProbes {
            present.insert(p)
            if !file.isThirdParty { presentFirstParty.insert(p) }
        }
        for (rule, ruleHits) in localHits {
            var entry = hits[rule.id] ?? (evidence: [], count: 0, thirdPartyOnly: true)
            entry.count += ruleHits.count
            if !file.isThirdParty { entry.thirdPartyOnly = false }
            for h in ruleHits where entry.evidence.count < maxEvidence {
                var snippet = h.snippet.trimmingCharacters(in: .whitespaces)
                if snippet.count > 240 { snippet = String(snippet.prefix(240)) + "…" }
                if rule.masksSecrets { snippet = Self.maskQuotedSecrets(snippet) }
                entry.evidence.append(Evidence(file: file.relativePath, line: h.line, snippet: snippet))
            }
            hits[rule.id] = entry
        }
    }

    private static let quoted = NSRegularExpression.rx("\"([^\"]{9,})\"|>([^<]{9,})<")

    /// Masks string literals so reports never contain full secrets.
    static func maskQuotedSecrets(_ s: String) -> String {
        var out = s
        let ns = s as NSString
        for m in quoted.matches(in: s, range: NSRange(location: 0, length: ns.length)).reversed() {
            for g in 1...2 where m.range(at: g).location != NSNotFound {
                let value = ns.substring(with: m.range(at: g))
                // Leave identifiers / prose alone; mask values that look like key material.
                guard value.count >= 12, value.contains(where: \.isNumber), !value.contains(" ") else { continue }
                if let r = Range(m.range(at: g), in: out) { out.replaceSubrange(r, with: SecretMasker.mask(value)) }
            }
        }
        return out
    }
}
