import Foundation

extension String {
    /// First capture group of `pattern`, or nil.
    func firstGroup(_ pattern: String, options: NSRegularExpression.Options = []) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: options),
              let m = re.firstMatch(in: self, range: NSRange(startIndex..., in: self)),
              m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: self) else { return nil }
        return String(self[r])
    }

    func allGroups(_ pattern: String, options: NSRegularExpression.Options = []) -> [String] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return [] }
        return re.matches(in: self, range: NSRange(startIndex..., in: self)).compactMap { m in
            guard m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: self) else { return nil }
            return String(self[r])
        }
    }
}

extension NSRegularExpression {
    /// Force-try constructor for pattern literals defined in code.
    static func rx(_ pattern: String, _ options: NSRegularExpression.Options = []) -> NSRegularExpression {
        // Patterns are compile-time constants; a failure here is a programming error.
        try! NSRegularExpression(pattern: pattern, options: options)
    }

    func matches(_ s: String) -> Bool {
        firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
}

enum Entropy {
    /// Shannon entropy in bits per character.
    static func shannon(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let n = Double(s.count)
        return freq.values.reduce(0) { acc, count in
            let p = Double(count) / n
            return acc - p * log2(p)
        }
    }
}

enum SecretMasker {
    /// Keeps a short prefix so the auditor can locate the value, masks the rest.
    static func mask(_ value: String) -> String {
        guard value.count > 8 else { return String(repeating: "•", count: value.count) }
        return String(value.prefix(4)) + String(repeating: "•", count: min(value.count - 4, 16))
    }
}
