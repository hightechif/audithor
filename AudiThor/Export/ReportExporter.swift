import Foundation
import AppKit
import CoreText

enum ExportFormat: String, CaseIterable, Identifiable {
    case pdf, html, json
    var id: String { rawValue }
    var title: String { rawValue.uppercased() }
    var fileExtension: String { rawValue }
}

enum ReportExporter {

    // MARK: JSON (machine-readable, for CI)

    static func json(_ scan: ScanResult) throws -> Data {
        struct Envelope: Encodable {
            let tool = "AudiThor"
            let format = "audithor-report"
            let scan: ScanResult
            let summary: Summary
            struct Summary: Encodable {
                let riskScore: Int
                let riskLabel: String
                let counts: [String: Int]
                let masvsCategories: [String: Int]
            }
        }
        var counts: [String: Int] = [:]
        for s in Severity.allCases { counts[s.rawValue] = scan.counts[s] ?? 0 }
        var cats: [String: Int] = [:]
        for f in scan.findings { cats[f.category.rawValue, default: 0] += 1 }
        let env = Envelope(scan: ScanResult(
            id: scan.id, startedAt: scan.startedAt, durationSeconds: scan.durationSeconds, input: scan.input,
            app: scan.app, signature: scan.signature, libraries: scan.libraries, findings: scan.sortedFindings,
            tools: scan.tools, warnings: scan.warnings, cveMode: scan.cveMode, riskScore: scan.riskScore),
            summary: .init(riskScore: scan.riskScore, riskLabel: ScanResult.riskLabel(for: scan.riskScore),
                           counts: counts, masvsCategories: cats))
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        enc.dateEncodingStrategy = .iso8601
        return try enc.encode(env)
    }

    // MARK: HTML (self-contained, no external resources)

    static func html(_ scan: ScanResult, forPrint: Bool = false) -> String {
        func e(_ s: String?) -> String {
            (s ?? "").replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
        }
        let df = DateFormatter(); df.dateStyle = .medium; df.timeStyle = .short
        let counts = scan.counts
        let sevColor: [Severity: String] = [.critical: "#8e1b1b", .high: "#d1452f", .medium: "#d98a00", .low: "#3a7bd5", .info: "#6b7280"]

        var tiles = ""
        for s in Severity.allCases {
            tiles += "<td class=\"tile\" style=\"border-top:4px solid \(sevColor[s]!)\"><span class=\"n\">\(counts[s] ?? 0)</span><br><span class=\"l\">\(s.title)</span></td>"
        }

        var rows = ""
        for (i, f) in scan.sortedFindings.enumerated() {
            var ev = ""
            for x in f.evidence {
                ev += "<div class=\"ev\"><div class=\"loc\">\(e(x.locationLabel))</div>"
                if let s = x.snippet, !s.isEmpty { ev += "<pre>\(e(s))</pre>" }
                ev += "</div>"
            }
            if f.occurrenceCount > f.evidence.count {
                ev += "<div class=\"more\">… \(f.occurrenceCount - f.evidence.count) more occurrence(s) not shown</div>"
            }
            let refs = [f.masvsControl, f.mastgReference, f.cwe].compactMap { $0 }.map(e).joined(separator: " · ")
            rows += """
            <section class="finding" id="f\(i)">
              <h3><span class="sev" style="background:\(sevColor[f.severity]!)">\(f.severity.title)</span> \(e(f.title))</h3>
              <div class="refs">\(refs)</div>
              <p>\(e(f.description).replacingOccurrences(of: "\n", with: "<br>"))</p>
              <h4>Evidence</h4>\(ev)
              <h4>Remediation</h4><p>\(e(f.remediation))</p>
            </section>
            """
        }

        var libs = ""
        for l in scan.libraries {
            libs += "<tr><td>\(e(l.displayName))</td><td><code>\(e(l.coordinate))</code></td><td>\(e(l.version ?? "—"))</td><td>\(e(l.source))</td></tr>"
        }
        var certs = ""
        for c in scan.signature.certificates {
            let validity = [c.notBefore, c.notAfter].compactMap { $0 }.map { df.string(from: $0) }.joined(separator: " → ")
            certs += "<tr><td>\(e(c.subject))</td><td>\(e(c.signatureAlgorithm ?? "—"))</td><td>\(e(c.keyAlgorithm ?? "")) \(c.keySize.map(String.init) ?? "")</td><td>\(e(validity))</td></tr>"
        }
        let schemes = scan.signature.schemes.keys.sorted().map { "\($0): \(scan.signature.schemes[$0]! ? "✓" : "✗")" }.joined(separator: "  ")
        // AppKit's HTML importer (used for PDF) ignores grid/flex and Core Text skips text tables,
        // so the print variant uses plain inline lines.
        let metaRows: [(String, String)] = [
            ("Package", "<code>\(e(scan.app.packageName))</code>"),
            ("Version", "\(e(scan.app.versionName ?? "—")) (\(e(scan.app.versionCode ?? "—")))"),
            ("SDK", "min \(scan.app.minSdk.map(String.init) ?? "—") · target \(scan.app.targetSdk.map(String.init) ?? "—")"),
            ("File", "\(e(scan.input.fileName)) · \(ByteCountFormatter.string(fromByteCount: scan.input.fileSize, countStyle: .file))"),
            ("SHA-256", "<code>\(e(scan.input.sha256))</code>"),
            ("Signature", "\(e(schemes))")
        ]
        let metaBlock = forPrint
            ? "<p>" + metaRows.map { "<span class=\"muted\">\($0.0):</span> \($0.1)" }.joined(separator: "<br>") + "</p>"
            : "<table class=\"meta\">" + metaRows.map { "<tr><td class=\"k\">\($0.0)</td><td>\($0.1)</td></tr>" }.joined() + "</table>"
        let tilesBlock = forPrint
            ? "<p>" + Severity.allCases.map { "<b style=\"color:\(sevColor[$0]!)\">\($0.title) \(counts[$0] ?? 0)</b>" }.joined(separator: " &nbsp;·&nbsp; ") + "</p>"
            : "<table class=\"tiles\"><tr>\(tiles)</tr></table>"
        let warnings = scan.warnings.map { "<li>\(e($0))</li>" }.joined()

        return """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>AudiThor report — \(e(scan.displayName))</title>
        <style>
        :root { --fg:#111827; --muted:#6b7280; --bg:#ffffff; --card:#f9fafb; --border:#e5e7eb; }
        @media (prefers-color-scheme: dark) { :root { --fg:#e5e7eb; --muted:#9ca3af; --bg:#111318; --card:#1a1d24; --border:#2d313a; } }
        \(forPrint ? ":root { --fg:#111827; --muted:#6b7280; --bg:#ffffff; --card:#f9fafb; --border:#e5e7eb; }" : "")
        body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; color: var(--fg); background: var(--bg); margin: 0; padding: 32px; max-width: 1000px; margin-inline: auto; }
        h1 { margin: 0 0 4px; font-size: 26px; } h2 { margin-top: 36px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
        .muted { color: var(--muted); } code, pre { font-family: ui-monospace, Menlo, monospace; font-size: 12px; }
        .meta { margin-top: 16px; width: auto; } .meta td { border: none; padding: 2px 16px 2px 0; font-size: 13px; } .meta td.k { color: var(--muted); }
        .score { font-size: 44px; font-weight: 700; }
        .tiles { margin: 16px 0; width: auto; border-collapse: separate; border-spacing: 10px 0; }
        .tile { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; min-width: 70px; text-align: center; }
        .tile .n { font-size: 24px; font-weight: 700; } .tile .l { color: var(--muted); font-size: 12px; text-transform: uppercase; }
        .finding { border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; margin: 14px 0; background: var(--card); page-break-inside: avoid; }
        .finding h3 { margin: 0 0 4px; font-size: 16px; } .finding h4 { margin: 12px 0 4px; font-size: 13px; color: var(--muted); }
        .sev { color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 10px; vertical-align: middle; text-transform: uppercase; }
        .refs { font-size: 12px; color: var(--muted); }
        .ev { margin: 6px 0; } .loc { font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: var(--muted); }
        pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; margin: 2px 0; white-space: pre-wrap; word-break: break-all; }
        .more { font-size: 12px; color: var(--muted); }
        table { border-collapse: collapse; width: 100%; font-size: 12px; } td, th { border-bottom: 1px solid var(--border); padding: 4px 6px; text-align: left; vertical-align: top; }
        .notice { font-size: 12px; color: var(--muted); border-top: 1px solid var(--border); margin-top: 40px; padding-top: 10px; }
        </style></head><body>
        <h1>\(e(scan.displayName))</h1>
        <div class="muted">Static security analysis aligned with OWASP MASVS v2 / MASTG · generated by AudiThor · \(e(df.string(from: scan.startedAt)))</div>
        \(metaBlock)
        <h2>Summary</h2>
        <div><span class="score">\(scan.riskScore)</span><span class="muted"> / 100 risk · \(ScanResult.riskLabel(for: scan.riskScore))</span></div>
        \(tilesBlock)
        <h2>Findings (\(scan.findings.count))</h2>
        \(rows)
        <h2>Signing certificates</h2>
        <table><tr><th>Subject</th><th>Signature alg.</th><th>Key</th><th>Validity</th></tr>\(certs)</table>
        <h2>Third-party SDKs (\(scan.libraries.count))</h2>
        <table><tr><th>Name</th><th>Coordinate</th><th>Version</th><th>Detected via</th></tr>\(libs)</table>
        <h2>Scan notes</h2><ul>\(warnings)</ul>
        <div class="notice">Generated for authorized security assessment only. Static analysis may produce false positives and cannot observe runtime behaviour; validate findings before acting on them.</div>
        </body></html>
        """
    }

    // MARK: PDF (paginated, rendered with Core Text — no WebKit, works headless)

    @MainActor
    static func pdf(_ scan: ScanResult) throws -> Data {
        let html = Self.html(scan, forPrint: true)
        guard let htmlData = html.data(using: .utf8),
              let attributed = NSAttributedString(html: htmlData, options: [.characterEncoding: String.Encoding.utf8.rawValue],
                                                  documentAttributes: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }

        let pageSize = CGSize(width: 595.2, height: 841.8) // A4 in points
        let margin: CGFloat = 40
        let textRect = CGRect(x: margin, y: margin, width: pageSize.width - 2 * margin, height: pageSize.height - 2 * margin - 16)

        let data = NSMutableData()
        var mediaBox = CGRect(origin: .zero, size: pageSize)
        guard let consumer = CGDataConsumer(data: data as CFMutableData),
              let ctx = CGContext(consumer: consumer, mediaBox: &mediaBox, [
                kCGPDFContextTitle as String: "AudiThor report — \(scan.displayName)",
                kCGPDFContextCreator as String: "AudiThor",
              ] as CFDictionary) else { throw CocoaError(.fileWriteUnknown) }

        let framesetter = CTFramesetterCreateWithAttributedString(attributed as CFAttributedString)
        var location = 0
        var page = 1
        let footerAttrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 8), .foregroundColor: NSColor.gray]

        while location < attributed.length {
            ctx.beginPDFPage(nil)
            let path = CGPath(rect: textRect, transform: nil)
            let frame = CTFramesetterCreateFrame(framesetter, CFRange(location: location, length: 0), path, nil)
            CTFrameDraw(frame, ctx)
            let visible = CTFrameGetVisibleStringRange(frame)

            let footer = NSAttributedString(string: "AudiThor · \(scan.app.packageName) · SHA-256 \(scan.input.sha256.prefix(16))… · page \(page)", attributes: footerAttrs)
            let line = CTLineCreateWithAttributedString(footer)
            ctx.textPosition = CGPoint(x: margin, y: margin / 2)
            CTLineDraw(line, ctx)
            ctx.endPDFPage()

            if visible.length == 0 { break } // safety: avoid infinite loop on unrenderable content
            location += visible.length
            page += 1
        }
        ctx.closePDF()
        return data as Data
    }
}
