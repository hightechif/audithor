import Foundation

/// Headless mode for CI pipelines:
///
///     AudiThor.app/Contents/MacOS/AudiThor --scan app.apk --out report.json \
///         [--format json|html|pdf] [--fail-on high] [--cve off|local|online] [--no-jadx] [--save]
///
/// Exit codes: 0 = OK, 1 = error, 2 = findings at or above `--fail-on` severity.
enum HeadlessCLI {
    static func runIfRequested() {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--scan"), i + 1 < args.count else { return }

        func value(_ flag: String) -> String? {
            guard let j = args.firstIndex(of: flag), j + 1 < args.count else { return nil }
            return args[j + 1]
        }
        let input = URL(fileURLWithPath: args[i + 1])
        let out = value("--out").map { URL(fileURLWithPath: $0) }
        let format = value("--format") ?? (["html", "pdf"].contains(out?.pathExtension ?? "") ? out!.pathExtension : "json")
        let failOn = value("--fail-on").flatMap(Severity.init(rawValue:))
        var options = ScanOptions()
        options.cveMode = value("--cve").flatMap(CVEMode.init(rawValue:)) ?? .off
        options.runJadx = !args.contains("--no-jadx")

        final class State: @unchecked Sendable { var exitCode: Int32 = 0; var done = false } // touched on main only, or before `done`
        let state = State()
        Task.detached {
            let tools = await ToolLocator.detect()
            let pipeline = AnalysisPipeline(tools: tools, options: options) { p in
                FileHandle.standardError.write(Data("[\(Int(p.fraction * 100))%] \(p.message)\n".utf8))
            }
            do {
                let result = try await pipeline.run(input: input)
                let data: Data
                switch format {
                case "html": data = Data(ReportExporter.html(result).utf8)
                case "pdf": data = try await MainActor.run { try ReportExporter.pdf(result) }
                default: data = try ReportExporter.json(result)
                }
                if args.contains("--save") { try ScanStore().save(result) } // also add to the app's history
                if let out { try data.write(to: out, options: .atomic) } else { FileHandle.standardOutput.write(data) }
                let c = result.counts
                FileHandle.standardError.write(Data(
                    "Risk \(result.riskScore)/100 — critical \(c[.critical] ?? 0), high \(c[.high] ?? 0), medium \(c[.medium] ?? 0), low \(c[.low] ?? 0), info \(c[.info] ?? 0)\n".utf8))
                if let failOn, result.findings.contains(where: { $0.severity.rank <= failOn.rank }) { state.exitCode = 2 }
            } catch {
                FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
                state.exitCode = 1
            }
            await MainActor.run { state.done = true }
        }
        // Spin the main run loop (rather than blocking it) so PDF rendering can use AppKit on the main thread.
        while !state.done { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        exit(state.exitCode)
    }
}
