import SwiftUI
import Combine
import AppKit
import UniformTypeIdentifiers

enum SidebarItem: Hashable {
    case newScan
    case compare
    case tools
    case scan(UUID)
}

/// Keys for user preferences (shared with @AppStorage in views).
enum PrefKey {
    static let acceptedNotice = "acceptedAuthorizedUseNotice.v1"
    static let cveMode = "cveMode"
    static let runJadx = "runJadx"
    static let scanThirdParty = "scanThirdPartyCode"
    static let keepWorkspace = "keepWorkspace"
    static let maxEvidence = "maxEvidencePerFinding"
}

@MainActor
final class AppModel: ObservableObject {
    struct RunState {
        var fileName: String
        var progress: PipelineProgress
        var completedStages: Set<PipelineStage> = []
        var log: [String] = []
        var task: Task<Void, Never>?
    }

    @Published var tools: ToolEnvironment?
    @Published var isDetectingTools = false
    @Published var history: [ScanSummary] = []
    @Published var selection: SidebarItem? = .newScan
    @Published var run: RunState?
    @Published var errorMessage: String?
    @Published private(set) var scanCache: [UUID: ScanResult] = [:]

    let store: ScanStore
    let storeWarning: String?

    init() {
        do {
            store = try ScanStore()
            storeWarning = nil
        } catch {
            // Fall back to an in-memory database so the app remains usable.
            store = try! ScanStore(inMemory: ())
            storeWarning = "Scan history could not be opened (\(error.localizedDescription)). Scans will not be saved this session."
        }
        reloadHistory()
        Task { await refreshTools() }
    }

    // MARK: Tools

    func refreshTools() async {
        isDetectingTools = true
        tools = await Task.detached(priority: .userInitiated) { await ToolLocator.detect() }.value
        isDetectingTools = false
    }

    // MARK: History

    func reloadHistory() {
        history = (try? store.summaries()) ?? []
    }

    func scan(_ id: UUID) -> ScanResult? {
        if let s = scanCache[id] { return s }
        guard let s = try? store.load(id) else { return nil }
        scanCache[id] = s
        return s
    }

    func delete(_ id: UUID) {
        try? store.delete(id)
        scanCache[id] = nil
        if selection == .scan(id) { selection = .newScan }
        reloadHistory()
    }

    // MARK: Scanning

    static let acceptedTypes: [UTType] = ["apk", "xapk", "apks", "apkm"].compactMap {
        UTType(filenameExtension: $0)
    }

    func chooseAndScan() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = Self.acceptedTypes
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose an Android package (.apk, .xapk, .apks) you are authorized to assess."
        if panel.runModal() == .OK, let url = panel.url { startScan(url) }
    }

    func options() -> ScanOptions {
        let d = UserDefaults.standard
        var o = ScanOptions()
        o.cveMode = CVEMode(rawValue: d.string(forKey: PrefKey.cveMode) ?? "") ?? .off
        o.runJadx = d.object(forKey: PrefKey.runJadx) as? Bool ?? true
        o.scanThirdPartyCode = d.bool(forKey: PrefKey.scanThirdParty)
        o.keepWorkspace = d.bool(forKey: PrefKey.keepWorkspace)
        let maxEv = d.integer(forKey: PrefKey.maxEvidence)
        o.maxEvidencePerFinding = maxEv > 0 ? maxEv : 25
        return o
    }

    func startScan(_ url: URL) {
        guard run == nil else {
            errorMessage = "A scan is already running. Cancel it before starting another."
            return
        }
        guard let tools else {
            errorMessage = "Still detecting installed tools — try again in a moment."
            return
        }
        if !tools.missingRequired.isEmpty {
            errorMessage = PipelineError.missingTools(tools.missingRequired).localizedDescription
            selection = .tools
            return
        }

        let opts = options()
        let initial = PipelineProgress(stage: .hashing, fraction: 0, message: "Starting…")
        run = RunState(fileName: url.lastPathComponent, progress: initial, log: ["Input: \(url.path)"])
        selection = .newScan

        let pipeline = AnalysisPipeline(tools: tools, options: opts) { [self] p in
            Task { @MainActor in self.apply(p) }
        }
        let task = Task.detached(priority: .userInitiated) { [self] in
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            do {
                let result = try await pipeline.run(input: url)
                await self.finish(result)
            } catch is CancellationError {
                await self.fail(nil)
            } catch {
                await self.fail(error.localizedDescription)
            }
        }
        run?.task = task
    }

    func cancelScan() {
        run?.task?.cancel()
    }

    private func apply(_ p: PipelineProgress) {
        guard var r = run else { return }
        if p.stage != r.progress.stage { r.completedStages.insert(r.progress.stage) }
        if p.message != r.progress.message { r.log.append(p.message) }
        if r.log.count > 300 { r.log.removeFirst(r.log.count - 300) }
        r.progress = p
        run = r
    }

    private func finish(_ result: ScanResult) {
        do { try store.save(result) } catch { errorMessage = "Could not save scan: \(error.localizedDescription)" }
        scanCache[result.id] = result
        run = nil
        reloadHistory()
        selection = .scan(result.id)
    }

    private func fail(_ message: String?) {
        run = nil
        if let message { errorMessage = message }
    }

    // MARK: Export

    func export(_ scan: ScanResult, as format: ExportFormat) {
        let panel = NSSavePanel()
        let base = "\(scan.app.packageName)-\(scan.app.versionName ?? "unknown")-audithor"
            .replacingOccurrences(of: "/", with: "_")
        panel.nameFieldStringValue = "\(base).\(format.fileExtension)"
        panel.allowedContentTypes = [UTType(filenameExtension: format.fileExtension) ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data: Data
            switch format {
            case .json: data = try ReportExporter.json(scan)
            case .html: data = Data(ReportExporter.html(scan).utf8)
            case .pdf: data = try ReportExporter.pdf(scan)
            }
            try data.write(to: url, options: .atomic)
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            errorMessage = "Export failed: \(error.localizedDescription)"
        }
    }
}
