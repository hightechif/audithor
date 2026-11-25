import SwiftUI

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(PrefKey.acceptedNotice) private var acceptedNotice = false

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 360)
        } detail: {
            detail
        }
        .sheet(isPresented: .constant(!acceptedNotice)) {
            AuthorizedUseView { acceptedNotice = true }
                .interactiveDismissDisabled()
        }
        .alert("AudiThor", isPresented: Binding(get: { model.errorMessage != nil },
                                                set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    @ViewBuilder private var detail: some View {
        switch model.selection ?? .newScan {
        case .newScan:
            if model.run != nil { ScanProgressView() } else { NewScanView() }
        case .compare:
            DiffView()
        case .tools:
            ToolSetupView()
        case .scan(let id):
            if let scan = model.scan(id) {
                ReportView(scan: scan).id(id)
            } else {
                ContentUnavailable(title: "Scan not found", systemImage: "questionmark.folder",
                                   message: "The scan may have been deleted.")
            }
        }
    }
}

struct SidebarView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        List(selection: $model.selection) {
            Section {
                Label(model.run == nil ? "New Scan" : "Scanning…", systemImage: model.run == nil ? "plus.viewfinder" : "hourglass")
                    .tag(SidebarItem.newScan)
                Label("Compare Scans", systemImage: "arrow.left.arrow.right").tag(SidebarItem.compare)
                HStack {
                    Label("Tool Setup", systemImage: "wrench.and.screwdriver")
                    Spacer()
                    if let tools = model.tools, !tools.missingRequired.isEmpty {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                }
                .tag(SidebarItem.tools)
            }
            Section("History") {
                if model.history.isEmpty {
                    Text("No scans yet").foregroundStyle(.secondary)
                }
                ForEach(model.history) { s in
                    HistoryRow(summary: s)
                        .tag(SidebarItem.scan(s.id))
                        .contextMenu {
                            Button("Delete Scan", role: .destructive) { model.delete(s.id) }
                        }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            if let w = model.storeWarning {
                Text(w).font(.caption).foregroundStyle(.orange).padding(8)
            }
        }
    }
}

struct HistoryRow: View {
    let summary: ScanSummary

    var body: some View {
        HStack(spacing: 8) {
            RiskBadge(score: summary.riskScore, compact: true)
            VStack(alignment: .leading, spacing: 1) {
                Text(summary.appLabel ?? summary.packageName).lineLimit(1)
                Text("\(summary.versionName ?? "?") · \(summary.startedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}

/// `ContentUnavailableView` is macOS 14+; this is a 13-compatible equivalent.
struct ContentUnavailable: View {
    var title: String
    var systemImage: String
    var message: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage).font(.system(size: 40)).foregroundStyle(.secondary)
            Text(title).font(.title3.weight(.semibold))
            Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
