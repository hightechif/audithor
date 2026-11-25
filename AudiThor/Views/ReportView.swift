import SwiftUI
import Charts

struct ReportView: View {
    @EnvironmentObject var model: AppModel
    let scan: ScanResult

    enum Tab: String, CaseIterable, Identifiable {
        case findings = "Findings", app = "App Details", notes = "Scan Notes"
        var id: String { rawValue }
    }

    @State private var tab: Tab = .findings
    @State private var severityFilter: Set<Severity> = Set(Severity.allCases)
    @State private var categoryFilter: MASVSCategory? = nil
    @State private var search = ""
    @State private var selectedID: String?

    var filtered: [Finding] {
        scan.sortedFindings.filter { f in
            severityFilter.contains(f.severity)
                && (categoryFilter == nil || f.category == categoryFilter)
                && (search.isEmpty || f.title.localizedCaseInsensitiveContains(search)
                    || f.ruleID.localizedCaseInsensitiveContains(search)
                    || f.masvsControl.localizedCaseInsensitiveContains(search)
                    || (f.cwe ?? "").localizedCaseInsensitiveContains(search)
                    || f.evidence.contains { $0.file.localizedCaseInsensitiveContains(search) })
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            ReportHeader(scan: scan)
            DashboardView(scan: scan, severityFilter: $severityFilter, categoryFilter: $categoryFilter)
            Divider()
            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 420)
            .padding(.vertical, 8)

            switch tab {
            case .findings: findingsPane
            case .app: AppDetailsView(scan: scan)
            case .notes: ScanNotesView(scan: scan)
            }
        }
        .navigationTitle(scan.displayName)
        .toolbar {
            ToolbarItem {
                Menu {
                    ForEach(ExportFormat.allCases) { f in
                        Button("Export \(f.title)…") { model.export(scan, as: f) }
                    }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .help("Export report as PDF, HTML or JSON")
            }
        }
    }

    private var findingsPane: some View {
        HSplitView {
            VStack(spacing: 0) {
                HStack {
                    TextField("Filter findings, rules, CWE, files…", text: $search)
                        .textFieldStyle(.roundedBorder)
                    if severityFilter.count != Severity.allCases.count || categoryFilter != nil || !search.isEmpty {
                        Button("Reset") {
                            severityFilter = Set(Severity.allCases); categoryFilter = nil; search = ""
                        }
                    }
                }
                .padding(8)
                List(filtered, selection: $selectedID) { f in
                    FindingRow(finding: f).tag(f.id)
                }
                .listStyle(.inset)
                .overlay {
                    if filtered.isEmpty {
                        Text(scan.findings.isEmpty ? "No findings" : "No findings match the filters")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(minWidth: 320, idealWidth: 420)

            Group {
                if let f = scan.findings.first(where: { $0.id == selectedID }) {
                    FindingDetailView(finding: f)
                } else {
                    ContentUnavailable(title: "Select a finding", systemImage: "list.bullet.rectangle",
                                       message: "Details, evidence and remediation appear here.")
                }
            }
            .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
        }
        .onAppear { if selectedID == nil { selectedID = filtered.first?.id } }
    }
}

struct ReportHeader: View {
    let scan: ScanResult

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text(scan.displayName).font(.title.weight(.semibold))
                Text(scan.app.packageName).font(.body.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                HStack(spacing: 12) {
                    Text("v\(scan.app.versionName ?? "?") (\(scan.app.versionCode ?? "?"))")
                    Text("minSdk \(scan.app.minSdk.map(String.init) ?? "?") · targetSdk \(scan.app.targetSdk.map(String.init) ?? "?")")
                    Text(ByteCountFormatter.string(fromByteCount: scan.input.fileSize, countStyle: .file))
                    Text(scan.startedAt.formatted(date: .abbreviated, time: .shortened))
                }
                .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text("SHA-256").font(.caption).foregroundStyle(.secondary)
                    Text(scan.input.sha256).font(.caption.monospaced()).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                    CopyButton(text: scan.input.sha256, label: "").labelStyle(.iconOnly).buttonStyle(.borderless)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
    }
}

struct DashboardView: View {
    let scan: ScanResult
    @Binding var severityFilter: Set<Severity>
    @Binding var categoryFilter: MASVSCategory?

    var categoryCounts: [(MASVSCategory, Severity, Int)] {
        var out: [(MASVSCategory, Severity, Int)] = []
        for c in MASVSCategory.allCases {
            for s in Severity.allCases {
                let n = scan.findings.filter { $0.category == c && $0.severity == s }.count
                if n > 0 { out.append((c, s, n)) }
            }
        }
        return out
    }

    var body: some View {
        HStack(alignment: .center, spacing: 24) {
            RiskGauge(score: scan.riskScore)
            HStack(spacing: 10) {
                ForEach(Severity.allCases) { s in
                    let n = scan.counts[s] ?? 0
                    let active = severityFilter.contains(s)
                    Button {
                        // Click: show only this severity; click again: show all.
                        severityFilter = (severityFilter == [s]) ? Set(Severity.allCases) : [s]
                    } label: {
                        VStack(spacing: 2) {
                            Text("\(n)").font(.system(size: 24, weight: .bold, design: .rounded)).monospacedDigit()
                            Text(s.title).font(.caption).foregroundStyle(.secondary)
                        }
                        .frame(width: 74, height: 62)
                        .background(RoundedRectangle(cornerRadius: 8).fill(s.color.opacity(active ? 0.16 : 0.04)))
                        .overlay(alignment: .top) {
                            RoundedRectangle(cornerRadius: 2).fill(s.color).frame(height: 3).padding(.horizontal, 8)
                        }
                    }
                    .buttonStyle(.plain)
                    .opacity(active ? 1 : 0.5)
                    .help("Show only \(s.title) findings")
                    .accessibilityLabel("\(n) \(s.title) findings")
                }
            }
            Chart {
                ForEach(Array(categoryCounts.enumerated()), id: \.offset) { _, item in
                    BarMark(x: .value("Findings", item.2), y: .value("Category", item.0.shortTitle))
                        .foregroundStyle(by: .value("Severity", item.1.title))
                }
            }
            .chartForegroundStyleScale(domain: Severity.allCases.map(\.title), range: Severity.allCases.map(\.color))
            .chartLegend(.hidden)
            .frame(minWidth: 220, maxWidth: 360, minHeight: 90, maxHeight: 120)
            .overlay(alignment: .topTrailing) {
                Menu {
                    Button("All categories") { categoryFilter = nil }
                    Divider()
                    ForEach(MASVSCategory.allCases) { c in
                        Button(c.rawValue) { categoryFilter = c }
                    }
                } label: {
                    Text(categoryFilter?.rawValue ?? "All MASVS").font(.caption)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: finding.severity.symbol).foregroundStyle(finding.severity.color)
                .frame(width: 16).padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title).lineLimit(2)
                HStack(spacing: 6) {
                    Text(finding.masvsControl)
                    if let cwe = finding.cwe { Text(cwe) }
                    if finding.occurrenceCount > 1 { Text("×\(finding.occurrenceCount)") }
                }
                .font(.caption.monospaced()).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

struct FindingDetailView: View {
    let finding: Finding

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 8) {
                    SeverityPill(severity: finding.severity)
                    Text(finding.category.rawValue).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Spacer()
                    Text(finding.ruleID).font(.caption.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
                }
                Text(finding.title).font(.title3.weight(.semibold)).textSelection(.enabled)
                Text(finding.description).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)

                section("References") {
                    VStack(alignment: .leading, spacing: 4) {
                        refRow("MASVS", finding.masvsControl, finding.category.referenceURL)
                        if let m = finding.mastgReference {
                            refRow("MASTG", m, URL(string: "https://mas.owasp.org/MASTG/tests/"))
                        }
                        if let c = finding.cwe { refRow("CWE", c, finding.cweURL) }
                    }
                }

                section("Evidence (\(finding.occurrenceCount))") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(finding.evidence.enumerated()), id: \.offset) { _, e in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Image(systemName: "doc.text").foregroundStyle(.secondary)
                                    Text(e.locationLabel).font(.caption.monospaced()).textSelection(.enabled)
                                }
                                if let s = e.snippet, !s.isEmpty {
                                    Text(s)
                                        .font(.system(.callout, design: .monospaced))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(8)
                                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.08)))
                                }
                            }
                        }
                        if finding.occurrenceCount > finding.evidence.count {
                            Text("\(finding.occurrenceCount - finding.evidence.count) more occurrence(s) not shown (limit set in Settings).")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }

                section("Remediation") {
                    Text(finding.remediation).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func section<C: View>(_ title: String, @ViewBuilder content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            content()
        }
    }

    private func refRow(_ label: String, _ value: String, _ url: URL?) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label).font(.caption.weight(.semibold)).foregroundStyle(.secondary).frame(width: 50, alignment: .leading)
            if let url { Link(value, destination: url) } else { Text(value) }
        }
    }
}
