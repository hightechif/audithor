import SwiftUI

struct DiffView: View {
    @EnvironmentObject var model: AppModel
    @State private var baselineID: UUID?
    @State private var comparisonID: UUID?

    var diff: ScanDiff? {
        guard let b = baselineID, let c = comparisonID, b != c,
              let bs = model.scan(b), let cs = model.scan(c) else { return nil }
        return ScanDiff(baseline: bs, comparison: cs)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                picker("Baseline", $baselineID)
                Image(systemName: "arrow.right").foregroundStyle(.secondary)
                picker("Compare to", $comparisonID)
                Button {
                    swap(&baselineID, &comparisonID)
                } label: { Image(systemName: "arrow.left.arrow.right") }
                .help("Swap")
            }
            .padding(16)
            Divider()

            if model.history.count < 2 {
                ContentUnavailable(title: "Need two scans", systemImage: "arrow.left.arrow.right",
                                   message: "Scan two versions of the same app, then compare them here.")
            } else if let diff {
                DiffContent(diff: diff)
            } else {
                ContentUnavailable(title: "Choose two different scans", systemImage: "arrow.left.arrow.right",
                                   message: "Pick a baseline (e.g. the previous release) and the scan to compare.")
            }
        }
        .navigationTitle("Compare Scans")
        .onAppear(perform: preselect)
    }

    private func preselect() {
        guard baselineID == nil, comparisonID == nil, let newest = model.history.first else { return }
        comparisonID = newest.id
        // Default baseline: the previous scan of the same package.
        baselineID = model.history.dropFirst().first(where: { $0.packageName == newest.packageName })?.id
    }

    private func picker(_ title: String, _ binding: Binding<UUID?>) -> some View {
        Picker(title, selection: binding) {
            Text("Select…").tag(UUID?.none)
            ForEach(model.history) { s in
                Text("\(s.appLabel ?? s.packageName) \(s.versionName ?? "") — \(s.startedAt.formatted(date: .numeric, time: .shortened))")
                    .tag(UUID?.some(s.id))
            }
        }
        .frame(maxWidth: 360)
    }
}

struct DiffContent: View {
    let diff: ScanDiff
    @State private var selected: Finding?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if !diff.samePackage {
                    Label("These scans are of different packages; the comparison may not be meaningful.",
                          systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                }
                HStack(spacing: 14) {
                    stat("New", diff.newFindings.count, .red)
                    stat("Resolved", diff.resolvedFindings.count, .green)
                    stat("Persisting", diff.persistingFindings.count, .secondary)
                    stat("Severity changed", diff.severityChanges.count, .orange)
                    VStack(alignment: .leading) {
                        Text("Risk score").font(.caption).foregroundStyle(.secondary)
                        HStack {
                            RiskBadge(score: diff.baseline.riskScore)
                            Image(systemName: "arrow.right")
                            RiskBadge(score: diff.comparison.riskScore)
                        }
                    }
                }

                if !diff.metadataChanges.isEmpty {
                    GroupBox("Metadata changes") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(diff.metadataChanges, id: \.field) { c in
                                HStack {
                                    Text(c.field).foregroundStyle(.secondary).frame(width: 120, alignment: .leading)
                                    Text(c.from).strikethrough().foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                    Image(systemName: "arrow.right").foregroundStyle(.secondary)
                                    Text(c.to).lineLimit(1).truncationMode(.middle)
                                }
                                .font(.callout)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                if !diff.addedPermissions.isEmpty || !diff.removedPermissions.isEmpty {
                    GroupBox("Permission changes") {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(diff.addedPermissions, id: \.self) { Text("+ \($0)").foregroundStyle(.red) }
                            ForEach(diff.removedPermissions, id: \.self) { Text("− \($0)").foregroundStyle(.green) }
                        }
                        .font(.callout.monospaced())
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                if !diff.addedLibraries.isEmpty || !diff.removedLibraries.isEmpty || !diff.changedLibraries.isEmpty {
                    GroupBox("SDK changes") {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(diff.addedLibraries) { Text("+ \($0.displayName) \($0.version ?? "")") }
                            ForEach(diff.removedLibraries) { Text("− \($0.displayName) \($0.version ?? "")").foregroundStyle(.secondary) }
                            ForEach(diff.changedLibraries, id: \.name) { c in
                                Text("~ \(c.name) \(c.from ?? "?") → \(c.to ?? "?")")
                            }
                        }
                        .font(.callout.monospaced())
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                findingGroup("New findings", diff.newFindings, tint: .red)
                if !diff.severityChanges.isEmpty {
                    GroupBox("Severity changes") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(diff.severityChanges) { c in
                                HStack {
                                    SeverityPill(severity: c.before.severity)
                                    Image(systemName: "arrow.right")
                                    SeverityPill(severity: c.after.severity)
                                    Text(c.after.title)
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                findingGroup("Resolved findings", diff.resolvedFindings, tint: .green)
                findingGroup("Persisting findings", diff.persistingFindings, tint: .secondary)
            }
            .padding(20)
        }
        .sheet(item: $selected) { f in
            VStack(spacing: 0) {
                FindingDetailView(finding: f)
                Divider()
                HStack { Spacer(); Button("Close") { selected = nil }.keyboardShortcut(.cancelAction) }.padding(10)
            }
            .frame(minWidth: 620, minHeight: 520)
        }
    }

    private func stat(_ label: String, _ n: Int, _ color: Color) -> some View {
        VStack(alignment: .leading) {
            Text("\(n)").font(.system(size: 26, weight: .bold, design: .rounded)).foregroundStyle(color)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .frame(minWidth: 80, alignment: .leading)
    }

    @ViewBuilder
    private func findingGroup(_ title: String, _ items: [Finding], tint: Color) -> some View {
        if !items.isEmpty {
            GroupBox {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(items) { f in
                        Button { selected = f } label: {
                            FindingRow(finding: f).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } label: {
                Text("\(title) (\(items.count))").foregroundStyle(tint)
            }
        }
    }
}
