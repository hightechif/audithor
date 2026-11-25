import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @AppStorage(PrefKey.cveMode) private var cveMode = CVEMode.off.rawValue
    @AppStorage(PrefKey.runJadx) private var runJadx = true
    @AppStorage(PrefKey.scanThirdParty) private var scanThirdParty = false
    @AppStorage(PrefKey.keepWorkspace) private var keepWorkspace = false
    @AppStorage(PrefKey.maxEvidence) private var maxEvidence = 25
    @AppStorage(PrefKey.acceptedNotice) private var acceptedNotice = false
    @State private var confirmClear = false

    var body: some View {
        TabView {
            Form {
                Toggle("Decompile DEX with jadx", isOn: $runJadx)
                Text("Enables source-level checks. Without it, code checks run against smali and are less precise.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Report issues inside third-party library code", isOn: $scanThirdParty)
                Text("Off by default to keep the focus on code the app owner controls. TLS-validation checks always include libraries.")
                    .font(.caption).foregroundStyle(.secondary)
                Stepper("Evidence items per finding: \(maxEvidence)", value: $maxEvidence, in: 5...200, step: 5)
                Toggle("Keep decompiled workspace after scan", isOn: $keepWorkspace)
                Text("Stored in ~/Library/Caches/AudiThor/workspaces. Useful for manual review of evidence.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(20)
            .tabItem { Label("Analysis", systemImage: "gearshape") }

            Form {
                Picker("CVE matching", selection: $cveMode) {
                    ForEach(CVEMode.allCases) { Text($0.title).tag($0.rawValue) }
                }
                .pickerStyle(.radioGroup)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Off by default. “Local database” matches detected library versions against the CVE list bundled with the app — no network access.")
                    Text("“OSV.dev online lookup” is the only network feature in AudiThor. When enabled, it sends **only** Maven library coordinates and versions (e.g. com.squareup.okhttp3:okhttp 4.9.0) to api.osv.dev. The APK, its hash, package name, and findings are never sent.")
                }
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)
            .tabItem { Label("Vulnerabilities", systemImage: "network.badge.shield.half.filled") }

            Form {
                Button("Clear scan history…", role: .destructive) { confirmClear = true }
                Button("Show authorized-use notice again") { acceptedNotice = false }
            }
            .padding(20)
            .tabItem { Label("Data", systemImage: "externaldrive") }
            .confirmationDialog("Delete all saved scans?", isPresented: $confirmClear) {
                Button("Delete All", role: .destructive) {
                    try? model.store.deleteAll()
                    model.reloadHistory()
                    model.selection = .newScan
                }
            } message: {
                Text("This permanently removes every scan from the local history database. Exported reports are not affected.")
            }
        }
        .frame(width: 560, height: 360)
    }
}

struct AuthorizedUseView: View {
    var onAccept: () -> Void
    @State private var confirmed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.shield").font(.system(size: 36)).foregroundStyle(Color.accentColor)
                Text("Authorized Use Only").font(.title2.weight(.bold))
            }
            Text("AudiThor performs static security analysis of Android applications. Use it only on apps you own or that you have explicit, written permission to assess.")
            VStack(alignment: .leading, spacing: 6) {
                Label("Analysis is fully local. The input APK is read-only and never modified, repackaged or re-signed.", systemImage: "lock.laptopcomputer")
                Label("No network access, except the optional CVE lookup you can enable in Settings.", systemImage: "network.slash")
                Label("Decompiling third-party apps may be restricted by licence terms or law in your jurisdiction.", systemImage: "building.columns")
                Label("Findings are indicators, not proof. Validate them before reporting.", systemImage: "magnifyingglass")
            }
            .font(.callout)
            Toggle("I confirm I am authorized to analyse the apps I load into AudiThor.", isOn: $confirmed)
            HStack {
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
                Button("Continue", action: onAccept)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!confirmed)
            }
        }
        .padding(28)
        .frame(width: 520)
    }
}
