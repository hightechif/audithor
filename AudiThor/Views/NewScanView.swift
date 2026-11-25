import SwiftUI

struct NewScanView: View {
    @EnvironmentObject var model: AppModel
    @State private var isTargeted = false

    var body: some View {
        VStack(spacing: 20) {
            if let tools = model.tools, !tools.missingRequired.isEmpty {
                MissingToolsBanner(missing: tools.missingRequired)
            }

            ZStack {
                RoundedRectangle(cornerRadius: 18)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    .foregroundStyle(isTargeted ? Color.accentColor : Color.secondary.opacity(0.5))
                    .background(RoundedRectangle(cornerRadius: 18).fill(isTargeted ? Color.accentColor.opacity(0.08) : Color.clear))
                VStack(spacing: 14) {
                    Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                        .font(.system(size: 56, weight: .light))
                        .foregroundStyle(Color.accentColor)
                    Text("Drop an APK to audit").font(.title2.weight(.semibold))
                    Text(".apk · .xapk · .apks — the file is only read, never modified")
                        .foregroundStyle(.secondary)
                    Button("Choose File…") { model.chooseAndScan() }
                        .keyboardShortcut("o")
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .disabled(model.tools == nil)
                    if model.tools == nil {
                        ProgressView("Detecting analysis tools…").controlSize(.small)
                    }
                }
                .padding(40)
            }
            .frame(maxWidth: 640, maxHeight: 360)
            .dropDestination(for: URL.self) { urls, _ in
                guard let url = urls.first else { return false }
                model.startScan(url)
                return true
            } isTargeted: { isTargeted = $0 }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Drop zone for Android packages")

            VStack(alignment: .leading, spacing: 6) {
                Text("What gets checked").font(.headline)
                FlowLayout(spacing: 6) {
                    ForEach(MASVSCategory.allCases.filter { $0 != .auth }) { c in
                        Text(c.rawValue).font(.caption.monospaced())
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Capsule().fill(Color.secondary.opacity(0.12)))
                    }
                }
                Text("Manifest & IPC exposure, network security config, TLS validation, data storage, secrets, cryptography, WebViews, logging, signing, and SDK inventory. All analysis runs locally.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .frame(maxWidth: 640, alignment: .leading)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("New Scan")
    }
}

struct MissingToolsBanner: View {
    @EnvironmentObject var model: AppModel
    let missing: [ExternalTool]

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.title2)
            VStack(alignment: .leading) {
                Text("Required tools missing: \(missing.map(\.displayName).joined(separator: ", "))").bold()
                Text("AudiThor needs these to decode APKs. Nothing is downloaded automatically.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Open Tool Setup") { model.selection = .tools }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color.orange.opacity(0.12)))
        .frame(maxWidth: 640)
    }
}
