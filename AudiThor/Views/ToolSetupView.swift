import SwiftUI

struct ToolSetupView: View {
    @EnvironmentObject var model: AppModel

    private var brewInstalled: Bool {
        FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/brew")
            || FileManager.default.isExecutableFile(atPath: "/usr/local/bin/brew")
    }

    private var installScript: String {
        guard let tools = model.tools else { return "" }
        var cmds: [String] = []
        let missing = ExternalTool.allCases.filter { !tools.has($0) }
        if missing.contains(.java) || missing.contains(.keytool) { cmds.append("brew install --cask temurin") }
        let formulae = missing.filter { $0 == .apktool || $0 == .jadx }.map(\.rawValue)
        if !formulae.isEmpty { cmds.append("brew install \(formulae.joined(separator: " "))") }
        if missing.contains(.aapt2) || missing.contains(.apksigner) {
            cmds.append("brew install --cask android-commandlinetools")
            cmds.append("sdkmanager \"build-tools;35.0.0\"")
        }
        return cmds.joined(separator: "\n")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Analysis Tools").font(.title2.weight(.semibold))
                        Text("AudiThor orchestrates proven open-source tools. It never downloads binaries on its own — install them with Homebrew, then re-check.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        Task { await model.refreshTools() }
                    } label: {
                        if model.isDetectingTools { ProgressView().controlSize(.small) } else { Label("Re-check", systemImage: "arrow.clockwise") }
                    }
                    .disabled(model.isDetectingTools)
                }

                if !brewInstalled {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            Label("Homebrew not found", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                            Text("Install Homebrew first by following the instructions at brew.sh, then run the commands below in Terminal.")
                                .font(.callout)
                            Link("Open brew.sh", destination: URL(string: "https://brew.sh")!)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                if let tools = model.tools {
                    VStack(spacing: 0) {
                        ForEach(ExternalTool.allCases) { tool in
                            ToolRow(status: tools.statuses[tool] ?? ToolStatus(tool: tool))
                            Divider()
                        }
                    }
                    .background(RoundedRectangle(cornerRadius: 10).fill(Color.secondary.opacity(0.06)))

                    if !installScript.isEmpty {
                        GroupBox("Install missing tools (run in Terminal)") {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(installScript)
                                    .font(.system(.body, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(10)
                                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.black.opacity(0.06)))
                                HStack {
                                    CopyButton(text: installScript, label: "Copy commands")
                                    Spacer()
                                    Text("`sdkmanager` is installed by android-commandlinetools; accept the SDK licences when prompted.")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    } else {
                        Label("All tools are installed.", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    }

                    GroupBox("Search paths") {
                        Text(tools.searchPaths.joined(separator: "\n"))
                            .font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } else {
                    ProgressView("Detecting tools…")
                }
            }
            .padding(24)
            .frame(maxWidth: 820, alignment: .leading)
        }
        .navigationTitle("Tool Setup")
    }
}

extension ToolStatus {
    init(tool: ExternalTool) { self.init(tool: tool, path: nil, version: nil) }
}

struct ToolRow: View {
    let status: ToolStatus

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: status.isAvailable ? "checkmark.circle.fill" : (status.tool.isRequired ? "xmark.octagon.fill" : "minus.circle"))
                .foregroundStyle(status.isAvailable ? .green : (status.tool.isRequired ? .red : .orange))
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(status.tool.displayName).bold()
                    Text(status.tool.isRequired ? "required" : "optional")
                        .font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    if let v = status.version { Text(v).font(.caption.monospaced()).foregroundStyle(.secondary) }
                }
                Text(status.tool.purpose).font(.callout).foregroundStyle(.secondary)
                if let p = status.path {
                    Text(p.path).font(.caption.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
                } else {
                    Text(status.tool.installHint).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            Spacer()
        }
        .padding(12)
    }
}
