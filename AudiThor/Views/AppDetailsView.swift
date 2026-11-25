import SwiftUI

struct AppDetailsView: View {
    let scan: ScanResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox("Signature") {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 14) {
                            ForEach(scan.signature.schemes.keys.sorted(), id: \.self) { k in
                                let on = scan.signature.schemes[k] ?? false
                                Label(k, systemImage: on ? "checkmark.seal.fill" : "xmark.seal")
                                    .foregroundStyle(on ? .green : .secondary)
                            }
                            Spacer()
                            if let v = scan.signature.verified {
                                Text(v ? "Verified by apksigner" : "Verification FAILED")
                                    .foregroundStyle(v ? Color.secondary : Color.red)
                            } else {
                                Text("Not cryptographically verified (\(scan.signature.source))").foregroundStyle(.secondary)
                            }
                        }
                        ForEach(Array(scan.signature.certificates.enumerated()), id: \.offset) { _, c in
                            Divider()
                            kv("Subject", c.subject)
                            if let i = c.issuer, i != c.subject { kv("Issuer", i) }
                            if let a = c.signatureAlgorithm { kv("Signature alg.", a) }
                            kv("Key", "\(c.keyAlgorithm ?? "?") \(c.keySize.map { "\($0)-bit" } ?? "")")
                            if let nb = c.notBefore, let na = c.notAfter {
                                kv("Validity", "\(nb.formatted(date: .abbreviated, time: .omitted)) → \(na.formatted(date: .abbreviated, time: .omitted))")
                            }
                            if let s = c.sha256 { kv("SHA-256", s, mono: true) }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
                }

                GroupBox("Permissions (\(scan.app.permissions.count))") {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(scan.app.permissions, id: \.self) { p in
                            let short = p.components(separatedBy: ".").last ?? p
                            HStack {
                                Text(p).font(.callout.monospaced()).textSelection(.enabled)
                                if ManifestChecks.highRiskPermissions.contains(short) {
                                    Text("high-risk").font(.caption2.bold()).foregroundStyle(.red)
                                } else if ManifestChecks.dangerousPermissions.contains(short) {
                                    Text("dangerous").font(.caption2.bold()).foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
                }

                GroupBox("Components (\(scan.app.components.count), \(scan.app.components.filter(\.exported).count) exported)") {
                    Table(scan.app.components.sorted { ($0.exported ? 0 : 1, $0.name) < ($1.exported ? 0 : 1, $1.name) }) {
                        TableColumn("Type") { Text($0.kind.rawValue) }.width(90)
                        TableColumn("Name") { Text($0.name).font(.callout.monospaced()).textSelection(.enabled) }
                        TableColumn("Exported") { c in
                            Text(c.exported ? (c.exportedExplicit ? "yes" : "yes (implicit)") : "no")
                                .foregroundStyle(c.exported && c.permission == nil ? .orange : .primary)
                        }.width(110)
                        TableColumn("Permission") { Text($0.permission ?? "—").font(.caption.monospaced()) }
                    }
                    .frame(minHeight: 220)
                }

                GroupBox("Third-party SDKs (\(scan.libraries.count))") {
                    Table(scan.libraries) {
                        TableColumn("Name", value: \.displayName)
                        TableColumn("Coordinate") { Text($0.coordinate).font(.caption.monospaced()).textSelection(.enabled) }
                        TableColumn("Version") { Text($0.version ?? "—") }.width(90)
                        TableColumn("Detected via") { Text($0.source).font(.caption).foregroundStyle(.secondary) }
                    }
                    .frame(minHeight: 220)
                }
            }
            .padding(20)
        }
    }

    private func kv(_ k: String, _ v: String, mono: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(k).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(v).font(mono ? .caption.monospaced() : .callout).textSelection(.enabled)
        }
    }
}

struct ScanNotesView: View {
    let scan: ScanResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("Scan") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Duration: \(String(format: "%.1f", scan.durationSeconds)) s")
                        Text("Input: \(scan.input.fileName) (\(scan.input.containerType))")
                        if !scan.input.bundledAPKs.isEmpty {
                            Text("Bundle contents: \(scan.input.bundledAPKs.joined(separator: ", "))")
                        }
                        Text("CVE matching: \(CVEMode(rawValue: scan.cveMode)?.title ?? scan.cveMode)")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                GroupBox("Warnings & notes") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(scan.warnings, id: \.self) { w in
                            Label(w, systemImage: "info.circle").textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                GroupBox("Tool versions") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(scan.tools, id: \.name) { t in
                            Text("\(t.name)  \(t.version ?? "?")  —  \(t.path ?? "")").font(.caption.monospaced())
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                if let raw = scan.signature.rawOutput {
                    GroupBox("apksigner output") {
                        Text(raw).font(.caption.monospaced()).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(20)
        }
    }
}
