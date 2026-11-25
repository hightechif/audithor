import SwiftUI

struct ScanProgressView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let run = model.run {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading) {
                        Text("Analysing \(run.fileName)").font(.title2.weight(.semibold))
                        Text(run.progress.message).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    Button("Cancel", role: .cancel) { model.cancelScan() }
                        .keyboardShortcut(.cancelAction)
                }
                ProgressView(value: run.progress.fraction)
                    .progressViewStyle(.linear)

                VStack(alignment: .leading, spacing: 8) {
                    ForEach(PipelineStage.allCases) { stage in
                        HStack(spacing: 10) {
                            Group {
                                if run.completedStages.contains(stage) {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                                } else if run.progress.stage == stage {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Image(systemName: "circle").foregroundStyle(.tertiary)
                                }
                            }
                            .frame(width: 18)
                            Text(stage.rawValue)
                                .foregroundStyle(run.progress.stage == stage ? .primary : .secondary)
                        }
                    }
                }

                GroupBox("Log") {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 2) {
                                ForEach(Array(run.log.enumerated()), id: \.offset) { i, line in
                                    Text(line).font(.caption.monospaced()).textSelection(.enabled).id(i)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .onChange(of: run.log.count) { n in proxy.scrollTo(n - 1, anchor: .bottom) }
                    }
                    .frame(minHeight: 120)
                }
            }
            .padding(28)
            .frame(maxWidth: 760, maxHeight: .infinity, alignment: .top)
            .navigationTitle("Scanning")
        }
    }
}
