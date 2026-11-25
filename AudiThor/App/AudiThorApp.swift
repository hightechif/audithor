import SwiftUI

@main
struct AudiThorApp: App {
    @StateObject private var model = AppModel()

    init() {
        // `AudiThor --scan app.apk --out report.json` runs headless for CI and exits.
        HeadlessCLI.runIfRequested()
    }

    var body: some Scene {
        WindowGroup("AudiThor") {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 1000, minHeight: 640)
        }
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open APK…") { model.chooseAndScan() }
                    .keyboardShortcut("o")
                    .disabled(model.run != nil)
            }
            CommandGroup(after: .newItem) {
                Button("Compare Scans") { model.selection = .compare }
                    .keyboardShortcut("d", modifiers: [.command, .shift])
            }
        }

        Settings {
            SettingsView()
                .environmentObject(model)
        }
    }
}
