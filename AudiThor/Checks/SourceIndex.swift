import Foundation

enum SourceKind: String, Sendable {
    case java, smali, xml, asset
}

struct SourceFile: Sendable {
    let url: URL
    let relativePath: String
    let kind: SourceKind
    /// Package-style path (`com/foo/Bar.java`) for code files.
    let packagePath: String?
    let isThirdParty: Bool
}

/// Inventory of text files produced by apktool/jadx that the rule engine scans.
struct SourceIndex: Sendable {
    let files: [SourceFile]
    let hasJavaSources: Bool

    var javaCount: Int { files.filter { $0.kind == .java }.count }
    var smaliCount: Int { files.filter { $0.kind == .smali }.count }

    /// Well-known library namespaces. Findings inside them are excluded by default
    /// (configurable) because the app owner usually can't fix them directly.
    static let thirdPartyPrefixes: [String] = [
        "android/", "androidx/", "kotlin/", "kotlinx/", "com/google/", "com/android/", "com/facebook/",
        "com/squareup/", "okhttp3/", "okio/", "retrofit2/", "io/reactivex/", "rx/", "org/jetbrains/",
        "org/intellij/", "com/bumptech/", "dagger/", "javax/", "org/apache/", "com/fasterxml/", "org/json/",
        "io/grpc/", "com/crashlytics/", "io/fabric/", "com/airbnb/", "org/bouncycastle/", "io/sentry/",
        "com/appsflyer/", "com/adjust/", "com/onesignal/", "org/greenrobot/", "com/jakewharton/",
        "io/flutter/", "j$/", "org/slf4j/", "ch/qos/", "com/amplitude/", "com/mixpanel/", "com/braze/",
        "com/unity3d/", "com/applovin/", "com/ironsource/", "net/sqlcipher/", "org/conscrypt/",
        "io/realm/", "com/microsoft/", "com/amazon/", "com/amazonaws/", "org/chromium/", "com/tencent/",
        "com/huawei/", "io/branch/", "com/stripe/", "com/paypal/", "org/reactivestreams/", "io/ktor/",
        "com/sun/", "sun/", "java/", "org/xmlpull/", "org/kxml2/", "org/w3c/", "org/xml/",
    ]

    static let assetExtensions: Set<String> = [
        "json", "xml", "txt", "properties", "js", "html", "htm", "yml", "yaml", "cfg", "conf", "ini",
        "env", "plist", "config", "pem", "crt", "key",
    ]

    static let maxFileSize = 2 * 1024 * 1024

    static func build(workspace: Workspace, appPackage: String) -> SourceIndex {
        let fm = FileManager.default
        let appPath = appPackage.replacingOccurrences(of: ".", with: "/") + "/"
        var files: [SourceFile] = []

        func isThirdParty(_ pkgPath: String) -> Bool {
            if pkgPath.hasPrefix(appPath) { return false }
            return thirdPartyPrefixes.contains { pkgPath.hasPrefix($0) }
        }

        func walk(_ dir: URL, _ visit: (URL, Int) -> Void) {
            guard let e = fm.enumerator(at: dir, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                                        options: [.skipsHiddenFiles]) else { return }
            for case let url as URL in e {
                let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard v?.isRegularFile == true else { continue }
                visit(url, v?.fileSize ?? 0)
            }
        }

        // 1. Java sources from jadx.
        let jadxSources = workspace.jadxDir.appendingPathComponent("sources")
        var hasJava = false
        if fm.fileExists(atPath: jadxSources.path) {
            walk(jadxSources) { url, size in
                guard url.pathExtension == "java", size <= maxFileSize else { return }
                let rel = workspace.relativePath(url)
                let pkg = String(rel.dropFirst("jadx/sources/".count))
                files.append(SourceFile(url: url, relativePath: rel, kind: .java, packagePath: pkg,
                                        isThirdParty: isThirdParty(pkg)))
                hasJava = true
            }
        }

        // 2. apktool output: smali (only when jadx is unavailable), resources and assets.
        if let top = try? fm.contentsOfDirectory(at: workspace.apktoolDir, includingPropertiesForKeys: nil) {
            for dir in top {
                let name = dir.lastPathComponent
                if name.hasPrefix("smali") {
                    guard !hasJava else { continue }
                    walk(dir) { url, size in
                        guard url.pathExtension == "smali", size <= maxFileSize else { return }
                        let rel = workspace.relativePath(url)
                        let pkg = url.path.replacingOccurrences(of: dir.path + "/", with: "")
                        files.append(SourceFile(url: url, relativePath: rel, kind: .smali, packagePath: pkg,
                                                isThirdParty: isThirdParty(pkg)))
                    }
                } else if name == "res" {
                    walk(dir) { url, size in
                        let rel = workspace.relativePath(url)
                        guard url.pathExtension == "xml", size <= maxFileSize,
                              rel.contains("/values") || rel.contains("/xml/") || rel.contains("/raw/") else { return }
                        files.append(SourceFile(url: url, relativePath: rel, kind: .xml, packagePath: nil,
                                                isThirdParty: false))
                    }
                } else if name == "assets" {
                    walk(dir) { url, size in
                        guard size <= maxFileSize, assetExtensions.contains(url.pathExtension.lowercased()) else { return }
                        files.append(SourceFile(url: url, relativePath: workspace.relativePath(url), kind: .asset,
                                                packagePath: nil, isThirdParty: false))
                    }
                }
            }
        }
        return SourceIndex(files: files, hasJavaSources: hasJava)
    }
}
