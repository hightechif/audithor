import Foundation

/// Builds the third-party SDK inventory from:
///  - `META-INF/<group>_<artifact>.version` files (AndroidX, Firebase, Play Services, Kotlin…)
///  - `META-INF/maven/**/pom.properties`
///  - package namespaces present in the decompiled code
///  - bundled native libraries (`lib/<abi>/*.so`)
enum LibraryDetector {
    /// Namespace → (coordinate, display name). Used when no version metadata exists.
    static let signatures: [(path: String, coordinate: String, name: String)] = [
        ("okhttp3", "com.squareup.okhttp3:okhttp", "OkHttp 3/4"),
        ("com/squareup/okhttp", "com.squareup.okhttp:okhttp", "OkHttp 2 (legacy)"),
        ("retrofit2", "com.squareup.retrofit2:retrofit", "Retrofit"),
        ("okio", "com.squareup.okio:okio", "Okio"),
        ("com/google/gson", "com.google.code.gson:gson", "Gson"),
        ("com/fasterxml/jackson/databind", "com.fasterxml.jackson.core:jackson-databind", "Jackson Databind"),
        ("com/bumptech/glide", "com.github.bumptech.glide:glide", "Glide"),
        ("com/squareup/picasso", "com.squareup.picasso:picasso", "Picasso"),
        ("io/reactivex/rxjava3", "io.reactivex.rxjava3:rxjava", "RxJava 3"),
        ("io/reactivex", "io.reactivex.rxjava2:rxjava", "RxJava 2"),
        ("org/bouncycastle", "org.bouncycastle:bcprov", "Bouncy Castle"),
        ("org/apache/commons/text", "org.apache.commons:commons-text", "Apache Commons Text"),
        ("org/apache/http", "org.apache.httpcomponents:httpclient", "Apache HttpClient (legacy)"),
        ("com/google/protobuf", "com.google.protobuf:protobuf-javalite", "Protocol Buffers"),
        ("io/sentry", "io.sentry:sentry-android", "Sentry"),
        ("com/facebook/react", "com.facebook.react:react-android", "React Native"),
        ("io/flutter", "io.flutter:flutter_embedding", "Flutter"),
        ("com/appsflyer", "com.appsflyer:af-android-sdk", "AppsFlyer"),
        ("com/adjust/sdk", "com.adjust.sdk:adjust-android", "Adjust"),
        ("com/onesignal", "com.onesignal:OneSignal", "OneSignal"),
        ("com/facebook/FacebookSdk", "com.facebook.android:facebook-core", "Facebook SDK"),
        ("com/mixpanel", "com.mixpanel.android:mixpanel-android", "Mixpanel"),
        ("com/amplitude", "com.amplitude:android-sdk", "Amplitude"),
        ("com/braze", "com.braze:android-sdk-ui", "Braze"),
        ("io/branch", "io.branch.sdk.android:library", "Branch"),
        ("com/stripe/android", "com.stripe:stripe-android", "Stripe"),
        ("net/sqlcipher", "net.zetetic:android-database-sqlcipher", "SQLCipher"),
        ("io/realm", "io.realm:realm-android", "Realm"),
        ("com/unity3d", "com.unity3d.ads:unity-ads", "Unity"),
        ("com/applovin", "com.applovin:applovin-sdk", "AppLovin"),
        ("com/ironsource", "com.ironsource.sdk:mediationsdk", "ironSource"),
        ("com/datadog", "com.datadoghq:dd-sdk-android", "Datadog"),
        ("com/newrelic", "com.newrelic.agent.android:android-agent", "New Relic"),
    ]

    static let nativeSignatures: [(file: String, name: String)] = [
        ("libflutter.so", "Flutter engine"), ("libapp.so", "Flutter AOT app code"),
        ("libreactnativejni.so", "React Native"), ("libhermes.so", "Hermes JS engine"),
        ("libunity.so", "Unity engine"), ("libil2cpp.so", "Unity IL2CPP"),
        ("libsqlcipher.so", "SQLCipher"), ("libcrypto.so", "OpenSSL / BoringSSL (bundled)"),
        ("libssl.so", "OpenSSL / BoringSSL (bundled)"), ("libconscrypt_jni.so", "Conscrypt"),
        ("libxamarin-app.so", "Xamarin / .NET MAUI"), ("libmonosgen-2.0.so", "Mono runtime"),
        ("libcocos2dcpp.so", "Cocos2d-x"), ("libjsc.so", "JavaScriptCore"),
    ]

    static func detect(entries: [String], metaInfDir: URL, workspace: Workspace, sources: SourceIndex) -> [DetectedLibrary] {
        var libs: [String: DetectedLibrary] = [:]
        let fm = FileManager.default

        // 1. META-INF/*.version
        let meta = metaInfDir.appendingPathComponent("META-INF")
        if let files = try? fm.contentsOfDirectory(atPath: meta.path) {
            for f in files where f.hasSuffix(".version") {
                let base = String(f.dropLast(".version".count))
                guard let us = base.firstIndex(of: "_") else { continue }
                let group = String(base[..<us]), artifact = String(base[base.index(after: us)...])
                let version = (try? String(contentsOf: meta.appendingPathComponent(f), encoding: .utf8))?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                guard let version, version.count < 40, version.first?.isNumber == true else { continue }
                let coord = "\(group):\(artifact)"
                libs[coord] = DetectedLibrary(coordinate: coord, displayName: artifact, version: version,
                                              source: "META-INF/\(f)")
            }
            // 2. pom.properties
            let maven = meta.appendingPathComponent("maven")
            if let e = fm.enumerator(at: maven, includingPropertiesForKeys: nil) {
                for case let url as URL in e where url.lastPathComponent == "pom.properties" {
                    guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
                    let g = text.firstGroup("(?m)^groupId=(.+)$"), a = text.firstGroup("(?m)^artifactId=(.+)$")
                    let v = text.firstGroup("(?m)^version=(.+)$")
                    guard let g, let a else { continue }
                    let coord = "\(g):\(a)"
                    libs[coord] = DetectedLibrary(coordinate: coord, displayName: a, version: v,
                                                  source: "META-INF/maven/…/pom.properties")
                }
            }
        }

        // 3. Code namespaces (jadx sources or smali).
        let codeRoots: [URL] = {
            var r: [URL] = []
            let jadx = workspace.jadxDir.appendingPathComponent("sources")
            if fm.fileExists(atPath: jadx.path) { r.append(jadx) }
            if let top = try? fm.contentsOfDirectory(at: workspace.apktoolDir, includingPropertiesForKeys: nil) {
                r += top.filter { $0.lastPathComponent.hasPrefix("smali") }
            }
            return r
        }()
        for sig in signatures {
            // Skip if a more precise entry (with version) for the same artifact exists.
            let artifact = sig.coordinate.split(separator: ":").last.map(String.init) ?? ""
            if libs.keys.contains(where: { $0 == sig.coordinate || $0.hasSuffix(":\(artifact)") }) { continue }
            let exists = codeRoots.contains { root in
                let p = root.appendingPathComponent(sig.path).path
                return fm.fileExists(atPath: p) || fm.fileExists(atPath: p + ".java") || fm.fileExists(atPath: p + ".smali")
            }
            if exists {
                libs[sig.coordinate] = DetectedLibrary(coordinate: sig.coordinate, displayName: sig.name, version: nil,
                                                       source: "package namespace \(sig.path.replacingOccurrences(of: "/", with: "."))")
            }
        }

        // OkHttp embeds its version in a user-agent constant.
        if libs["com.squareup.okhttp3:okhttp"] != nil, libs["com.squareup.okhttp3:okhttp"]?.version == nil {
            if let v = findOkHttpVersion(codeRoots) { libs["com.squareup.okhttp3:okhttp"]?.version = v }
        }

        // 4. Native libraries.
        var abis: [String: Set<String>] = [:]
        for e in entries where e.hasPrefix("lib/") && e.hasSuffix(".so") {
            let parts = e.split(separator: "/")
            guard parts.count == 3 else { continue }
            abis[String(parts[2]), default: []].insert(String(parts[1]))
        }
        for (file, abiSet) in abis {
            let name = nativeSignatures.first(where: { $0.file == file })?.name ?? file
            let coord = "native:\(file)"
            libs[coord] = DetectedLibrary(coordinate: coord, displayName: name, version: nil,
                                          source: "lib/{\(abiSet.sorted().joined(separator: ","))}/\(file)")
        }

        return libs.values.sorted { $0.displayName.lowercased() < $1.displayName.lowercased() }
    }

    private static func findOkHttpVersion(_ roots: [URL]) -> String? {
        let candidates = ["okhttp3/internal/Version.java", "okhttp3/internal/Util.java", "okhttp3/OkHttp.java",
                          "okhttp3/internal/Version.smali", "okhttp3/OkHttp.smali", "okhttp3/internal/Util.smali",
                          "okhttp3/internal/_UtilJvmKt.java", "okhttp3/internal/_UtilJvmKt.smali"]
        for root in roots {
            for c in candidates {
                if let t = try? String(contentsOf: root.appendingPathComponent(c), encoding: .utf8),
                   let v = t.firstGroup("okhttp/(\\d+\\.\\d+\\.\\d+)") { return v }
            }
        }
        return nil
    }
}

/// Simple semantic-ish version comparison ("1.10.2" > "1.9").
enum VersionCompare {
    static func parts(_ v: String) -> [Int] {
        v.split(whereSeparator: { !$0.isNumber }).prefix(4).compactMap { Int($0) }
    }

    static func less(_ a: String, _ b: String) -> Bool {
        let x = parts(a), y = parts(b)
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l < r }
        }
        return false
    }
}
