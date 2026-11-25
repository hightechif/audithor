import Foundation

/// Lightweight DOM built from apktool's decoded (plain-text) XML.
final class XMLNode: @unchecked Sendable {
    let name: String
    let attributes: [String: String]
    var children: [XMLNode] = []
    var text = ""
    let line: Int
    weak var parent: XMLNode?

    init(name: String, attributes: [String: String], line: Int) {
        self.name = name
        self.attributes = attributes
        self.line = line
    }

    /// Attribute lookup that tolerates the `android:` prefix being present or not.
    func attr(_ key: String) -> String? {
        attributes["android:\(key)"] ?? attributes[key]
    }

    func boolAttr(_ key: String) -> Bool? {
        guard let v = attr(key)?.lowercased() else { return nil }
        if v == "true" { return true }
        if v == "false" { return false }
        return nil
    }

    func children(named n: String) -> [XMLNode] { children.filter { $0.name == n } }

    func descendants(named n: String) -> [XMLNode] {
        var out: [XMLNode] = []
        for c in children {
            if c.name == n { out.append(c) }
            out += c.descendants(named: n)
        }
        return out
    }
}

final class SimpleXMLParser: NSObject, XMLParserDelegate {
    private var stack: [XMLNode] = []
    private(set) var root: XMLNode?
    private var parser: XMLParser?

    static func parse(_ url: URL) -> XMLNode? {
        guard let p = XMLParser(contentsOf: url) else { return nil }
        let d = SimpleXMLParser()
        d.parser = p
        p.delegate = d
        p.shouldProcessNamespaces = false
        p.shouldResolveExternalEntities = false // never resolve XXE in untrusted input
        _ = p.parse()
        return d.root
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        let node = XMLNode(name: elementName, attributes: attributeDict, line: parser.lineNumber)
        if let top = stack.last {
            node.parent = top
            top.children.append(node)
        } else {
            root = node
        }
        stack.append(node)
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        stack.last?.text += string
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        _ = stack.popLast()
    }
}

/// Extracts `AppInfo` from apktool's decoded manifest + apktool.yml.
enum ManifestParser {
    struct Parsed {
        var root: XMLNode
        var info: AppInfo
        var manifestURL: URL
    }

    static func parse(apktoolDir: URL) -> Parsed? {
        let manifestURL = apktoolDir.appendingPathComponent("AndroidManifest.xml")
        guard let root = SimpleXMLParser.parse(manifestURL), root.name == "manifest" else { return nil }

        var info = AppInfo()
        info.packageName = root.attributes["package"] ?? "unknown"
        info.versionName = root.attr("versionName")
        info.versionCode = root.attr("versionCode")
        info.compileSdk = root.attr("compileSdkVersion").flatMap { Int($0) }

        if let usesSdk = root.children(named: "uses-sdk").first {
            info.minSdk = usesSdk.attr("minSdkVersion").flatMap { Int($0) }
            info.targetSdk = usesSdk.attr("targetSdkVersion").flatMap { Int($0) }
        }
        // apktool moves SDK versions into apktool.yml (sdkInfo / versionInfo).
        let yml = (try? String(contentsOf: apktoolDir.appendingPathComponent("apktool.yml"), encoding: .utf8)) ?? ""
        func ymlValue(_ key: String) -> String? {
            yml.firstGroup("(?m)^\\s*\(key):\\s*'?\"?([^'\"\\n]+)")?.trimmingCharacters(in: .whitespaces)
        }
        if info.minSdk == nil { info.minSdk = ymlValue("minSdkVersion").flatMap { Int($0) } }
        if info.targetSdk == nil { info.targetSdk = ymlValue("targetSdkVersion").flatMap { Int($0) } }
        if info.versionName == nil { info.versionName = ymlValue("versionName") }
        if info.versionCode == nil { info.versionCode = ymlValue("versionCode") }

        info.permissions = (root.children(named: "uses-permission") + root.children(named: "uses-permission-sdk-23"))
            .compactMap { $0.attr("name") }
        info.permissions = Array(Set(info.permissions)).sorted()

        for p in root.children(named: "permission") {
            if let name = p.attr("name") { info.customPermissions[name] = p.attr("protectionLevel") ?? "normal" }
        }

        if let app = root.children(named: "application").first {
            info.appLabel = resolveString(app.attr("label"), apktoolDir: apktoolDir)
            let target = info.targetSdk ?? 1
            for kind in [ComponentInfo.Kind.activity, .activityAlias, .service, .receiver, .provider] {
                for node in app.children(named: kind.rawValue) {
                    guard let rawName = node.attr("name") ?? node.attr("targetActivity") else { continue }
                    let name = qualifiedName(rawName, package: info.packageName)
                    let hasFilter = !node.children(named: "intent-filter").isEmpty
                    let explicit = node.boolAttr("exported")
                    let exported: Bool
                    if let explicit {
                        exported = explicit
                    } else if kind == .provider {
                        exported = target < 17
                    } else {
                        exported = hasFilter
                    }
                    var permission = node.attr("permission")
                    if kind == .provider, permission == nil {
                        permission = node.attr("readPermission") ?? node.attr("writePermission")
                    }
                    info.components.append(ComponentInfo(kind: kind, name: name, exported: exported,
                                                         exportedExplicit: explicit != nil, permission: permission,
                                                         hasIntentFilter: hasFilter))
                }
            }
        }
        return Parsed(root: root, info: info, manifestURL: manifestURL)
    }

    /// Expands relative component names (`.Main`, `Main`) to fully-qualified ones.
    static func qualifiedName(_ raw: String, package: String) -> String {
        if raw.hasPrefix(".") { return package + raw }
        if !raw.contains(".") { return package + "." + raw }
        return raw
    }

    /// Resolves `@string/foo` against `res/values/strings.xml`.
    static func resolveString(_ value: String?, apktoolDir: URL) -> String? {
        guard let value else { return nil }
        guard value.hasPrefix("@string/") else { return value }
        let key = String(value.dropFirst("@string/".count))
        let strings = apktoolDir.appendingPathComponent("res/values/strings.xml")
        guard let text = try? String(contentsOf: strings, encoding: .utf8) else { return nil }
        return text.firstGroup("<string name=\"\(NSRegularExpression.escapedPattern(for: key))\"[^>]*>([^<]*)</string>")
    }

    /// Resolves an `@xml/name` resource reference to a file.
    static func resolveXMLResource(_ ref: String?, apktoolDir: URL) -> URL? {
        guard let ref, ref.hasPrefix("@xml/") else { return nil }
        let url = apktoolDir.appendingPathComponent("res/xml/\(ref.dropFirst(5)).xml")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }
}
