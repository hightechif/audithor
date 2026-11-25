import Foundation
import CryptoKit

/// A scratch directory holding everything derived from one scan.
///
/// The input APK is **never** modified: tools only read it, and all decoded
/// output is written here. The directory lives under the user's Caches folder
/// and is removed after the scan unless the user opts to keep it.
struct Workspace: Sendable {
    let root: URL
    var apktoolDir: URL { root.appendingPathComponent("apktool", isDirectory: true) }
    var jadxDir: URL { root.appendingPathComponent("jadx", isDirectory: true) }
    var bundleDir: URL { root.appendingPathComponent("bundle", isDirectory: true) }
    var frameworkDir: URL { root.appendingPathComponent("apktool-framework", isDirectory: true) }
    var metaInfDir: URL { root.appendingPathComponent("meta-inf", isDirectory: true) }

    static func create(scanID: UUID) throws -> Workspace {
        let caches = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask,
                                                 appropriateFor: nil, create: true)
        let root = caches.appendingPathComponent("AudiThor/workspaces/\(scanID.uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return Workspace(root: root)
    }

    func remove() { try? FileManager.default.removeItem(at: root) }

    /// Path relative to the workspace root, used in evidence so reports don't leak
    /// local directory names.
    func relativePath(_ url: URL) -> String {
        let r = root.standardizedFileURL.path
        let p = url.standardizedFileURL.path
        if p.hasPrefix(r) { return String(p.dropFirst(r.count + 1)) }
        return url.lastPathComponent
    }
}

enum FileHasher {
    /// Streams the file through SHA-256 so large APKs don't need to fit in memory.
    static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1 << 20) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
