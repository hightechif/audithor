import Foundation
import GRDB

/// Local scan history, stored in SQLite via GRDB at
/// `~/Library/Application Support/AudiThor/history.sqlite`.
///
/// Queryable columns are denormalised for the sidebar; the full `ScanResult`
/// is stored as a JSON payload so the schema can evolve without migrations
/// for every new field.
final class ScanStore: @unchecked Sendable {
    private let dbQueue: DatabaseQueue

    private struct Row: Codable, FetchableRecord, PersistableRecord {
        static let databaseTableName = "scan"
        var id: String
        var startedAt: Date
        var packageName: String
        var appLabel: String?
        var versionName: String?
        var fileName: String
        var sha256: String
        var riskScore: Int
        var findingCount: Int
        var payload: Data
    }

    static func defaultURL() throws -> URL {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
        let dir = support.appendingPathComponent("AudiThor", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("history.sqlite")
    }

    init(url: URL? = nil) throws {
        let path = try (url ?? ScanStore.defaultURL()).path
        dbQueue = try DatabaseQueue(path: path)
        try Self.migrator.migrate(dbQueue)
    }

    /// In-memory store (used when the on-disk database cannot be opened).
    init(inMemory: Void) throws {
        dbQueue = try DatabaseQueue()
        try Self.migrator.migrate(dbQueue)
    }

    private static var migrator: DatabaseMigrator {
        var m = DatabaseMigrator()
        m.registerMigration("v1") { db in
            try db.create(table: "scan") { t in
                t.primaryKey("id", .text)
                t.column("startedAt", .datetime).notNull().indexed()
                t.column("packageName", .text).notNull().indexed()
                t.column("appLabel", .text)
                t.column("versionName", .text)
                t.column("fileName", .text).notNull()
                t.column("sha256", .text).notNull().indexed()
                t.column("riskScore", .integer).notNull()
                t.column("findingCount", .integer).notNull()
                t.column("payload", .blob).notNull()
            }
        }
        return m
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    func save(_ scan: ScanResult) throws {
        let row = Row(id: scan.id.uuidString, startedAt: scan.startedAt, packageName: scan.app.packageName,
                      appLabel: scan.app.appLabel, versionName: scan.app.versionName,
                      fileName: scan.input.fileName, sha256: scan.input.sha256,
                      riskScore: scan.riskScore, findingCount: scan.findings.count,
                      payload: try Self.encoder.encode(scan))
        try dbQueue.write { db in try row.save(db) }
    }

    func summaries() throws -> [ScanSummary] {
        try dbQueue.read { db in
            try Row.order(Column("startedAt").desc).fetchAll(db).compactMap { r in
                guard let id = UUID(uuidString: r.id) else { return nil }
                return ScanSummary(id: id, startedAt: r.startedAt, packageName: r.packageName,
                                   appLabel: r.appLabel, versionName: r.versionName, fileName: r.fileName,
                                   sha256: r.sha256, riskScore: r.riskScore, findingCount: r.findingCount)
            }
        }
    }

    func load(_ id: UUID) throws -> ScanResult? {
        let row = try dbQueue.read { db in try Row.fetchOne(db, key: id.uuidString) }
        guard let row else { return nil }
        return try Self.decoder.decode(ScanResult.self, from: row.payload)
    }

    func delete(_ id: UUID) throws {
        _ = try dbQueue.write { db in try Row.deleteOne(db, key: id.uuidString) }
    }

    func deleteAll() throws {
        _ = try dbQueue.write { db in try Row.deleteAll(db) }
    }
}
