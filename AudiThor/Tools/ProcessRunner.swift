import Foundation

struct ProcessResult: Sendable {
    var exitCode: Int32
    var stdout: String
    var stderr: String
    var succeeded: Bool { exitCode == 0 }
}

enum ProcessRunnerError: LocalizedError {
    case launchFailed(String, Error)
    case timedOut(String, TimeInterval)

    var errorDescription: String? {
        switch self {
        case let .launchFailed(cmd, err): return "Could not launch \(cmd): \(err.localizedDescription)"
        case let .timedOut(cmd, t): return "\(cmd) did not finish within \(Int(t))s and was stopped."
        }
    }
}

/// Runs external command-line tools off the main thread.
///
/// Output is redirected to temporary files rather than pipes so large outputs
/// (jadx/apktool can be chatty) can never dead-lock on a full pipe buffer.
/// Task cancellation terminates the child process.
enum ProcessRunner {
    static func run(_ executable: URL,
                    arguments: [String],
                    environment: [String: String]? = nil,
                    workingDirectory: URL? = nil,
                    timeout: TimeInterval = 900) async throws -> ProcessResult {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent("audithor-proc-\(UUID().uuidString)")
        try fm.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tmp) }
        let outURL = tmp.appendingPathComponent("out"), errURL = tmp.appendingPathComponent("err")
        fm.createFile(atPath: outURL.path, contents: nil)
        fm.createFile(atPath: errURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: outURL)
        let errHandle = try FileHandle(forWritingTo: errURL)

        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = outHandle
        process.standardError = errHandle
        process.standardInput = FileHandle.nullDevice
        if let environment { process.environment = environment }
        if let workingDirectory { process.currentDirectoryURL = workingDirectory }

        let label = ([executable.lastPathComponent] + arguments.prefix(2)).joined(separator: " ")

        let exitCode: Int32 = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Int32, Error>) in
                let timeoutItem = DispatchWorkItem { [weak process] in
                    if process?.isRunning == true { process?.terminate() }
                }
                process.terminationHandler = { p in
                    timeoutItem.cancel()
                    cont.resume(returning: p.terminationStatus)
                }
                do {
                    try process.run()
                    DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timeoutItem)
                } catch {
                    process.terminationHandler = nil
                    cont.resume(throwing: ProcessRunnerError.launchFailed(label, error))
                }
            }
        } onCancel: {
            if process.isRunning { process.terminate() }
        }

        try? outHandle.close()
        try? errHandle.close()
        try Task.checkCancellation()

        let stdout = (try? String(contentsOf: outURL, encoding: .utf8)) ?? ""
        let stderr = (try? String(contentsOf: errURL, encoding: .utf8)) ?? ""
        if process.terminationReason == .uncaughtSignal && exitCode == SIGTERM {
            throw ProcessRunnerError.timedOut(label, timeout)
        }
        return ProcessResult(exitCode: exitCode, stdout: stdout, stderr: stderr)
    }
}
