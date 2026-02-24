import Foundation

struct IssuerRunRequest {
    let scriptPath: String
    let commandArgs: [String]
    let password: String?
    let passwordEnv: String
    let adminHash: String?
    let injectAdminHash: Bool
}

struct IssuerRunResult {
    let commandDisplay: String
    let exitCode: Int32
    let output: String
}

enum IssuerRunnerError: Error, LocalizedError {
    case scriptMissing(String)
    case launchFailed(String)

    var errorDescription: String? {
        switch self {
        case .scriptMissing(let path):
            return "Issuer script not found at \(path)"
        case .launchFailed(let reason):
            return "Failed to launch issuer process: \(reason)"
        }
    }
}

final class IssuerRunner {
    typealias ChunkHandler = (String) -> Void
    typealias CompletionHandler = (IssuerRunResult) -> Void

    @discardableResult
    func run(
        request: IssuerRunRequest,
        onChunk: @escaping ChunkHandler,
        onComplete: @escaping CompletionHandler
    ) throws -> Process {
        guard FileManager.default.fileExists(atPath: request.scriptPath) else {
            throw IssuerRunnerError.scriptMissing(request.scriptPath)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")

        var args: [String] = ["python3", request.scriptPath]
        if request.password != nil {
            args += ["--password-env", request.passwordEnv]
        }
        args += request.commandArgs
        process.arguments = args

        var env = ProcessInfo.processInfo.environment
        if let password = request.password {
            env[request.passwordEnv] = password
        }
        if request.injectAdminHash,
           env["QOS_ISSUER_ADMIN_HASH"] == nil,
           let adminHash = request.adminHash,
           !adminHash.isEmpty {
            env["QOS_ISSUER_ADMIN_HASH"] = adminHash
        }
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        let safeDisplay = args.map { $0 == request.password ? "<redacted>" : $0 }.joined(separator: " ")

        var mergedData = Data()
        let lock = NSLock()
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                return
            }
            lock.lock()
            mergedData.append(data)
            lock.unlock()

            if let chunk = String(data: data, encoding: .utf8), !chunk.isEmpty {
                DispatchQueue.main.async {
                    onChunk(chunk)
                }
            }
        }

        process.terminationHandler = { proc in
            pipe.fileHandleForReading.readabilityHandler = nil

            lock.lock()
            let outputData = mergedData
            lock.unlock()
            let output = String(data: outputData, encoding: .utf8) ?? "<non-utf8 output>"
            let result = IssuerRunResult(
                commandDisplay: safeDisplay,
                exitCode: proc.terminationStatus,
                output: output
            )
            DispatchQueue.main.async {
                onComplete(result)
            }
        }

        do {
            try process.run()
        } catch {
            throw IssuerRunnerError.launchFailed(error.localizedDescription)
        }

        return process
    }
}
