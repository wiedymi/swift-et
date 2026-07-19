import Darwin
import ETBootstrap
import ETSession
import Foundation

private struct DemoArguments: Sendable {
    let host: String
    let user: String
    let etPort: UInt16
    let sshPort: UInt16?

    static let usage = """
    Usage: ETDemo [--ssh-port PORT] <host> <user> [et-port]

      host       SSH and etserver host
      user       SSH user
      et-port    etserver TCP port (default: 2022)
    """

    static func parse(_ arguments: [String]) throws -> DemoArguments {
        if arguments.contains("--help") || arguments.contains("-h") {
            throw DemoError.help
        }
        var values = arguments
        var sshPort: UInt16?
        if let index = values.firstIndex(of: "--ssh-port") {
            guard values.indices.contains(index + 1),
                  let port = UInt16(values[index + 1]) else {
                throw DemoError.invalidArguments
            }
            sshPort = port
            values.removeSubrange(index...(index + 1))
        }
        guard values.count == 2 || values.count == 3 else {
            throw DemoError.invalidArguments
        }
        let etPort = values.count == 3 ? UInt16(values[2]) : 2022
        guard let etPort else { throw DemoError.invalidArguments }
        return DemoArguments(
            host: values[0],
            user: values[1],
            etPort: etPort,
            sshPort: sshPort
        )
    }
}

private enum DemoError: Error {
    case help
    case invalidArguments
    case sshFailed(Int32, String)
}

private struct SystemSSHBootstrapExecutor: ETBootstrapExecutor {
    let host: String
    let user: String
    let port: UInt16?

    func run(command: String) async throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        var arguments: [String] = []
        if let port {
            arguments += ["-p", String(port)]
        }
        arguments += ["\(user)@\(host)", command]
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = try output.fileHandleForReading.readToEnd() ?? Data()
        process.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw DemoError.sshFailed(process.terminationStatus, text)
        }
        return text
    }
}

private struct RawTerminal {
    private let original: termios

    init?() {
        var original = termios()
        guard tcgetattr(STDIN_FILENO, &original) == 0 else { return nil }
        self.original = original
        var raw = original
        cfmakeraw(&raw)
        guard tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0 else { return nil }
    }

    func restore() {
        var original = original
        _ = tcsetattr(STDIN_FILENO, TCSANOW, &original)
    }
}

@main
private struct ETDemo {
    static func main() async {
        do {
            let arguments = try DemoArguments.parse(Array(CommandLine.arguments.dropFirst()))
            try await run(arguments)
        } catch DemoError.help {
            print(DemoArguments.usage)
        } catch DemoError.invalidArguments {
            FileHandle.standardError.write(Data((DemoArguments.usage + "\n").utf8))
            Foundation.exit(64)
        } catch {
            FileHandle.standardError.write(Data("ETDemo: \(error)\n".utf8))
            Foundation.exit(1)
        }
    }

    private static func run(_ arguments: DemoArguments) async throws {
        let executor = SystemSSHBootstrapExecutor(
            host: arguments.host,
            user: arguments.user,
            port: arguments.sshPort
        )
        let session = ETTerminalSession(
            host: arguments.host,
            port: arguments.etPort,
            bootstrapExecutor: executor,
            environmentVariables: ["TERM": ProcessInfo.processInfo.environment["TERM"] ?? "xterm-256color"]
        )
        let outputTask = Task {
            for await data in session.output {
                try FileHandle.standardOutput.write(contentsOf: data)
            }
        }
        let stateTask = Task {
            for await state in session.stateChanges {
                FileHandle.standardError.write(Data("[ET] \(state)\n".utf8))
            }
        }
        defer {
            outputTask.cancel()
            stateTask.cancel()
        }

        try await session.connect()
        let rawTerminal = RawTerminal()
        defer { rawTerminal?.restore() }
        for try await byte in FileHandle.standardInput.bytes {
            try await session.send(Data([byte]))
        }
        await session.close()
        _ = try await outputTask.value
    }
}
