// Real-etserver integration harness.
//
// Run explicitly with:
//   ET_INTEGRATION=1 swift test --filter ETIntegrationTests
//
// Every test owns an etserver, etterminal, router Unix socket, config, logs,
// and any TCP proxy/listeners under a unique temporary directory. The suite is
// skipped before creating those resources unless ET_INTEGRATION=1.

@testable import ETClient
import Darwin
import Foundation
import Network
import XCTest

@MainActor
final class ETIntegrationTests: XCTestCase {
    func testHandshakeAndTerminalEcho() async throws {
        try requireIntegration()
        try await withFixture { fixture in
            let session = try await fixture.connectSession()
            await fixture.clearOutput()
            try await session.send(Data("echo hello-et\n".utf8))
            try await fixture.waitForOutput("hello-et", minimumOccurrences: 2)
        }
    }

    func testTerminalResizeDoesNotError() async throws {
        try requireIntegration()
        try await withFixture { fixture in
            let session = try await fixture.connectSession()
            try await session.resize(rows: 37, cols: 119)
        }
    }

    func testReconnectPreservesShellState() async throws {
        try requireIntegration()
        try await withFixture { fixture in
            let proxy = try await fixture.startDropProxy()
            let session = try await fixture.connectSession(port: await proxy.port())

            try await session.send(Data("et_state=survived\n".utf8))
            try await session.send(Data("echo state-ready\n".utf8))
            try await fixture.waitForOutput("state-ready", minimumOccurrences: 2)
            await fixture.clearOutput()

            await proxy.dropActiveConnection()
            try await session.send(Data("echo \"$et_state\"\n".utf8))
            try await fixture.waitForOutput("survived")
            let connectionCount = await proxy.acceptedConnectionCount()
            XCTAssertGreaterThanOrEqual(connectionCount, 2)
        }
    }

    func testForwardTunnelAgainstLocalEchoServer() async throws {
        try requireIntegration()
        try await withFixture { fixture in
            let echoServer = try await fixture.startEchoServer()
            let sourcePort = try reserveEphemeralPort()
            let echoPort = try await echoServer.port()
            let tunnel = ETTunnel(
                source: .endpoint(.tcp(host: "127.0.0.1", port: sourcePort)),
                destination: .tcp(host: nil, port: echoPort)
            )
            _ = try await fixture.connectSession(tunnels: [tunnel])

            let client = try await fixture.connectTCP(port: sourcePort)
            let payload = Data((0..<131_072).map { UInt8(truncatingIfNeeded: $0 &* 17) })
            try await client.write(payload)
            let echoed = try await client.read(exactly: payload.count)
            XCTAssertEqual(echoed, payload)
        }
    }

    private func requireIntegration() throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["ET_INTEGRATION"] == "1",
            "Set ET_INTEGRATION=1 to run against /opt/homebrew/bin/etserver"
        )
        try XCTSkipUnless(
            IntegrationFixture.hasRequiredExecutables,
            "etserver/etterminal not found; install with: brew install MisterTea/et/et"
        )
    }

    private func withFixture(
        _ body: (IntegrationFixture) async throws -> Void
    ) async throws {
        let fixture = try IntegrationFixture()
        do {
            try await fixture.start()
            try await body(fixture)
            await fixture.stop()
        } catch {
            let diagnostics = fixture.diagnostics()
            await fixture.stop()
            let message = diagnostics.isEmpty
                ? String(describing: error)
                : "\(error)\n\(diagnostics)"
            throw IntegrationError.testFailure(message)
        }
    }
}

@MainActor
private final class IntegrationFixture {
    private static let serverExecutable = URL(fileURLWithPath: "/opt/homebrew/bin/etserver")
    private static let terminalExecutable = URL(fileURLWithPath: "/opt/homebrew/bin/etterminal")

    static var hasRequiredExecutables: Bool {
        FileManager.default.isExecutableFile(atPath: serverExecutable.path)
            && FileManager.default.isExecutableFile(atPath: terminalExecutable.path)
    }

    private let directory: URL
    private let configURL: URL
    private let fifoURL: URL
    private let serverLogURL: URL
    private let terminalLogURL: URL
    private let serverPort: UInt16
    private let clientID: String
    private let passkey: String
    private let output = OutputBuffer()

    private var serverProcess: Process?
    private var terminalProcess: Process?
    private var terminalDaemonPID: pid_t?
    private var logHandles: [FileHandle] = []
    private var session: ETTerminalSession?
    private var outputTask: Task<Void, Never>?
    private var proxies: [DropTCPProxy] = []
    private var echoServers: [LocalEchoServer] = []
    private var clientConnections: [TestTCPConnection] = []
    private var hasStopped = false

    init() throws {
        let temporaryRoot = URL(fileURLWithPath: "/tmp", isDirectory: true)
        let uniqueSuffix = UUID().uuidString.prefixString(8)
        directory = temporaryRoot.appendingPathComponent(
            "swift-et-\(getpid())-\(uniqueSuffix)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        configURL = directory.appendingPathComponent("etserver.conf")
        fifoURL = directory.appendingPathComponent("router.sock")
        serverLogURL = directory.appendingPathComponent("etserver.log")
        terminalLogURL = directory.appendingPathComponent("etterminal.log")
        serverPort = try reserveEphemeralPort()
        clientID = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefixString(16)
        passkey = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefixString(32)
    }

    func start() async throws {
        let config = """
        [Networking]
        port=\(serverPort)
        bind_ip=127.0.0.1

        [Debug]
        telemetry=false
        serverfifo=\(fifoURL.path)
        logdirectory=\(directory.path)/
        silent=0
        """
        try config.write(to: configURL, atomically: true, encoding: .utf8)

        serverProcess = try launch(
            executable: Self.serverExecutable,
            arguments: [
                "--cfgfile", configURL.path,
                "--port", String(serverPort),
                "--bindip", "127.0.0.1",
                "--serverfifo", fifoURL.path,
                "--logdir", directory.path,
                "--logtostdout",
            ],
            logURL: serverLogURL
        )
        try await waitUntil(timeout: .seconds(5)) {
            if self.serverProcess?.isRunning != true {
                throw IntegrationError.processExited("etserver", self.readLog(self.serverLogURL))
            }
            return FileManager.default.fileExists(atPath: self.fifoURL.path)
        }

        let terminalInput = Pipe()
        terminalProcess = try launch(
            executable: Self.terminalExecutable,
            arguments: [
                "--serverfifo", fifoURL.path,
                "--logdir", directory.path,
                "--logtostdout",
            ],
            logURL: terminalLogURL,
            standardInput: terminalInput
        )
        let registration = Data("\(clientID)/\(passkey)_xterm-256color\n".utf8)
        try terminalInput.fileHandleForWriting.write(contentsOf: registration)
        try terminalInput.fileHandleForWriting.close()

        try await waitUntil(timeout: .seconds(5)) {
            self.readLog(self.terminalLogURL).contains("IDPASSKEY:")
        }
        let launcherPID = terminalProcess?.processIdentifier
        try await waitUntil(timeout: .seconds(5)) {
            let candidates = self.processIDs(
                matchingCommandFragments: [
                    Self.terminalExecutable.path,
                    self.fifoURL.path,
                ]
            ).filter { $0 != launcherPID }
            guard let daemonPID = candidates.first else { return false }
            self.terminalDaemonPID = daemonPID
            return true
        }
    }

    func connectSession(
        port: UInt16? = nil,
        tunnels: [ETTunnel] = []
    ) async throws -> ETTerminalSession {
        guard session == nil else { throw IntegrationError.sessionAlreadyConnected }
        let newSession = try ETTerminalSession(
            host: "127.0.0.1",
            port: port ?? serverPort,
            clientID: clientID,
            passkey: Data(passkey.utf8),
            tunnels: tunnels,
            environmentVariables: ["TERM": "xterm-256color"]
        )
        session = newSession
        outputTask = Task { [output, stream = newSession.output] in
            for await bytes in stream {
                guard !Task.isCancelled else { return }
                await output.append(bytes)
            }
        }
        try await newSession.connect()
        return newSession
    }

    func startDropProxy() async throws -> DropTCPProxy {
        let proxy = try DropTCPProxy(upstreamPort: serverPort)
        try await proxy.start()
        proxies.append(proxy)
        return proxy
    }

    func startEchoServer() async throws -> LocalEchoServer {
        let server = try LocalEchoServer()
        try await server.start()
        echoServers.append(server)
        return server
    }

    func connectTCP(port: UInt16) async throws -> TestTCPConnection {
        let connection = TestTCPConnection(host: "127.0.0.1", port: port)
        try await connection.start()
        clientConnections.append(connection)
        return connection
    }

    func clearOutput() async {
        await output.clear()
    }

    func waitForOutput(
        _ text: String,
        minimumOccurrences: Int = 1
    ) async throws {
        let needle = Data(text.utf8)
        try await waitUntil(timeout: .seconds(10)) {
            await self.output.occurrences(of: needle) >= minimumOccurrences
        }
    }

    func stop() async {
        guard !hasStopped else { return }
        hasStopped = true

        for connection in clientConnections { await connection.close() }
        clientConnections.removeAll()
        for proxy in proxies { await proxy.close() }
        proxies.removeAll()
        for echoServer in echoServers { await echoServer.close() }
        echoServers.removeAll()

        outputTask?.cancel()
        outputTask = nil
        await session?.close()
        session = nil

        let discoveredTerminalPID = terminalDaemonPID ?? processIDs(
            matchingCommandFragments: [Self.terminalExecutable.path, fifoURL.path]
        ).first
        if let discoveredTerminalPID {
            await stopProcess(identifier: discoveredTerminalPID, includeDescendants: true)
        }
        terminalDaemonPID = nil
        await stopProcess(terminalProcess, includeDescendants: false)
        terminalProcess = nil
        await stopProcess(serverProcess, includeDescendants: false)
        serverProcess = nil

        for handle in logHandles { try? handle.close() }
        logHandles.removeAll()
        try? FileManager.default.removeItem(at: directory)
    }

    func diagnostics() -> String {
        let server = readLog(serverLogURL)
        let terminal = readLog(terminalLogURL)
        guard !server.isEmpty || !terminal.isEmpty else { return "" }
        return "--- etserver.log ---\n\(server)\n--- etterminal.log ---\n\(terminal)"
    }

    private func launch(
        executable: URL,
        arguments: [String],
        logURL: URL,
        standardInput: Pipe? = nil
    ) throws -> Process {
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw IntegrationError.missingExecutable(executable.path)
        }
        _ = FileManager.default.createFile(atPath: logURL.path, contents: nil)
        let logHandle = try FileHandle(forWritingTo: logURL)
        logHandles.append(logHandle)

        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardInput = standardInput ?? FileHandle.nullDevice
        process.standardOutput = logHandle
        process.standardError = logHandle
        var environment = ProcessInfo.processInfo.environment
        environment["SHELL"] = "/bin/sh"
        environment["TERM"] = "xterm-256color"
        process.environment = environment
        try process.run()
        return process
    }

    private func stopProcess(
        _ process: Process?,
        includeDescendants: Bool
    ) async {
        guard let process else { return }
        let pid = process.processIdentifier
        let descendants = includeDescendants ? descendantProcessIDs(of: pid) : []
        for child in descendants.reversed() { _ = Darwin.kill(child, SIGTERM) }
        if process.isRunning { _ = Darwin.kill(pid, SIGTERM) }

        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(1))
        while process.isRunning, clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(20))
        }
        for child in descendants where Darwin.kill(child, 0) == 0 {
            _ = Darwin.kill(child, SIGKILL)
        }
        if process.isRunning { _ = Darwin.kill(pid, SIGKILL) }
        if process.isRunning { process.waitUntilExit() }
    }

    private func stopProcess(
        identifier pid: pid_t,
        includeDescendants: Bool
    ) async {
        let descendants = includeDescendants ? descendantProcessIDs(of: pid) : []
        for child in descendants.reversed() { _ = Darwin.kill(child, SIGTERM) }
        if Darwin.kill(pid, 0) == 0 { _ = Darwin.kill(pid, SIGTERM) }

        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(1))
        while Darwin.kill(pid, 0) == 0, clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(20))
        }
        for child in descendants where Darwin.kill(child, 0) == 0 {
            _ = Darwin.kill(child, SIGKILL)
        }
        if Darwin.kill(pid, 0) == 0 { _ = Darwin.kill(pid, SIGKILL) }
    }

    private func descendantProcessIDs(of parent: pid_t) -> [pid_t] {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-P", String(parent)]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = try output.fileHandleForReading.readToEnd() ?? Data()
            let children = String(decoding: data, as: UTF8.self)
                .split(whereSeparator: \Character.isWhitespace)
                .compactMap { pid_t($0) }
            return children + children.flatMap(descendantProcessIDs)
        } catch {
            return []
        }
    }

    private func processIDs(matchingCommandFragments fragments: [String]) -> [pid_t] {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,command="]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = try output.fileHandleForReading.readToEnd() ?? Data()
            process.waitUntilExit()
            return String(decoding: data, as: UTF8.self)
                .split(separator: "\n")
                .compactMap { line in
                    guard fragments.allSatisfy({ line.contains($0) }) else { return nil }
                    guard let first = line.split(whereSeparator: \Character.isWhitespace).first else {
                        return nil
                    }
                    return pid_t(String(first))
                }
        } catch {
            return []
        }
    }

    private func readLog(_ url: URL) -> String {
        guard let data = try? Data(contentsOf: url) else { return "" }
        return String(decoding: data, as: UTF8.self)
    }
}

private actor OutputBuffer {
    private var data = Data()

    func append(_ bytes: Data) {
        data.append(bytes)
    }

    func clear() {
        data.removeAll(keepingCapacity: true)
    }

    func occurrences(of needle: Data) -> Int {
        guard !needle.isEmpty, data.count >= needle.count else { return 0 }
        var count = 0
        var searchStart = data.startIndex
        while searchStart < data.endIndex,
              let range = data.range(of: needle, in: searchStart..<data.endIndex) {
            count += 1
            searchStart = range.upperBound
        }
        return count
    }
}

private actor TestTCPConnection {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "ETIntegrationTests.TCPConnection")
    private var startContinuation: CheckedContinuation<Void, any Error>?
    private var isStarted = false
    private var isClosed = false

    init(host: String, port: UInt16) {
        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any,
            using: .tcp
        )
    }

    init(connection: NWConnection) {
        self.connection = connection
    }

    func start() async throws {
        guard !isStarted else { return }
        guard !isClosed else { throw IntegrationError.connectionClosed }
        isStarted = true
        connection.stateUpdateHandler = { [weak self] state in
            let result: Result<Void, IntegrationError>?
            switch state {
            case .setup, .preparing, .waiting:
                result = nil
            case .ready:
                result = .success(())
            case .failed(let error):
                result = .failure(.network(String(describing: error)))
            case .cancelled:
                result = .failure(.connectionClosed)
            @unknown default:
                result = .failure(.network("Unknown Network.framework state"))
            }
            guard let result else { return }
            Task { [weak self] in await self?.completeStart(result) }
        }
        try await withCheckedThrowingContinuation { continuation in
            startContinuation = continuation
            connection.start(queue: queue)
        }
    }

    func read() async throws -> Data {
        guard isStarted, !isClosed else { throw IntegrationError.connectionClosed }
        return try await withCheckedThrowingContinuation { continuation in
            connection.receive(
                minimumIncompleteLength: 1,
                maximumLength: 64 * 1_024
            ) { content, _, complete, error in
                if let error {
                    continuation.resume(throwing: IntegrationError.network(String(describing: error)))
                } else if let content, !content.isEmpty {
                    continuation.resume(returning: content)
                } else if complete {
                    continuation.resume(throwing: IntegrationError.connectionClosed)
                } else {
                    continuation.resume(returning: Data())
                }
            }
        }
    }

    func read(exactly count: Int) async throws -> Data {
        var result = Data()
        while result.count < count {
            result.append(try await read())
        }
        return Data(result.prefix(count))
    }

    func write(_ data: Data) async throws {
        guard isStarted, !isClosed else { throw IntegrationError.connectionClosed }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: IntegrationError.network(String(describing: error)))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func close() {
        guard !isClosed else { return }
        isClosed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        startContinuation?.resume(throwing: IntegrationError.connectionClosed)
        startContinuation = nil
    }

    private func completeStart(_ result: Result<Void, IntegrationError>) {
        guard let continuation = startContinuation else { return }
        startContinuation = nil
        continuation.resume(with: result)
    }
}

private actor TestTCPListener {
    nonisolated let connections: AsyncStream<TestTCPConnection>

    private let continuation: AsyncStream<TestTCPConnection>.Continuation
    private let listener: NWListener
    private let queue = DispatchQueue(label: "ETIntegrationTests.TCPListener")
    private var startContinuation: CheckedContinuation<Void, any Error>?
    private var listeningPort: UInt16?
    private var isClosed = false

    init(port: UInt16? = nil) throws {
        let pair = AsyncStream<TestTCPConnection>.makeStream(bufferingPolicy: .unbounded)
        connections = pair.stream
        continuation = pair.continuation
        if let port {
            guard let networkPort = NWEndpoint.Port(rawValue: port) else {
                throw IntegrationError.network("Invalid listener port \(port)")
            }
            listener = try NWListener(using: .tcp, on: networkPort)
        } else {
            listener = try NWListener(using: .tcp, on: .any)
        }
    }

    func start() async throws {
        guard !isClosed else { throw IntegrationError.connectionClosed }
        listener.newConnectionHandler = { [continuation] connection in
            continuation.yield(TestTCPConnection(connection: connection))
        }
        listener.stateUpdateHandler = { [weak self] state in
            let result: Result<UInt16, IntegrationError>?
            switch state {
            case .setup, .waiting:
                result = nil
            case .ready:
                if let port = self?.listener.port?.rawValue {
                    result = .success(port)
                } else {
                    result = .failure(.network("Listener has no bound port"))
                }
            case .failed(let error):
                result = .failure(.network(String(describing: error)))
            case .cancelled:
                result = .failure(.connectionClosed)
            @unknown default:
                result = .failure(.network("Unknown Network.framework listener state"))
            }
            guard let result else { return }
            Task { [weak self] in await self?.completeStart(result) }
        }
        try await withCheckedThrowingContinuation { continuation in
            startContinuation = continuation
            listener.start(queue: queue)
        }
    }

    func port() throws -> UInt16 {
        guard let listeningPort else {
            throw IntegrationError.network("Listener is not ready")
        }
        return listeningPort
    }

    func close() {
        guard !isClosed else { return }
        isClosed = true
        listener.stateUpdateHandler = nil
        listener.newConnectionHandler = nil
        listener.cancel()
        continuation.finish()
        startContinuation?.resume(throwing: IntegrationError.connectionClosed)
        startContinuation = nil
    }

    private func completeStart(_ result: Result<UInt16, IntegrationError>) {
        guard let continuation = startContinuation else { return }
        startContinuation = nil
        switch result {
        case .success(let port):
            listeningPort = port
            continuation.resume()
        case .failure(let error):
            continuation.resume(throwing: error)
        }
    }
}

private actor DropTCPProxy {
    private let upstreamPort: UInt16
    private let listener: TestTCPListener
    private var acceptTask: Task<Void, Never>?
    private var relayTasks: [Task<Void, Never>] = []
    private var client: TestTCPConnection?
    private var upstream: TestTCPConnection?
    private var connectionCount = 0

    init(upstreamPort: UInt16) throws {
        self.upstreamPort = upstreamPort
        listener = try TestTCPListener()
    }

    func start() async throws {
        try await listener.start()
        let connections = listener.connections
        acceptTask = Task { [weak self] in
            for await connection in connections {
                guard !Task.isCancelled else { return }
                await self?.accept(connection)
            }
        }
    }

    func port() async throws -> UInt16 {
        try await listener.port()
    }

    func acceptedConnectionCount() -> Int {
        connectionCount
    }

    func dropActiveConnection() async {
        await closeActiveConnection()
    }

    func close() async {
        acceptTask?.cancel()
        acceptTask = nil
        await closeActiveConnection()
        await listener.close()
    }

    private func accept(_ newClient: TestTCPConnection) async {
        let newUpstream = TestTCPConnection(host: "127.0.0.1", port: upstreamPort)
        do {
            async let clientStart: Void = newClient.start()
            async let upstreamStart: Void = newUpstream.start()
            try await clientStart
            try await upstreamStart
        } catch {
            await newClient.close()
            await newUpstream.close()
            return
        }

        await closeActiveConnection()
        client = newClient
        upstream = newUpstream
        connectionCount += 1
        relayTasks = [
            relay(from: newClient, to: newUpstream),
            relay(from: newUpstream, to: newClient),
        ]
    }

    private func relay(
        from source: TestTCPConnection,
        to destination: TestTCPConnection
    ) -> Task<Void, Never> {
        Task { [weak self] in
            do {
                while !Task.isCancelled {
                    let bytes = try await source.read()
                    guard !bytes.isEmpty else { continue }
                    try await destination.write(bytes)
                }
            } catch {
                await self?.connectionEnded(source: source)
            }
        }
    }

    private func connectionEnded(source: TestTCPConnection) async {
        guard source === client || source === upstream else { return }
        await closeActiveConnection()
    }

    private func closeActiveConnection() async {
        let tasks = relayTasks
        relayTasks.removeAll()
        tasks.forEach { $0.cancel() }
        let activeClient = client
        let activeUpstream = upstream
        client = nil
        upstream = nil
        await activeClient?.close()
        await activeUpstream?.close()
    }
}

private actor LocalEchoServer {
    private let listener: TestTCPListener
    private var acceptTask: Task<Void, Never>?
    private var connections: [TestTCPConnection] = []
    private var echoTasks: [Task<Void, Never>] = []

    init() throws {
        listener = try TestTCPListener()
    }

    func start() async throws {
        try await listener.start()
        let incoming = listener.connections
        acceptTask = Task { [weak self] in
            for await connection in incoming {
                guard !Task.isCancelled else { return }
                await self?.accept(connection)
            }
        }
    }

    func port() async throws -> UInt16 {
        try await listener.port()
    }

    func close() async {
        acceptTask?.cancel()
        acceptTask = nil
        echoTasks.forEach { $0.cancel() }
        echoTasks.removeAll()
        let activeConnections = connections
        connections.removeAll()
        for connection in activeConnections { await connection.close() }
        await listener.close()
    }

    private func accept(_ connection: TestTCPConnection) async {
        do {
            try await connection.start()
        } catch {
            await connection.close()
            return
        }
        connections.append(connection)
        echoTasks.append(
            Task {
                do {
                    while !Task.isCancelled {
                        let bytes = try await connection.read()
                        guard !bytes.isEmpty else { continue }
                        try await connection.write(bytes)
                    }
                } catch {
                    await connection.close()
                }
            }
        )
    }
}

private enum IntegrationError: Error {
    case connectionClosed
    case missingExecutable(String)
    case network(String)
    case processExited(String, String)
    case sessionAlreadyConnected
    case testFailure(String)
    case timeout
}

@MainActor
private func waitUntil(
    timeout: Duration,
    condition: () async throws -> Bool
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    while clock.now < deadline {
        if try await condition() { return }
        try await Task.sleep(for: .milliseconds(20))
    }
    throw IntegrationError.timeout
}

private func reserveEphemeralPort() throws -> UInt16 {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else {
        throw IntegrationError.network(String(cString: strerror(errno)))
    }
    defer { Darwin.close(descriptor) }

    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = 0
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bindResult = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bindResult == 0 else {
        throw IntegrationError.network(String(cString: strerror(errno)))
    }

    var boundAddress = sockaddr_in()
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.getsockname(descriptor, $0, &length)
        }
    }
    guard nameResult == 0 else {
        throw IntegrationError.network(String(cString: strerror(errno)))
    }
    return UInt16(bigEndian: boundAddress.sin_port)
}

private extension String {
    func prefixString(_ count: Int) -> String {
        String(prefix(count))
    }
}
