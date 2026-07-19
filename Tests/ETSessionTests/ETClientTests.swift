@testable import ETSession
import ETBootstrap
import ETCore
import ETCrypto
import ETTransport
import Foundation
import SwiftProtobuf
import XCTest

@MainActor
final class ETClientTests: XCTestCase {
    private let key = Data("0123456789abcdefghijklmnopqrstuv".utf8)

    func testHandshakeTerminalInputResizeAndOutput() async throws {
        let server = FakeETServer()
        let session = try makeSession(server: server)
        let output = expectation(description: "terminal output")
        let outputTask = Task {
            for await bytes in session.output {
                if bytes == Data("server output".utf8) {
                    output.fulfill()
                    return
                }
            }
        }
        defer { outputTask.cancel() }

        try await session.connect()
        try await session.send(Data("client input".utf8))
        try await session.resize(rows: 42, cols: 132)
        try await server.sendTerminalOutput(Data("server output".utf8))

        await fulfillment(of: [output], timeout: 1)
        let snapshot = await server.snapshot()
        XCTAssertEqual(snapshot.connectRequests.count, 1)
        XCTAssertEqual(snapshot.connectRequests.first?.clientID, "test-client")
        XCTAssertEqual(snapshot.connectRequests.first?.version, 6)
        XCTAssertEqual(snapshot.initialPayloads.count, 1)
        XCTAssertEqual(snapshot.terminalInput, [Data("client input".utf8)])
        XCTAssertEqual(snapshot.terminalSizes, [TerminalSize(rows: 42, columns: 132)])
        await session.close()
    }

    func testResizeEncodesOptionalPixelDimensions() async throws {
        let server = FakeETServer()
        let session = try makeSession(server: server)
        try await session.connect()

        try await session.resize(
            rows: 50,
            cols: 160,
            pixelWidth: 1_920,
            pixelHeight: 1_080
        )

        let sizes = await server.snapshot().terminalSizes
        XCTAssertEqual(
            sizes.last,
            TerminalSize(
                rows: 50,
                columns: 160,
                pixelWidth: 1_920,
                pixelHeight: 1_080
            )
        )
        do {
            try await session.resize(rows: 50, cols: 160, pixelWidth: -1)
            XCTFail("Expected negative pixel width to fail")
        } catch {
            XCTAssertEqual(
                error as? ETClientError,
                .invalidTerminalPixels(width: -1, height: nil)
            )
        }
        await session.close()
    }

    func testBootstrapStatePrecedesConnecting() async throws {
        let server = FakeETServer()
        let gate = TestPauseGate()
        let executor = GatedBootstrapExecutor(gate: gate)
        let session = ETTerminalSession(
            endpoint: TransportEndpoint(host: "in-memory", port: 2022),
            bootstrapExecutor: executor,
            transportFactory: InMemoryTransportFactory(server: server),
            configuration: ETConnectionConfiguration(
                reconnectDelay: .milliseconds(10),
                initializationTimeout: .seconds(1),
                keepAliveInterval: .seconds(10)
            )
        )
        let states = StateCollector()
        let stateTask = Task {
            for await state in session.stateChanges {
                await states.append(state)
            }
        }
        defer { stateTask.cancel() }

        let connectTask = Task { try await session.connect() }
        await gate.waitUntilPaused()
        let statesDuringBootstrap = await states.values()
        XCTAssertEqual(statesDuringBootstrap.prefix(2), [.idle, .bootstrapping])
        await gate.release()
        try await connectTask.value
        try await eventually {
            await states.values().contains(.connected)
        }
        let connectedStates = await states.values()
        XCTAssertEqual(
            Array(connectedStates.prefix(4)),
            [.idle, .bootstrapping, .connecting, .connected]
        )
        await session.close()
    }

    func testMismatchedProtocolIsTypedError() async throws {
        let server = FakeETServer(
            acceptance: .reject(.mismatchedProtocol, "server speaks another version")
        )
        let session = try makeSession(server: server)

        do {
            try await session.connect()
            XCTFail("Expected mismatched protocol")
        } catch {
            XCTAssertEqual(
                error as? ETClientError,
                .mismatchedProtocol("server speaks another version")
            )
        }
        await session.close()
    }

    func testInvalidKeyIsTypedError() async throws {
        let server = FakeETServer(acceptance: .reject(.invalidKey, "bad passkey"))
        let session = try makeSession(server: server)

        do {
            try await session.connect()
            XCTFail("Expected invalid key")
        } catch {
            XCTAssertEqual(error as? ETClientError, .invalidKey("bad passkey"))
        }
        await session.close()
    }

    func testReconnectReplaysCiphertextAfterDropsAtArbitraryOffsets() async throws {
        let server = FakeETServer()
        let session = try makeSession(
            server: server,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .seconds(10)
        )
        let outputCollector = OutputCollector()
        let outputTask = Task {
            for await bytes in session.output {
                await outputCollector.append(bytes)
            }
        }
        defer { outputTask.cancel() }

        try await session.connect()

        for (index, offset) in [1, 5, 19].enumerated() {
            let payload = Data("client-\(index)".utf8)
            await server.dropNextClientPacket(afterByteCount: offset)
            try await session.send(payload)
            try await eventually {
                let snapshot = await server.snapshot()
                return snapshot.terminalInput.filter { $0 == payload }.count == 1
            }
        }

        for (index, offset) in [1, 7, 23].enumerated() {
            let payload = Data("server-\(index)".utf8)
            try await server.sendTerminalOutput(payload, dropAfterByteCount: offset)
            try await eventually {
                await outputCollector.values().filter { $0 == payload }.count == 1
            }
        }

        let snapshot = await server.snapshot()
        let collectedOutput = await outputCollector.values()
        XCTAssertEqual(snapshot.terminalInput, (0..<3).map { Data("client-\($0)".utf8) })
        XCTAssertGreaterThanOrEqual(snapshot.connectionCount, 7)
        XCTAssertEqual(
            collectedOutput,
            (0..<3).map { Data("server-\($0)".utf8) }
        )
        await session.close()
    }

    func testDisconnectStateSequenceAndForcedReconnectPreserveCatchupData() async throws {
        let server = FakeETServer()
        let session = try makeSession(
            server: server,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .seconds(10)
        )
        let states = StateCollector()
        let stateTask = Task {
            for await state in session.stateChanges {
                await states.append(state)
            }
        }
        defer { stateTask.cancel() }

        try await session.connect()
        await session.notifyNetworkPathChanged()
        let duringRecovery = Data("nudge-catchup".utf8)
        try await session.send(duringRecovery)

        try await eventually {
            let snapshot = await server.snapshot()
            return snapshot.connectionCount >= 2
                && snapshot.terminalInput.filter { $0 == duringRecovery }.count == 1
        }
        try await eventually {
            let values = await states.values()
            return values.containsConsecutiveSubsequence([
                .connected,
                .disconnected,
                .reconnecting,
                .connected,
            ])
        }
        await session.close()
    }

    func testNetworkPathNudgeCancelsReconnectBackoff() async throws {
        let server = FakeETServer()
        let factory = ControlledTransportFactory(
            server: server,
            waitOnConnectionNumber: 2
        )
        let session = try makeSession(
            server: server,
            transportFactory: factory,
            reconnectDelay: .seconds(5),
            connectTimeout: .milliseconds(20),
            keepAliveInterval: .seconds(10)
        )
        try await session.connect()
        await server.disconnectClient()
        try await eventually {
            await factory.makeCount() == 2
        }
        try await Task.sleep(for: .milliseconds(40))

        await session.notifyNetworkPathChanged()

        try await eventually(timeout: .seconds(1)) {
            await factory.makeCount() >= 3
        }
        await session.close()
    }

    func testReconnectDoesNotLosePacketsDecodedDuringFailure() async throws {
        let readGate = TestPauseGate(armed: false)
        let server = FakeETServer()
        let factory = ControlledTransportFactory(server: server, firstReadGate: readGate)
        let session = try makeSession(
            server: server,
            transportFactory: factory,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .seconds(10)
        )
        let outputCollector = OutputCollector()
        let outputTask = Task {
            for await bytes in session.output {
                await outputCollector.append(bytes)
            }
        }
        defer { outputTask.cancel() }

        try await session.connect()
        await readGate.arm()
        let first = Data(repeating: 0x41, count: 2 * 1024 * 1024)
        let second = Data(repeating: 0x42, count: 2 * 1024 * 1024)
        try await server.sendTerminalOutputsUnchunked([first, second])
        await readGate.waitUntilPaused()
        await readGate.release()
        try await Task.sleep(for: .milliseconds(5))
        await server.disconnectClient()

        try await eventually(timeout: .seconds(5)) {
            await outputCollector.values().count == 2
        }
        try await eventually(timeout: .seconds(5)) {
            await server.snapshot().connectionCount >= 2
        }
        let collectedOutput = await outputCollector.values()
        let reconnectClientSequences = await server.snapshot().reconnectClientSequences
        XCTAssertEqual(collectedOutput, [first, second])
        XCTAssertEqual(reconnectClientSequences.last, 3)
        await session.close()
    }

    func testConnectTimeoutAndReconnectRetryDoNotHangOnWaitingTransport() async throws {
        let initialFactory = WaitingOnlyTransportFactory()
        let initialConnection = try ETConnection(
            endpoint: TransportEndpoint(host: "waiting", port: 2022),
            clientID: "test-client",
            passkey: key,
            transportFactory: initialFactory,
            configuration: ETConnectionConfiguration(connectTimeout: .milliseconds(20))
        )

        do {
            try await initialConnection.connect(initialPayload: Et_InitialPayload())
            XCTFail("Expected connect timeout")
        } catch {
            guard case .transportFailure = error as? ETClientError else {
                return XCTFail("Expected transportFailure, got \(error)")
            }
        }
        let initialMakeCount = await initialFactory.makeCount()
        XCTAssertEqual(initialMakeCount, 1)

        let server = FakeETServer()
        let reconnectFactory = ControlledTransportFactory(
            server: server,
            waitOnConnectionNumber: 2
        )
        let session = try makeSession(
            server: server,
            transportFactory: reconnectFactory,
            reconnectDelay: .seconds(1),
            connectTimeout: .milliseconds(20),
            keepAliveInterval: .seconds(10)
        )
        try await session.connect()
        await server.disconnectClient()

        try await eventually(timeout: .seconds(3)) {
            await reconnectFactory.makeCount() >= 3
        }
        await session.close()
    }

    func testPermanentReconnectFailureFullyTearsDownConnection() async throws {
        let reconnectGate = TestPauseGate()
        let server = FakeETServer(
            acceptance: .rejectReconnect(.invalidKey, "revoked passkey"),
            reconnectResponseGate: reconnectGate
        )
        let session = try makeSession(
            server: server,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .seconds(10)
        )
        let stateTask = Task {
            var states: [ETConnectionState] = []
            for await state in session.stateChanges {
                states.append(state)
            }
            return states
        }

        try await session.connect()
        await server.disconnectClient()
        await reconnectGate.waitUntilPaused()
        let pendingSend = Task {
            try await session.send(Data("pending".utf8))
        }
        await Task.yield()
        await reconnectGate.release()

        do {
            try await pendingSend.value
            XCTFail("Expected pending send to fail")
        } catch {
            XCTAssertEqual(error as? ETClientError, .connectionClosed)
        }
        let states = await stateTask.value
        XCTAssertEqual(states.last, .failed(.invalidKey("revoked passkey")))

        do {
            try await session.send(Data("after failure".utf8))
            XCTFail("Expected send after permanent failure to fail")
        } catch {
            XCTAssertEqual(error as? ETClientError, .connectionClosed)
        }
        await session.close()
    }

    func testHeartbeatUsesTerminalKeepAliveCadence() async throws {
        let server = FakeETServer(echoKeepAlives: true)
        let session = try makeSession(
            server: server,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .milliseconds(20)
        )
        try await session.connect()

        try await eventually(timeout: .seconds(1)) {
            await server.snapshot().keepAliveCount >= 3
        }
        let snapshot = await server.snapshot()
        XCTAssertEqual(snapshot.connectionCount, 1)
        await session.close()
    }

    func testMissingHeartbeatEchoDetectsHalfOpenConnection() async throws {
        let server = FakeETServer(echoKeepAlives: false)
        let session = try makeSession(
            server: server,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .milliseconds(20)
        )
        try await session.connect()

        try await eventually(timeout: .seconds(1)) {
            await server.snapshot().connectionCount >= 2
        }
        let snapshot = await server.snapshot()
        XCTAssertGreaterThanOrEqual(snapshot.keepAliveCount, 1)
        await session.close()
    }

    func testTunnelGrammarMatchesCppValidCases() throws {
        XCTAssertEqual(
            try ETTunnel.parse("1000:2000"),
            [
                ETTunnel(
                    source: .endpoint(.tcp(host: "localhost", port: 1000)),
                    destination: .tcp(host: nil, port: 2000)
                )
            ]
        )
        XCTAssertEqual(try ETTunnel.parse("8000-8002:9000-9002").count, 3)
        XCTAssertEqual(
            try ETTunnel.parse("SSH_AUTH_SOCK:/tmp/agent.sock"),
            [
                ETTunnel(
                    source: .environmentVariable("SSH_AUTH_SOCK"),
                    destination: .unix(path: "/tmp/agent.sock")
                )
            ]
        )
        XCTAssertEqual(
            try ETTunnel.parse("/tmp/local.sock:/tmp/remote.sock").first,
            ETTunnel(
                source: .endpoint(.unix(path: "/tmp/local.sock")),
                destination: .unix(path: "/tmp/remote.sock")
            )
        )
        XCTAssertEqual(
            try ETTunnel.parse("[::1]:8888:[2001:db8::1]:9999").first,
            ETTunnel(
                source: .endpoint(.tcp(host: "::1", port: 8888)),
                destination: .tcp(host: "2001:db8::1", port: 9999)
            )
        )
    }

    func testTunnelGrammarRejectsMalformedCasesWithTypedReasons() {
        let cases: [(String, ETTunnelParseReason)] = [
            ("", .emptySpecification),
            ("8080", .missingSourceOrDestination),
            ("abc:123", .invalidPort("abc")),
            ("8000-8001:9000", .rangePairRequired),
            ("8000-8002:9000-9001", .rangeLengthMismatch),
            ("9000-8000:9000-8000", .invalidRange("9000-8000")),
            ("8888:0.0.0.0:9999", .sshStyleRequiresFourParts),
            ("::1:8888:0.0.0.0:9999", .unbracketedIPv6),
        ]
        for (specification, reason) in cases {
            XCTAssertThrowsError(try ETTunnel.parse(specification)) { error in
                XCTAssertEqual(
                    error as? ETClientError,
                    .invalidTunnelSpecification(specification, reason)
                )
            }
        }
    }

    func testForwardTunnelEchoAndRemoteClose() async throws {
        let server = FakeETServer()
        let forwardingNetwork = InMemoryForwardingNetwork()
        let tunnel = try XCTUnwrap(ETTunnel.parse("7000:8000").first)
        let session = try makeSession(
            server: server,
            tunnels: [tunnel],
            forwardingNetwork: forwardingNetwork,
            keepAliveInterval: .seconds(10)
        )
        try await session.connect()

        let localSocket = try await forwardingNetwork.connectClient(
            to: .tcp(host: "localhost", port: 7000)
        )
        let payload = Data("forward-data".utf8)
        try await localSocket.write(payload)
        let echoedPayload = try await localSocket.read()
        XCTAssertEqual(echoedPayload, payload)

        try await eventually {
            await server.snapshot().forwardData == [payload]
        }
        try await server.closeForwardSocket()
        do {
            _ = try await localSocket.read()
            XCTFail("Expected remote close to tear down the local socket")
        } catch {
            XCTAssertEqual(error as? TransportError, .connectionClosed)
        }
        await session.close()
    }

    func testReverseTunnelEndToEndAndJumphostPayload() async throws {
        let server = FakeETServer()
        let forwardingNetwork = InMemoryForwardingNetwork()
        let reverseTunnel = try XCTUnwrap(ETTunnel.parse("9000:9100").first)
        let session = try makeSession(
            server: server,
            reverseTunnels: [reverseTunnel],
            jumphost: true,
            forwardingNetwork: forwardingNetwork,
            keepAliveInterval: .seconds(10)
        )
        try await session.connect()

        let snapshot = await server.snapshot()
        let initialPayload = try XCTUnwrap(snapshot.initialPayloads.first)
        XCTAssertTrue(initialPayload.jumphost)
        XCTAssertEqual(initialPayload.reversetunnels.count, 1)

        try await server.requestReverseDestination(
            reverseTunnel.destination.protobufEndpoint()
        )
        try await eventually {
            await server.snapshot().reverseSocketID != nil
        }
        let destinationSocket = try await eventuallyValue {
            await forwardingNetwork.takeDialedPeer(
                for: .tcp(host: nil, port: 9100)
            )
        }

        let inbound = Data("reverse-in".utf8)
        try await server.sendReverseData(inbound)
        let receivedInbound = try await destinationSocket.read()
        XCTAssertEqual(receivedInbound, inbound)

        let outbound = Data("reverse-out".utf8)
        try await destinationSocket.write(outbound)
        try await eventually {
            await server.snapshot().reverseData == [outbound]
        }
        await session.close()
    }

    func testReverseEnvironmentUnixSocketEndToEnd() async throws {
        let server = FakeETServer()
        let forwardingNetwork = InMemoryForwardingNetwork()
        let reverseTunnel = try XCTUnwrap(
            ETTunnel.parse("SSH_AUTH_SOCK:/tmp/local-agent.sock").first
        )
        let session = try makeSession(
            server: server,
            reverseTunnels: [reverseTunnel],
            forwardingNetwork: forwardingNetwork,
            keepAliveInterval: .seconds(10)
        )
        try await session.connect()

        let snapshot = await server.snapshot()
        let request = try XCTUnwrap(snapshot.initialPayloads.first?.reversetunnels.first)
        XCTAssertFalse(request.hasSource)
        XCTAssertEqual(request.environmentvariable, "SSH_AUTH_SOCK")
        XCTAssertEqual(request.destination.name, "/tmp/local-agent.sock")

        try await server.requestReverseDestination(request.destination)
        try await eventually {
            await server.snapshot().reverseSocketID != nil
        }
        let localSocket = try await eventuallyValue {
            await forwardingNetwork.takeDialedPeer(
                for: .unix(path: "/tmp/local-agent.sock")
            )
        }
        let inbound = Data("agent-request".utf8)
        try await server.sendReverseData(inbound)
        let receivedInbound = try await localSocket.read()
        XCTAssertEqual(receivedInbound, inbound)

        let outbound = Data("agent-response".utf8)
        try await localSocket.write(outbound)
        try await eventually {
            await server.snapshot().reverseData == [outbound]
        }
        await session.close()
    }

    func testForwardingTrafficRefreshesKeepAliveDeadline() async throws {
        let server = FakeETServer(echoKeepAlives: true)
        let forwardingNetwork = InMemoryForwardingNetwork()
        let tunnel = try XCTUnwrap(ETTunnel.parse("7100:8100").first)
        let session = try makeSession(
            server: server,
            tunnels: [tunnel],
            forwardingNetwork: forwardingNetwork,
            keepAliveInterval: .milliseconds(200)
        )
        try await session.connect()
        let localSocket = try await forwardingNetwork.connectClient(
            to: .tcp(host: "localhost", port: 7100)
        )

        for index in 0..<7 {
            let payload = Data("keepalive-\(index)".utf8)
            try await localSocket.write(payload)
            let echoedPayload = try await localSocket.read()
            XCTAssertEqual(echoedPayload, payload)
            try await Task.sleep(for: .milliseconds(50))
        }
        let keepAliveCountDuringTraffic = await server.snapshot().keepAliveCount
        XCTAssertEqual(keepAliveCountDuringTraffic, 0)
        try await eventually(timeout: .seconds(1)) {
            await server.snapshot().keepAliveCount >= 1
        }
        await session.close()
    }

    func testForwardDataSurvivesReconnectWhileSocketRemainsActive() async throws {
        let server = FakeETServer()
        let forwardingNetwork = InMemoryForwardingNetwork()
        let tunnel = try XCTUnwrap(ETTunnel.parse("7200:8200").first)
        let session = try makeSession(
            server: server,
            tunnels: [tunnel],
            forwardingNetwork: forwardingNetwork,
            reconnectDelay: .milliseconds(5),
            keepAliveInterval: .seconds(10)
        )
        try await session.connect()
        let localSocket = try await forwardingNetwork.connectClient(
            to: .tcp(host: "localhost", port: 7200)
        )

        let before = Data("before".utf8)
        try await localSocket.write(before)
        let echoedBefore = try await localSocket.read()
        XCTAssertEqual(echoedBefore, before)

        await server.dropNextClientPacket(afterByteCount: 5)
        let recovered = Data("through-reconnect".utf8)
        try await localSocket.write(recovered)
        let echoedRecovered = try await localSocket.read()
        XCTAssertEqual(echoedRecovered, recovered)

        try await eventually {
            let snapshot = await server.snapshot()
            return snapshot.connectionCount >= 2
                && snapshot.forwardData == [before, recovered]
        }
        await session.close()
    }

    private func makeSession(
        server: FakeETServer,
        tunnels: [ETTunnel] = [],
        reverseTunnels: [ETTunnel] = [],
        jumphost: Bool = false,
        forwardingNetwork: InMemoryForwardingNetwork? = nil,
        transportFactory: (any TransportFactory)? = nil,
        reconnectDelay: Duration = .milliseconds(10),
        connectTimeout: Duration = .seconds(5),
        keepAliveInterval: Duration = .seconds(1)
    ) throws -> ETTerminalSession {
        let listenerFactory: any ForwardingListenerFactory
        let socketFactory: any ForwardingSocketFactory
        if let forwardingNetwork {
            listenerFactory = forwardingNetwork
            socketFactory = forwardingNetwork
        } else {
            listenerFactory = SystemForwardingListenerFactory()
            socketFactory = SystemForwardingSocketFactory()
        }
        return try ETTerminalSession(
            endpoint: TransportEndpoint(host: "in-memory", port: 2022),
            clientID: "test-client",
            passkey: key,
            tunnels: tunnels,
            reverseTunnels: reverseTunnels,
            jumphost: jumphost,
            environmentVariables: ["TERM": "xterm-256color"],
            transportFactory: transportFactory ?? InMemoryTransportFactory(server: server),
            configuration: ETConnectionConfiguration(
                reconnectDelay: reconnectDelay,
                connectTimeout: connectTimeout,
                initializationTimeout: .seconds(1),
                keepAliveInterval: keepAliveInterval
            ),
            listenerFactory: listenerFactory,
            forwardingSocketFactory: socketFactory
        )
    }

    private func eventually(
        timeout: Duration = .seconds(2),
        condition: @escaping @Sendable () async -> Bool
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(2))
        }
        XCTFail("Condition was not satisfied before timeout")
    }

    private func eventuallyValue<Value: Sendable>(
        timeout: Duration = .seconds(2),
        value: @escaping @Sendable () async -> Value?
    ) async throws -> Value {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if let value = await value() { return value }
            try await Task.sleep(for: .milliseconds(2))
        }
        throw ETClientError.forwardingFailure("Timed out waiting for test value")
    }
}

private struct TerminalSize: Equatable, Sendable {
    let rows: Int32
    let columns: Int32
    let pixelWidth: Int32?
    let pixelHeight: Int32?

    init(
        rows: Int32,
        columns: Int32,
        pixelWidth: Int32? = nil,
        pixelHeight: Int32? = nil
    ) {
        self.rows = rows
        self.columns = columns
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
    }
}

private struct ServerSnapshot: Sendable {
    let connectionCount: Int
    let connectRequests: [Et_ConnectRequest]
    let initialPayloads: [Et_InitialPayload]
    let terminalInput: [Data]
    let terminalSizes: [TerminalSize]
    let keepAliveCount: Int
    let forwardData: [Data]
    let reverseData: [Data]
    let forwardSocketID: Int32?
    let reverseSocketID: Int32?
    let reconnectClientSequences: [Int32]
}

private actor OutputCollector {
    private var collected: [Data] = []

    func append(_ data: Data) {
        collected.append(data)
    }

    func values() -> [Data] {
        collected
    }
}

private actor StateCollector {
    private var states: [ETConnectionState] = []

    func append(_ state: ETConnectionState) {
        states.append(state)
    }

    func values() -> [ETConnectionState] {
        states
    }
}

private enum ServerAcceptance: Sendable {
    case normal
    case reject(Et_ConnectStatus, String)
    case rejectReconnect(Et_ConnectStatus, String)
}

private enum ServerPhase: Sendable {
    case connectRequest
    case initialPayload
    case clientSequence
    case clientCatchup(clientSequence: Int64)
    case active
    case rejected
}

private protocol InMemoryClientSink: Sendable {
    func deliver(_ data: Data) async
    func serverDisconnected() async
}

private actor FakeETServer {
    private let acceptance: ServerAcceptance
    private let echoKeepAlives: Bool
    private let reconnectResponseGate: TestPauseGate?
    private let responseChunkSizes = [1, 2, 5, 3, 8]
    private let key = Data("0123456789abcdefghijklmnopqrstuv".utf8)

    private var connectionCount = 0
    private var connectionID = 0
    private var sink: (any InMemoryClientSink)?
    private var phase: ServerPhase = .connectRequest
    private var framingBuffer = Data()
    private var reader: BackedReader?
    private var writer: BackedWriter?
    private var connectRequests: [Et_ConnectRequest] = []
    private var initialPayloads: [Et_InitialPayload] = []
    private var terminalInput: [Data] = []
    private var terminalSizes: [TerminalSize] = []
    private var keepAliveCount = 0
    private var clientDropOffset: Int?
    private var nextForwardSocketID: Int32 = 100
    private var forwardSocketIDs: Set<Int32> = []
    private var reverseSocketID: Int32?
    private var forwardData: [Data] = []
    private var reverseData: [Data] = []
    private var reconnectClientSequences: [Int32] = []

    init(
        acceptance: ServerAcceptance = .normal,
        echoKeepAlives: Bool = true,
        reconnectResponseGate: TestPauseGate? = nil
    ) {
        self.acceptance = acceptance
        self.echoKeepAlives = echoKeepAlives
        self.reconnectResponseGate = reconnectResponseGate
    }

    func accept(_ newSink: any InMemoryClientSink) -> Int {
        connectionCount += 1
        connectionID += 1
        sink = newSink
        phase = .connectRequest
        framingBuffer.removeAll(keepingCapacity: true)
        return connectionID
    }

    func receive(_ data: Data, connection id: Int) async throws {
        guard id == connectionID, sink != nil else {
            throw TransportError.connectionClosed
        }

        if case .active = phase, let offset = clientDropOffset {
            clientDropOffset = nil
            let acceptedCount = min(max(offset, 0), data.count)
            if acceptedCount > 0 {
                framingBuffer.append(data.prefix(acceptedCount))
                try await processBufferedBytes()
            }
            await disconnectCurrentConnection()
            throw TransportError.connectionClosed
        }

        framingBuffer.append(data)
        try await processBufferedBytes()
    }

    func clientClosed(connection id: Int) async {
        guard id == connectionID else { return }
        await invalidateProtocolIO()
        sink = nil
    }

    func dropNextClientPacket(afterByteCount offset: Int) {
        clientDropOffset = offset
    }

    func sendTerminalOutput(
        _ data: Data,
        dropAfterByteCount offset: Int? = nil
    ) async throws {
        var terminalBuffer = Et_TerminalBuffer()
        terminalBuffer.buffer = data
        let framed = try await makeServerPacket(
            header: UInt8(Et_TerminalPacketType.terminalBuffer.rawValue),
            payload: terminalBuffer.serializedData()
        )
        if let offset {
            let acceptedCount = min(max(offset, 0), framed.count)
            if acceptedCount > 0 {
                await sink?.deliver(Data(framed.prefix(acceptedCount)))
            }
            await disconnectCurrentConnection()
        } else {
            await deliverChunked(framed)
        }
    }

    func sendTerminalOutputsUnchunked(_ payloads: [Data]) async throws {
        var framedPackets = Data()
        for payload in payloads {
            var terminalBuffer = Et_TerminalBuffer()
            terminalBuffer.buffer = payload
            framedPackets.append(
                try await makeServerPacket(
                    header: UInt8(Et_TerminalPacketType.terminalBuffer.rawValue),
                    payload: terminalBuffer.serializedData()
                )
            )
        }
        await sink?.deliver(framedPackets)
    }

    func disconnectClient() async {
        await disconnectCurrentConnection()
    }

    func requestReverseDestination(_ endpoint: Et_SocketEndpoint) async throws {
        var request = Et_PortForwardDestinationRequest()
        request.destination = endpoint
        request.fd = 77
        try await sendPacket(
            header: .portForwardDestinationRequest,
            payload: request.serializedData()
        )
    }

    func sendReverseData(_ bytes: Data) async throws {
        guard let reverseSocketID else {
            throw ETClientError.forwardingFailure("Missing reverse socket id")
        }
        var data = Et_PortForwardData()
        data.socketid = reverseSocketID
        data.sourcetodestination = true
        data.buffer = bytes
        try await sendPacket(
            header: .portForwardData,
            payload: data.serializedData()
        )
    }

    func closeForwardSocket() async throws {
        guard let socketID = forwardSocketIDs.first else {
            throw ETClientError.forwardingFailure("Missing forward socket id")
        }
        var data = Et_PortForwardData()
        data.socketid = socketID
        data.sourcetodestination = false
        data.closed = true
        try await sendPacket(
            header: .portForwardData,
            payload: data.serializedData()
        )
        forwardSocketIDs.remove(socketID)
    }

    func snapshot() -> ServerSnapshot {
        ServerSnapshot(
            connectionCount: connectionCount,
            connectRequests: connectRequests,
            initialPayloads: initialPayloads,
            terminalInput: terminalInput,
            terminalSizes: terminalSizes,
            keepAliveCount: keepAliveCount,
            forwardData: forwardData,
            reverseData: reverseData,
            forwardSocketID: forwardSocketIDs.first,
            reverseSocketID: reverseSocketID,
            reconnectClientSequences: reconnectClientSequences
        )
    }

    private func processBufferedBytes() async throws {
        switch phase {
        case .connectRequest:
            guard let request = try takeProto(Et_ConnectRequest.self) else { return }
            connectRequests.append(request)
            var response = Et_ConnectResponse()
            switch acceptance {
            case .reject(let status, let message):
                response.status = status
                response.error = message
                phase = .rejected
            case .normal, .rejectReconnect(_, _):
                if reader == nil || writer == nil {
                    response.status = .newClient
                    reader = try BackedReader(
                        key: key,
                        nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
                    )
                    writer = try BackedWriter(
                        key: key,
                        nonceMostSignificantByte: SecretBox.serverToClientNonceMostSignificantByte
                    )
                    phase = .initialPayload
                } else {
                    if case .rejectReconnect(let status, let message) = acceptance {
                        await reconnectResponseGate?.pause()
                        response.status = status
                        response.error = message
                        phase = .rejected
                    } else {
                        response.status = .returningClient
                        phase = .clientSequence
                    }
                }
            }
            await deliverChunked(try frameProto(response))
            if !framingBuffer.isEmpty {
                try await processBufferedBytes()
            }

        case .initialPayload, .active:
            guard let reader else { throw TransportError.connectionClosed }
            let bytes = framingBuffer
            framingBuffer.removeAll(keepingCapacity: true)
            let packets = try await reader.receive(bytes)
            for packet in packets {
                try await handle(packet)
            }

        case .clientSequence:
            guard let clientSequence = try takeProto(Et_SequenceHeader.self) else { return }
            reconnectClientSequences.append(clientSequence.sequenceNumber)
            guard let reader else { throw TransportError.connectionClosed }
            let serverSequence = try await reader.sequenceHeader()
            phase = .clientCatchup(clientSequence: Int64(clientSequence.sequenceNumber))
            await deliverChunked(try frameProto(serverSequence))
            if !framingBuffer.isEmpty {
                try await processBufferedBytes()
            }

        case .clientCatchup(let clientSequence):
            guard let clientCatchup = try takeProto(Et_CatchupBuffer.self) else { return }
            guard let reader, let writer else { throw TransportError.connectionClosed }
            let serverCatchup = try await writer.catchupBuffer(after: clientSequence)
            await deliverChunked(try frameProto(serverCatchup))
            try await reader.revive(with: clientCatchup.buffer)
            await writer.revive()
            phase = .active
            let recovered = try await reader.receive()
            for packet in recovered {
                try await handle(packet)
            }
            if !framingBuffer.isEmpty {
                try await processBufferedBytes()
            }

        case .rejected:
            return
        }
    }

    private func handle(_ packet: Packet) async throws {
        switch packet.header {
        case UInt8(Et_EtPacketType.initialPayload.rawValue):
            initialPayloads.append(try Et_InitialPayload(serializedBytes: packet.payload))
            var response = Et_InitialResponse()
            response.error = ""
            phase = .active
            let framed = try await makeServerPacket(
                header: UInt8(Et_EtPacketType.initialResponse.rawValue),
                payload: response.serializedData()
            )
            await deliverChunked(framed)

        case UInt8(Et_TerminalPacketType.terminalBuffer.rawValue):
            let terminalBuffer = try Et_TerminalBuffer(serializedBytes: packet.payload)
            terminalInput.append(terminalBuffer.buffer)

        case UInt8(Et_TerminalPacketType.terminalInfo.rawValue):
            let terminalInfo = try Et_TerminalInfo(serializedBytes: packet.payload)
            terminalSizes.append(
                TerminalSize(
                    rows: terminalInfo.row,
                    columns: terminalInfo.column,
                    pixelWidth: terminalInfo.hasWidth ? terminalInfo.width : nil,
                    pixelHeight: terminalInfo.hasHeight ? terminalInfo.height : nil
                )
            )

        case UInt8(Et_TerminalPacketType.keepAlive.rawValue):
            keepAliveCount += 1
            if echoKeepAlives {
                let framed = try await makeServerPacket(
                    header: UInt8(Et_TerminalPacketType.keepAlive.rawValue),
                    payload: Data()
                )
                await deliverChunked(framed)
            }

        case UInt8(Et_TerminalPacketType.portForwardDestinationRequest.rawValue):
            let request = try Et_PortForwardDestinationRequest(
                serializedBytes: packet.payload
            )
            let socketID = nextForwardSocketID
            nextForwardSocketID = nextForwardSocketID == Int32.max
                ? 100
                : nextForwardSocketID + 1
            forwardSocketIDs.insert(socketID)
            var response = Et_PortForwardDestinationResponse()
            response.clientfd = request.fd
            response.socketid = socketID
            try await sendPacket(
                header: .portForwardDestinationResponse,
                payload: response.serializedData()
            )

        case UInt8(Et_TerminalPacketType.portForwardDestinationResponse.rawValue):
            let response = try Et_PortForwardDestinationResponse(
                serializedBytes: packet.payload
            )
            guard !response.hasError else {
                throw ETClientError.forwardingFailure(response.error)
            }
            reverseSocketID = response.socketid

        case UInt8(Et_TerminalPacketType.portForwardData.rawValue):
            let data = try Et_PortForwardData(serializedBytes: packet.payload)
            if forwardSocketIDs.contains(data.socketid), data.sourcetodestination {
                if data.hasBuffer {
                    forwardData.append(data.buffer)
                }
                var echo = data
                echo.sourcetodestination = false
                try await sendPacket(
                    header: .portForwardData,
                    payload: echo.serializedData()
                )
                if data.hasClosed || data.hasError {
                    forwardSocketIDs.remove(data.socketid)
                }
            } else if data.socketid == reverseSocketID, !data.sourcetodestination {
                if data.hasBuffer {
                    reverseData.append(data.buffer)
                }
            }

        default:
            throw ETClientError.malformedFrame("Unexpected client packet \(packet.header)")
        }
    }

    private func makeServerPacket(header: UInt8, payload: Data) async throws -> Data {
        guard let writer else { throw TransportError.connectionClosed }
        let result = try await writer.write(Packet(header: header, payload: payload))
        guard result.state == .success, let framed = result.framedBytes else {
            throw TransportError.connectionClosed
        }
        return framed
    }

    private func sendPacket(
        header: Et_TerminalPacketType,
        payload: Data
    ) async throws {
        let framed = try await makeServerPacket(
            header: UInt8(header.rawValue),
            payload: payload
        )
        await deliverChunked(framed)
    }

    private func disconnectCurrentConnection() async {
        let currentSink = sink
        await invalidateProtocolIO()
        sink = nil
        await currentSink?.serverDisconnected()
    }

    private func invalidateProtocolIO() async {
        await reader?.invalidate()
        await writer?.invalidate()
    }

    private func deliverChunked(_ data: Data) async {
        guard let sink else { return }
        var offset = 0
        var sizeIndex = 0
        while offset < data.count {
            let count = min(responseChunkSizes[sizeIndex % responseChunkSizes.count], data.count - offset)
            await sink.deliver(Data(data[offset..<(offset + count)]))
            offset += count
            sizeIndex += 1
        }
    }

    private func frameProto<Message: SwiftProtobuf.Message>(_ message: Message) throws -> Data {
        let payload = try message.serializedData()
        var data = Data(capacity: 8 + payload.count)
        let length = UInt64(payload.count)
        for index in 0..<8 {
            data.append(UInt8(truncatingIfNeeded: length >> UInt64(index * 8)))
        }
        data.append(payload)
        return data
    }

    private func takeProto<Message: SwiftProtobuf.Message>(
        _ type: Message.Type
    ) throws -> Message? {
        guard framingBuffer.count >= 8 else { return nil }
        var length: UInt64 = 0
        for index in 0..<8 {
            length |= UInt64(framingBuffer[framingBuffer.startIndex + index]) << UInt64(index * 8)
        }
        guard let payloadLength = Int(exactly: length), payloadLength <= 128 * 1024 * 1024 else {
            throw ETClientError.malformedFrame("Invalid test protobuf frame")
        }
        let totalLength = 8 + payloadLength
        guard framingBuffer.count >= totalLength else { return nil }
        let payload = Data(framingBuffer.dropFirst(8).prefix(payloadLength))
        framingBuffer.removeFirst(totalLength)
        return try Message(serializedBytes: payload)
    }
}

private actor TestPauseGate {
    private var isArmed: Bool
    private var isPaused = false
    private var pauseWaiter: CheckedContinuation<Void, Never>?
    private var observers: [CheckedContinuation<Void, Never>] = []

    init(armed: Bool = true) {
        isArmed = armed
    }

    func arm() {
        isArmed = true
    }

    func pause() async {
        guard isArmed else { return }
        isArmed = false
        isPaused = true
        let currentObservers = observers
        observers.removeAll()
        for observer in currentObservers {
            observer.resume()
        }
        await withCheckedContinuation { continuation in
            pauseWaiter = continuation
        }
        isPaused = false
    }

    func waitUntilPaused() async {
        guard !isPaused else { return }
        await withCheckedContinuation { continuation in
            observers.append(continuation)
        }
    }

    func release() {
        let waiter = pauseWaiter
        pauseWaiter = nil
        waiter?.resume()
    }
}

private actor GatedBootstrapExecutor: ETBootstrapExecutor {
    private let gate: TestPauseGate

    init(gate: TestPauseGate) {
        self.gate = gate
    }

    func run(command: String) async -> String {
        _ = command
        await gate.pause()
        return "IDPASSKEY:abcdefghijklmnop/0123456789abcdefghijklmnopqrstuv"
    }
}

private actor WaitingOnlyTransportFactory: TransportFactory {
    private var count = 0

    func makeTransport() -> any Transport {
        count += 1
        return WaitingTransport()
    }

    func makeCount() -> Int {
        count
    }
}

private actor ControlledTransportFactory: TransportFactory {
    private let server: FakeETServer
    private let firstReadGate: TestPauseGate?
    private let waitOnConnectionNumber: Int?
    private var count = 0

    init(
        server: FakeETServer,
        firstReadGate: TestPauseGate? = nil,
        waitOnConnectionNumber: Int? = nil
    ) {
        self.server = server
        self.firstReadGate = firstReadGate
        self.waitOnConnectionNumber = waitOnConnectionNumber
    }

    func makeTransport() -> any Transport {
        count += 1
        if count == waitOnConnectionNumber {
            return WaitingTransport()
        }
        return InMemoryTransport(
            server: server,
            readGate: count == 1 ? firstReadGate : nil
        )
    }

    func makeCount() -> Int {
        count
    }
}

private actor WaitingTransport: Transport {
    nonisolated let stateChanges: AsyncStream<TransportState>

    private let stateContinuation: AsyncStream<TransportState>.Continuation
    private var connectContinuation: CheckedContinuation<Void, any Error>?
    private var isClosed = false

    init() {
        let pair = AsyncStream<TransportState>.makeStream(
            bufferingPolicy: .bufferingNewest(8)
        )
        stateChanges = pair.stream
        stateContinuation = pair.continuation
        stateContinuation.yield(.idle)
    }

    func connect(to endpoint: TransportEndpoint) async throws {
        _ = endpoint
        guard !isClosed else { throw TransportError.connectionClosed }
        stateContinuation.yield(.connecting)
        stateContinuation.yield(.waiting)
        try await withCheckedThrowingContinuation { continuation in
            connectContinuation = continuation
        }
    }

    func read() async throws -> Data {
        throw TransportError.connectionClosed
    }

    func write(_ data: Data) async throws {
        _ = data
        throw TransportError.connectionClosed
    }

    func close() {
        guard !isClosed else { return }
        isClosed = true
        let continuation = connectContinuation
        connectContinuation = nil
        continuation?.resume(throwing: TransportError.connectionClosed)
        stateContinuation.yield(.closed)
        stateContinuation.finish()
    }
}

private struct InMemoryTransportFactory: TransportFactory {
    let server: FakeETServer

    func makeTransport() async -> any Transport {
        InMemoryTransport(server: server)
    }
}

private actor InMemoryTransport: Transport, InMemoryClientSink {
    nonisolated let stateChanges: AsyncStream<TransportState>

    private let stateContinuation: AsyncStream<TransportState>.Continuation
    private let server: FakeETServer
    private let readGate: TestPauseGate?
    private let incoming = AsyncDataQueue()
    private var connectionID: Int?
    private var isOpen = false

    init(server: FakeETServer, readGate: TestPauseGate? = nil) {
        self.server = server
        self.readGate = readGate
        let pair = AsyncStream<TransportState>.makeStream(
            bufferingPolicy: .bufferingNewest(8)
        )
        stateChanges = pair.stream
        stateContinuation = pair.continuation
        stateContinuation.yield(.idle)
    }

    func connect(to endpoint: TransportEndpoint) async throws {
        guard !isOpen else { throw TransportError.alreadyConnected }
        stateContinuation.yield(.connecting)
        connectionID = await server.accept(self)
        isOpen = true
        stateContinuation.yield(.ready)
    }

    func read() async throws -> Data {
        guard isOpen else { throw TransportError.connectionClosed }
        let data = try await incoming.next()
        await readGate?.pause()
        return data
    }

    func write(_ data: Data) async throws {
        guard isOpen, let connectionID else { throw TransportError.connectionClosed }
        try await server.receive(data, connection: connectionID)
    }

    func close() async {
        guard isOpen else { return }
        isOpen = false
        let currentID = connectionID
        connectionID = nil
        await incoming.fail()
        stateContinuation.yield(.closed)
        stateContinuation.finish()
        if let currentID {
            await server.clientClosed(connection: currentID)
        }
    }

    func deliver(_ data: Data) async {
        guard isOpen else { return }
        await incoming.push(data)
    }

    func serverDisconnected() async {
        guard isOpen else { return }
        isOpen = false
        connectionID = nil
        await incoming.fail()
        stateContinuation.yield(.failed("Server disconnected"))
        stateContinuation.finish()
    }
}

private actor AsyncDataQueue {
    private var buffered: [Data] = []
    private var waiter: CheckedContinuation<Data, any Error>?
    private var isClosed = false

    func next() async throws -> Data {
        if !buffered.isEmpty {
            return buffered.removeFirst()
        }
        if isClosed {
            throw TransportError.connectionClosed
        }
        return try await withCheckedThrowingContinuation { continuation in
            waiter = continuation
        }
    }

    func push(_ data: Data) {
        guard !isClosed else { return }
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: data)
        } else {
            buffered.append(data)
        }
    }

    func fail() {
        guard !isClosed else { return }
        isClosed = true
        let currentWaiter = waiter
        waiter = nil
        currentWaiter?.resume(throwing: TransportError.connectionClosed)
    }
}

private enum ForwardingEndpointKey: Hashable, Sendable {
    case tcp(UInt16)
    case unix(String)

    init(_ endpoint: ETTunnelEndpoint) {
        switch endpoint {
        case .tcp(_, let port):
            self = .tcp(port)
        case .unix(let path):
            self = .unix(path)
        }
    }
}

private actor InMemoryForwardingNetwork: ForwardingListenerFactory, ForwardingSocketFactory {
    private var listeners: [ForwardingEndpointKey: InMemoryForwardingListener] = [:]
    private var dialedPeers: [ForwardingEndpointKey: [InMemoryForwardingSocket]] = [:]

    func makeListener(
        for endpoint: ETTunnelEndpoint
    ) async throws -> any ForwardingListener {
        let key = ForwardingEndpointKey(endpoint)
        guard listeners[key] == nil else {
            throw ETClientError.forwardingFailure("Duplicate test listener")
        }
        let listener = InMemoryForwardingListener()
        listeners[key] = listener
        return listener
    }

    func connect(
        to endpoint: ETTunnelEndpoint
    ) async throws -> any ForwardingSocket {
        let pair = InMemoryForwardingSocket.makePair()
        dialedPeers[ForwardingEndpointKey(endpoint), default: []].append(pair.peer)
        return pair.local
    }

    func connectClient(to endpoint: ETTunnelEndpoint) async throws -> InMemoryForwardingSocket {
        guard let listener = listeners[ForwardingEndpointKey(endpoint)] else {
            throw ETClientError.forwardingFailure("Missing test listener")
        }
        let pair = InMemoryForwardingSocket.makePair()
        try await listener.enqueue(pair.peer)
        return pair.local
    }

    func takeDialedPeer(for endpoint: ETTunnelEndpoint) -> InMemoryForwardingSocket? {
        let key = ForwardingEndpointKey(endpoint)
        guard var peers = dialedPeers[key], !peers.isEmpty else { return nil }
        let peer = peers.removeFirst()
        dialedPeers[key] = peers
        return peer
    }
}

private actor InMemoryForwardingListener: ForwardingListener {
    private let queue = AsyncForwardingSocketQueue()
    private var isStarted = false
    private var isClosed = false

    func start() throws {
        guard !isClosed else { throw TransportError.connectionClosed }
        isStarted = true
    }

    func accept() async throws -> any ForwardingSocket {
        guard isStarted, !isClosed else { throw TransportError.connectionClosed }
        return try await queue.next()
    }

    func enqueue(_ socket: any ForwardingSocket) async throws {
        guard isStarted, !isClosed else { throw TransportError.connectionClosed }
        await queue.push(socket)
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        await queue.fail()
    }
}

private actor InMemoryForwardingSocket: ForwardingSocket {
    private let incoming: AsyncDataQueue
    private let peerIncoming: AsyncDataQueue
    private var isClosed = false

    init(incoming: AsyncDataQueue, peerIncoming: AsyncDataQueue) {
        self.incoming = incoming
        self.peerIncoming = peerIncoming
    }

    static func makePair() -> (
        local: InMemoryForwardingSocket,
        peer: InMemoryForwardingSocket
    ) {
        let firstIncoming = AsyncDataQueue()
        let secondIncoming = AsyncDataQueue()
        return (
            InMemoryForwardingSocket(
                incoming: firstIncoming,
                peerIncoming: secondIncoming
            ),
            InMemoryForwardingSocket(
                incoming: secondIncoming,
                peerIncoming: firstIncoming
            )
        )
    }

    func read() async throws -> Data {
        guard !isClosed else { throw TransportError.connectionClosed }
        return try await incoming.next()
    }

    func write(_ data: Data) async throws {
        guard !isClosed else { throw TransportError.connectionClosed }
        await peerIncoming.push(data)
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        await incoming.fail()
        await peerIncoming.fail()
    }
}

private actor AsyncForwardingSocketQueue {
    private var buffered: [any ForwardingSocket] = []
    private var waiter: CheckedContinuation<any ForwardingSocket, any Error>?
    private var isClosed = false

    func next() async throws -> any ForwardingSocket {
        if !buffered.isEmpty {
            return buffered.removeFirst()
        }
        guard !isClosed else { throw TransportError.connectionClosed }
        return try await withCheckedThrowingContinuation { continuation in
            waiter = continuation
        }
    }

    func push(_ socket: any ForwardingSocket) async {
        guard !isClosed else {
            await socket.close()
            return
        }
        if let waiter {
            self.waiter = nil
            waiter.resume(returning: socket)
        } else {
            buffered.append(socket)
        }
    }

    func fail() async {
        guard !isClosed else { return }
        isClosed = true
        let currentWaiter = waiter
        waiter = nil
        currentWaiter?.resume(throwing: TransportError.connectionClosed)
        let sockets = buffered
        buffered.removeAll()
        for socket in sockets {
            await socket.close()
        }
    }
}

private extension Array where Element: Equatable {
    func containsConsecutiveSubsequence(_ subsequence: [Element]) -> Bool {
        guard !subsequence.isEmpty else { return true }
        guard count >= subsequence.count else { return false }
        for start in 0...(count - subsequence.count) {
            if Array(self[start..<(start + subsequence.count)]) == subsequence {
                return true
            }
        }
        return false
    }
}
