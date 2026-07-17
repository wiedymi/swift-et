@testable import ETClient
import ETProtocol
import Foundation
import SwiftProtobuf
import XCTest

@MainActor
final class ETClientTests: XCTestCase {
    private let key = Data((0..<32).map(UInt8.init))

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

    private func makeSession(
        server: FakeETServer,
        reconnectDelay: Duration = .milliseconds(10),
        keepAliveInterval: Duration = .seconds(1)
    ) throws -> ETTerminalSession {
        try ETTerminalSession(
            endpoint: TransportEndpoint(host: "in-memory", port: 2022),
            clientID: "test-client",
            passkey: key,
            environmentVariables: ["TERM": "xterm-256color"],
            transportFactory: InMemoryTransportFactory(server: server),
            configuration: ETConnectionConfiguration(
                reconnectDelay: reconnectDelay,
                initializationTimeout: .seconds(1),
                keepAliveInterval: keepAliveInterval
            )
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
}

private struct TerminalSize: Equatable, Sendable {
    let rows: Int32
    let columns: Int32
}

private struct ServerSnapshot: Sendable {
    let connectionCount: Int
    let connectRequests: [Et_ConnectRequest]
    let initialPayloads: [Et_InitialPayload]
    let terminalInput: [Data]
    let terminalSizes: [TerminalSize]
    let keepAliveCount: Int
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

private enum ServerAcceptance: Sendable {
    case normal
    case reject(Et_ConnectStatus, String)
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
    private let responseChunkSizes = [1, 2, 5, 3, 8]
    private let key = Data((0..<32).map(UInt8.init))

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

    init(
        acceptance: ServerAcceptance = .normal,
        echoKeepAlives: Bool = true
    ) {
        self.acceptance = acceptance
        self.echoKeepAlives = echoKeepAlives
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

    func snapshot() -> ServerSnapshot {
        ServerSnapshot(
            connectionCount: connectionCount,
            connectRequests: connectRequests,
            initialPayloads: initialPayloads,
            terminalInput: terminalInput,
            terminalSizes: terminalSizes,
            keepAliveCount: keepAliveCount
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
            case .normal:
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
                    response.status = .returningClient
                    phase = .clientSequence
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
                TerminalSize(rows: terminalInfo.row, columns: terminalInfo.column)
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
    private let incoming = AsyncDataQueue()
    private var connectionID: Int?
    private var isOpen = false

    init(server: FakeETServer) {
        self.server = server
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
        return try await incoming.next()
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
