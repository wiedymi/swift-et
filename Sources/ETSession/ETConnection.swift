import ETCore
import ETCrypto
import ETTransport
import Foundation
import SwiftProtobuf

/// Public failures raised by session setup, transport, and forwarding operations.
public enum ETClientError: Error, Equatable, Sendable {
    /// A secretbox passkey was not 32 bytes.
    case invalidPasskeyLength(actual: Int)
    /// The server rejected the passkey.
    case invalidKey(String)
    /// The server rejected protocol version 6.
    case mismatchedProtocol(String)
    /// The server returned an invalid status for the current lifecycle phase.
    case unexpectedConnectStatus(Et_ConnectStatus, String)
    /// The encrypted initial exchange failed.
    case initializationFailed(String)
    /// A length-prefixed protobuf frame was invalid.
    case malformedFrame(String)
    /// The transport failed.
    case transportFailure(String)
    /// The disconnected reliable buffer is full.
    case disconnectedBufferFull
    /// A connect operation is already running.
    case connectionInProgress
    /// The session has closed permanently.
    case connectionClosed
    /// Terminal rows or columns were invalid or exceeded Int32.
    case invalidTerminalSize(rows: Int, columns: Int)
    /// Pixel dimensions were negative or exceeded Int32.
    case invalidTerminalPixels(width: Int?, height: Int?)
    /// A tunnel string was invalid.
    case invalidTunnelSpecification(String, ETTunnelParseReason)
    /// A forwarding socket or listener failed.
    case forwardingFailure(String)
    /// Recovery can never succeed for this session: the peer requested catchup
    /// history that is no longer retained, or the wire sequence ceiling was hit.
    /// The session fails permanently instead of retrying; start a new session.
    case sessionUnrecoverable(String)
}

/// Observable lifecycle state for an Eternal Terminal session.
public enum ETConnectionState: Equatable, Sendable {
    /// No connection work has started.
    case idle
    /// The consumer-provided bootstrap executor is running.
    case bootstrapping
    /// A TCP connection or initial handshake is in progress.
    case connecting
    /// The encrypted session is active.
    case connected
    /// The active transport was lost and has been torn down.
    case disconnected
    /// Recovery attempts are in progress or waiting for retry.
    case reconnecting
    /// A nonrecoverable error ended the session.
    case failed(ETClientError)
    /// The consumer closed the session.
    case closed
}

struct ETConnectionConfiguration: Sendable {
    var reconnectDelay: Duration = .seconds(1)
    var connectTimeout: Duration = .seconds(5)
    var initializationTimeout: Duration = .seconds(3)
    var keepAliveInterval: Duration = .seconds(5)
}

actor ETConnection {
    static let protocolVersion: Int32 = 6

    nonisolated let packets: AsyncStream<Packet>
    nonisolated let stateChanges: AsyncStream<ETConnectionState>

    private let packetContinuation: AsyncStream<Packet>.Continuation
    private let stateContinuation: AsyncStream<ETConnectionState>.Continuation
    private let endpoint: TransportEndpoint
    private let clientID: String
    private let passkey: SecretKey
    private let transportFactory: any TransportFactory
    private let configuration: ETConnectionConfiguration

    private var state: ETConnectionState = .idle
    private var transport: (any Transport)?
    private var pendingTransport: (any Transport)?
    private var reader: BackedReader?
    private var writer: BackedWriter?
    private var generation: UInt64 = 0
    private var readTask: Task<Void, Never>?
    private var stateTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private var reconnectBackoffTask: Task<Void, Never>?
    private var heartbeatTask: Task<Void, Never>?
    private var writeDrainTask: Task<Void, Never>?
    private var waitingOnKeepAlive = false
    private var isClosed = false
    private var pendingWrites: [PendingWrite] = []
    private var isDrainingWrites = false
    private var isRecovering = false
    private var writeDrainWaiters: [CheckedContinuation<Void, Never>] = []

    init(
        endpoint: TransportEndpoint,
        clientID: String,
        passkey: Data,
        transportFactory: any TransportFactory = NWTransportFactory(),
        configuration: ETConnectionConfiguration = ETConnectionConfiguration()
    ) throws {
        guard passkey.count == 32 else {
            throw ETClientError.invalidPasskeyLength(actual: passkey.count)
        }

        let packetPair = AsyncStream<Packet>.makeStream(bufferingPolicy: .unbounded)
        packets = packetPair.stream
        packetContinuation = packetPair.continuation

        let statePair = AsyncStream<ETConnectionState>.makeStream(
            bufferingPolicy: .bufferingNewest(16)
        )
        stateChanges = statePair.stream
        stateContinuation = statePair.continuation
        stateContinuation.yield(.idle)

        self.endpoint = endpoint
        self.clientID = clientID
        self.passkey = SecretKey(passkey)
        self.transportFactory = transportFactory
        self.configuration = configuration
    }

    func connect(initialPayload: Et_InitialPayload) async throws {
        guard !isClosed else { throw ETClientError.connectionClosed }
        guard state == .idle else { return }

        updateState(.connecting)
        let newTransport = await transportFactory.makeTransport()
        pendingTransport = newTransport

        do {
            try await connect(newTransport)
            var framingBuffer = Data()
            let response = try await exchangeConnectRequest(
                over: newTransport,
                framingBuffer: &framingBuffer
            )
            try validateInitial(response)

            let newReader = try BackedReader(
                key: passkey,
                nonceMostSignificantByte: SecretBox.serverToClientNonceMostSignificantByte
            )
            let newWriter = try BackedWriter(
                key: passkey,
                nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
            )
            reader = newReader
            writer = newWriter

            try await sendInitialPayload(initialPayload, over: newTransport, writer: newWriter)
            try await receiveInitialResponse(
                over: newTransport,
                reader: newReader,
                bufferedBytes: framingBuffer
            )
            guard !isClosed else { throw ETClientError.connectionClosed }
            pendingTransport = nil
            activate(newTransport)
        } catch {
            pendingTransport = nil
            await newTransport.close()
            reader = nil
            writer = nil
            transport = nil
            guard !isClosed else { throw ETClientError.connectionClosed }
            let clientError = mapError(error)
            updateState(.failed(clientError))
            throw clientError
        }
    }

    func send(_ packet: Packet) async throws {
        guard !isClosed else { throw ETClientError.connectionClosed }
        guard writer != nil else { throw ETClientError.connectionClosed }

        try await withCheckedThrowingContinuation { continuation in
            pendingWrites.append(PendingWrite(packet: packet, continuation: continuation))
            startWriteDrainIfNeeded()
        }
        if state == .connected,
           packet.header != UInt8(Et_TerminalPacketType.keepAlive.rawValue),
           packet.header != UInt8(Et_EtPacketType.heartbeat.rawValue) {
            startHeartbeat(generation: generation)
        }
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        generation &+= 1
        readTask?.cancel()
        stateTask?.cancel()
        reconnectTask?.cancel()
        reconnectBackoffTask?.cancel()
        heartbeatTask?.cancel()
        writeDrainTask?.cancel()
        readTask = nil
        stateTask = nil
        reconnectTask = nil
        reconnectBackoffTask = nil
        heartbeatTask = nil
        writeDrainTask = nil

        await reader?.invalidate()
        await writer?.invalidate()
        let currentTransport = transport
        transport = nil
        let currentPendingTransport = pendingTransport
        pendingTransport = nil
        await currentTransport?.close()
        await currentPendingTransport?.close()

        let writes = pendingWrites
        pendingWrites.removeAll()
        for write in writes {
            write.continuation.resume(throwing: ETClientError.connectionClosed)
        }
        packetContinuation.finish()
        updateState(.closed)
        stateContinuation.finish()
    }

    func notifyNetworkPathChanged() async {
        switch state {
        case .connected:
            await connectionDidFail(generation: generation)
        case .reconnecting:
            reconnectBackoffTask?.cancel()
        case .idle, .bootstrapping, .connecting, .disconnected, .failed, .closed:
            return
        }
    }

    private func exchangeConnectRequest(
        over transport: any Transport,
        framingBuffer: inout Data
    ) async throws -> Et_ConnectResponse {
        var request = Et_ConnectRequest()
        request.clientID = clientID
        request.version = Self.protocolVersion
        try await writeProto(request, over: transport)
        return try await readProto(
            Et_ConnectResponse.self,
            over: transport,
            buffer: &framingBuffer
        )
    }

    private func validateInitial(_ response: Et_ConnectResponse) throws {
        switch response.status {
        case .newClient, .returningClient:
            return
        case .invalidKey:
            throw ETClientError.invalidKey(response.error)
        case .mismatchedProtocol:
            throw ETClientError.mismatchedProtocol(response.error)
        }
    }

    private func validateReconnect(_ response: Et_ConnectResponse) throws {
        switch response.status {
        case .returningClient:
            return
        case .invalidKey:
            throw ETClientError.invalidKey(response.error)
        case .mismatchedProtocol:
            throw ETClientError.mismatchedProtocol(response.error)
        case .newClient:
            throw ETClientError.unexpectedConnectStatus(response.status, response.error)
        }
    }

    private func sendInitialPayload(
        _ payload: Et_InitialPayload,
        over transport: any Transport,
        writer: BackedWriter
    ) async throws {
        let packet = Packet(
            header: UInt8(Et_EtPacketType.initialPayload.rawValue),
            payload: try payload.serializedData()
        )
        let write = try await writer.write(packet)
        guard write.state == .success, let framedBytes = write.framedBytes else {
            throw ETClientError.connectionClosed
        }
        try await transport.write(framedBytes)
    }

    private func receiveInitialResponse(
        over transport: any Transport,
        reader: BackedReader,
        bufferedBytes: Data
    ) async throws {
        let timeoutTask = Task { [duration = configuration.initializationTimeout] in
            try await Task.sleep(for: duration)
            await transport.close()
        }
        defer { timeoutTask.cancel() }

        var bytes = bufferedBytes
        while true {
            let receivedPackets = try await reader.receive(bytes)
            bytes = Data()
            var foundInitialResponse = false
            for packet in receivedPackets {
                if foundInitialResponse {
                    packetContinuation.yield(packet)
                } else if packet.header == UInt8(Et_EtPacketType.initialResponse.rawValue) {
                    let response = try Et_InitialResponse(serializedBytes: packet.payload)
                    guard response.error.isEmpty else {
                        throw ETClientError.initializationFailed(response.error)
                    }
                    foundInitialResponse = true
                } else {
                    packetContinuation.yield(packet)
                }
            }
            if foundInitialResponse { return }
            bytes = try await transport.read()
        }
    }

    private func activate(_ activeTransport: any Transport) {
        generation &+= 1
        let activeGeneration = generation
        transport = activeTransport
        waitingOnKeepAlive = false
        reconnectTask = nil
        updateState(.connected)

        readTask?.cancel()
        readTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    let bytes = try await activeTransport.read()
                    guard !bytes.isEmpty else { continue }
                    await self?.receive(bytes, generation: activeGeneration)
                } catch is CancellationError {
                    return
                } catch {
                    await self?.connectionDidFail(generation: activeGeneration)
                    return
                }
            }
        }

        stateTask?.cancel()
        let transportStates = activeTransport.stateChanges
        stateTask = Task { [weak self] in
            for await transportState in transportStates {
                guard !Task.isCancelled else { return }
                switch transportState {
                case .failed:
                    await self?.connectionDidFail(generation: activeGeneration)
                    return
                case .closed:
                    await self?.connectionDidFail(generation: activeGeneration)
                    return
                case .idle, .connecting, .ready, .waiting:
                    continue
                }
            }
        }

        startHeartbeat(generation: activeGeneration)
        startWriteDrainIfNeeded()
    }

    private func receive(_ bytes: Data, generation receivedGeneration: UInt64) async {
        guard receivedGeneration == generation, !isClosed, let reader else { return }
        do {
            let receivedPackets = try await reader.receive(bytes)
            guard !isClosed else { return }
            let isCurrentConnection = receivedGeneration == generation && state == .connected
            for packet in receivedPackets {
                if packet.header == UInt8(Et_TerminalPacketType.keepAlive.rawValue)
                    || packet.header == UInt8(Et_EtPacketType.heartbeat.rawValue) {
                    if isCurrentConnection {
                        waitingOnKeepAlive = false
                    }
                } else {
                    if isCurrentConnection {
                        startHeartbeat(generation: receivedGeneration)
                    }
                    packetContinuation.yield(packet)
                }
            }
        } catch {
            await connectionDidFail(generation: receivedGeneration)
        }
    }

    private func startHeartbeat(generation heartbeatGeneration: UInt64) {
        heartbeatTask?.cancel()
        heartbeatTask = Task { [weak self, interval = configuration.keepAliveInterval] in
            do {
                try await Task.sleep(for: interval)
            } catch {
                return
            }
            await self?.heartbeatTick(generation: heartbeatGeneration)
        }
    }

    private func heartbeatTick(generation heartbeatGeneration: UInt64) async {
        guard heartbeatGeneration == generation, state == .connected, !isClosed else {
            return
        }
        if waitingOnKeepAlive {
            await connectionDidFail(generation: heartbeatGeneration)
            return
        }

        waitingOnKeepAlive = true
        do {
            try await send(
                Packet(header: UInt8(Et_TerminalPacketType.keepAlive.rawValue), payload: Data())
            )
            startHeartbeat(generation: heartbeatGeneration)
        } catch {
            await connectionDidFail(generation: heartbeatGeneration)
        }
    }

    private func startWriteDrainIfNeeded() {
        guard !isRecovering, !isDrainingWrites, !pendingWrites.isEmpty else { return }
        isDrainingWrites = true
        writeDrainTask = Task { [weak self] in
            await self?.drainWrites()
        }
    }

    private func drainWrites() async {
        while !pendingWrites.isEmpty, !isClosed, !isRecovering {
            let pending = pendingWrites.removeFirst()
            guard let writer else {
                pending.continuation.resume(throwing: ETClientError.connectionClosed)
                continue
            }

            do {
                let writeGeneration = generation
                let write = try await writer.write(pending.packet)
                switch write.state {
                case .success:
                    if writeGeneration == generation,
                       state == .connected,
                       let framedBytes = write.framedBytes,
                       let transport {
                        do {
                            try await transport.write(framedBytes)
                        } catch {
                            await connectionDidFail(generation: writeGeneration)
                        }
                    }
                    pending.continuation.resume()
                case .bufferedOnly:
                    pending.continuation.resume()
                case .skipped:
                    pending.continuation.resume(throwing: ETClientError.disconnectedBufferFull)
                }
            } catch {
                pending.continuation.resume(throwing: mapError(error))
            }
        }
        isDrainingWrites = false
        writeDrainTask = nil
        let waiters = writeDrainWaiters
        writeDrainWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    private func connectionDidFail(generation failedGeneration: UInt64) async {
        guard failedGeneration == generation, !isClosed, state == .connected else { return }
        generation &+= 1
        readTask?.cancel()
        stateTask?.cancel()
        heartbeatTask?.cancel()
        readTask = nil
        stateTask = nil
        heartbeatTask = nil
        waitingOnKeepAlive = false

        await reader?.invalidate()
        await writer?.invalidate()
        let failedTransport = transport
        transport = nil
        await failedTransport?.close()
        updateState(.disconnected)
        updateState(.reconnecting)
        startReconnectLoop()
    }

    private func startReconnectLoop() {
        guard reconnectTask == nil, !isClosed else { return }
        reconnectTask = Task { [weak self, delay = configuration.reconnectDelay] in
            while !Task.isCancelled {
                guard let self else { return }
                do {
                    try await self.attemptReconnect()
                    return
                } catch let error as ETClientError {
                    if case .invalidKey = error {
                        await self.failPermanently(error)
                        return
                    }
                    if case .mismatchedProtocol = error {
                        await self.failPermanently(error)
                        return
                    }
                    if case .sessionUnrecoverable = error {
                        await self.failPermanently(error)
                        return
                    }
                } catch {
                    // Retry transport and recoverable handshake failures.
                }
                await self.waitBeforeReconnect(delay)
                guard !Task.isCancelled else { return }
            }
        }
    }

    private func attemptReconnect() async throws {
        guard !isClosed, state == .reconnecting, let reader, let writer else {
            throw ETClientError.connectionClosed
        }

        isRecovering = true
        await waitForWriteDrain()
        guard !isClosed, state == .reconnecting else {
            isRecovering = false
            throw ETClientError.connectionClosed
        }
        let newTransport = await transportFactory.makeTransport()
        pendingTransport = newTransport
        do {
            try await connect(newTransport)
            var framingBuffer = Data()
            let response = try await exchangeConnectRequest(
                over: newTransport,
                framingBuffer: &framingBuffer
            )
            try validateReconnect(response)

            let localSequence = try await reader.sequenceHeader()
            try await writeProto(localSequence, over: newTransport)
            let remoteSequence = try await readProto(
                Et_SequenceHeader.self,
                over: newTransport,
                buffer: &framingBuffer
            )
            let localCatchup = try await writer.catchupBuffer(
                after: Int64(remoteSequence.sequenceNumber)
            )
            try await writeProto(localCatchup, over: newTransport)
            let remoteCatchup = try await readProto(
                Et_CatchupBuffer.self,
                over: newTransport,
                buffer: &framingBuffer
            )

            try await reader.revive(with: remoteCatchup.buffer)
            await writer.revive()
            let recoveredPackets = try await reader.receive(framingBuffer)
            for packet in recoveredPackets {
                if packet.header != UInt8(Et_TerminalPacketType.keepAlive.rawValue),
                   packet.header != UInt8(Et_EtPacketType.heartbeat.rawValue) {
                    packetContinuation.yield(packet)
                }
            }
            guard !isClosed, state == .reconnecting else {
                throw ETClientError.connectionClosed
            }
            isRecovering = false
            pendingTransport = nil
            activate(newTransport)
        } catch {
            let clientError: ETClientError
            switch error as? ETProtocolError {
            case .recoveryUnavailable, .sequenceNumberOutOfRange:
                // Retrying cannot help: the catchup gap only grows and sequence
                // numbers never shrink, so classify as permanently unrecoverable.
                clientError = .sessionUnrecoverable(String(describing: error))
            default:
                clientError = mapError(error)
            }
            let isPermanentFailure: Bool
            switch clientError {
            case .invalidKey, .mismatchedProtocol, .sessionUnrecoverable:
                isPermanentFailure = true
            default:
                isPermanentFailure = false
            }
            isRecovering = isPermanentFailure
            pendingTransport = nil
            await reader.invalidate()
            await writer.invalidate()
            if !isPermanentFailure {
                startWriteDrainIfNeeded()
            }
            await newTransport.close()
            throw clientError
        }
    }

    private func waitForWriteDrain() async {
        guard isDrainingWrites else { return }
        await withCheckedContinuation { continuation in
            writeDrainWaiters.append(continuation)
        }
    }

    private func waitBeforeReconnect(_ delay: Duration) async {
        let task = Task<Void, Never> {
            do {
                try await Task.sleep(for: delay)
            } catch {
                return
            }
        }
        reconnectBackoffTask = task
        await task.value
        reconnectBackoffTask = nil
    }

    private func failPermanently(_ error: ETClientError) async {
        guard !isClosed else { return }
        isClosed = true
        generation &+= 1
        readTask?.cancel()
        stateTask?.cancel()
        reconnectTask?.cancel()
        reconnectBackoffTask?.cancel()
        heartbeatTask?.cancel()
        writeDrainTask?.cancel()
        readTask = nil
        stateTask = nil
        reconnectTask = nil
        reconnectBackoffTask = nil
        heartbeatTask = nil
        writeDrainTask = nil
        isRecovering = false
        isDrainingWrites = false

        await reader?.invalidate()
        await writer?.invalidate()
        let currentTransport = transport
        transport = nil
        let currentPendingTransport = pendingTransport
        pendingTransport = nil
        await currentTransport?.close()
        await currentPendingTransport?.close()

        let writes = pendingWrites
        pendingWrites.removeAll()
        for write in writes {
            write.continuation.resume(throwing: ETClientError.connectionClosed)
        }
        let waiters = writeDrainWaiters
        writeDrainWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
        updateState(.failed(error))
        packetContinuation.finish()
        stateContinuation.finish()
    }

    private func connect(_ newTransport: any Transport) async throws {
        enum Outcome: Sendable {
            case connected
            case timedOut
        }

        let endpoint = endpoint
        let timeout = configuration.connectTimeout
        try await withThrowingTaskGroup(of: Outcome.self) { group in
            group.addTask {
                try await newTransport.connect(to: endpoint)
                return .connected
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                return .timedOut
            }

            guard let outcome = try await group.next() else {
                throw ETClientError.transportFailure("Transport connect race ended unexpectedly")
            }
            group.cancelAll()
            switch outcome {
            case .connected:
                return
            case .timedOut:
                await newTransport.close()
                throw ETClientError.transportFailure("Transport connect timed out")
            }
        }
    }

    private func writeProto<Message: SwiftProtobuf.Message>(
        _ message: Message,
        over transport: any Transport
    ) async throws {
        let payload = try message.serializedData()
        guard payload.count <= ProtoFraming.maximumPayloadBytes else {
            throw ETClientError.malformedFrame("Protobuf payload exceeds 128 MiB")
        }
        var framed = Data(capacity: 8 + payload.count)
        // The 8-byte length prefix is little-endian, matching the C++ reference's raw
        // host-order int64 (SocketHandler.hpp) on every platform supported here.
        let length = UInt64(payload.count)
        for byteIndex in 0..<8 {
            framed.append(UInt8(truncatingIfNeeded: length >> UInt64(byteIndex * 8)))
        }
        framed.append(payload)
        try await transport.write(framed)
    }

    private func readProto<Message: SwiftProtobuf.Message>(
        _ type: Message.Type,
        over transport: any Transport,
        buffer: inout Data
    ) async throws -> Message {
        while buffer.count < 8 {
            buffer.append(try await transport.read())
        }

        var length: UInt64 = 0
        for byteIndex in 0..<8 {
            length |= UInt64(buffer[buffer.startIndex + byteIndex]) << UInt64(byteIndex * 8)
        }
        guard length <= UInt64(ProtoFraming.maximumPayloadBytes),
              let payloadLength = Int(exactly: length) else {
            throw ETClientError.malformedFrame("Invalid protobuf frame length: \(length)")
        }
        let totalLength = 8 + payloadLength
        while buffer.count < totalLength {
            buffer.append(try await transport.read())
        }

        let payload = Data(buffer.dropFirst(8).prefix(payloadLength))
        buffer.removeFirst(totalLength)
        do {
            return try Message(serializedBytes: payload)
        } catch {
            throw ETClientError.malformedFrame(String(describing: error))
        }
    }

    private func mapError(_ error: any Error) -> ETClientError {
        if let error = error as? ETClientError {
            return error
        }
        return .transportFailure(String(describing: error))
    }

    private func updateState(_ newState: ETConnectionState) {
        guard state != newState else { return }
        state = newState
        stateContinuation.yield(newState)
    }
}

private enum ProtoFraming {
    static let maximumPayloadBytes = 128 * 1024 * 1024
}

private struct PendingWrite {
    let packet: Packet
    let continuation: CheckedContinuation<Void, any Error>
}
