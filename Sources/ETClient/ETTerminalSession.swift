import ETProtocol
import Foundation

public actor ETTerminalSession {
    public nonisolated let output: AsyncStream<Data>
    public nonisolated let stateChanges: AsyncStream<ETConnectionState>

    private let outputContinuation: AsyncStream<Data>.Continuation
    private let connection: ETConnection
    private var initialPayload: Et_InitialPayload
    private var packetTask: Task<Void, Never>?
    private var isConnecting = false
    private var hasConnected = false
    private var isClosed = false

    public init(
        host: String,
        port: UInt16 = 2022,
        clientID: String,
        passkey: Data,
        environmentVariables: [String: String] = [:]
    ) throws {
        try self.init(
            endpoint: TransportEndpoint(host: host, port: port),
            clientID: clientID,
            passkey: passkey,
            environmentVariables: environmentVariables,
            transportFactory: NWTransportFactory(),
            configuration: ETConnectionConfiguration()
        )
    }

    init(
        endpoint: TransportEndpoint,
        clientID: String,
        passkey: Data,
        environmentVariables: [String: String] = [:],
        transportFactory: any TransportFactory,
        configuration: ETConnectionConfiguration
    ) throws {
        let outputPair = AsyncStream<Data>.makeStream(bufferingPolicy: .unbounded)
        output = outputPair.stream
        outputContinuation = outputPair.continuation

        var payload = Et_InitialPayload()
        payload.jumphost = false
        payload.environmentvariables = environmentVariables
        initialPayload = payload

        let newConnection = try ETConnection(
            endpoint: endpoint,
            clientID: clientID,
            passkey: passkey,
            transportFactory: transportFactory,
            configuration: configuration
        )
        connection = newConnection
        stateChanges = newConnection.stateChanges
    }

    public func connect() async throws {
        guard !isClosed else { throw ETClientError.connectionClosed }
        guard !isConnecting else { throw ETClientError.connectionInProgress }
        guard !hasConnected else { return }
        isConnecting = true
        startPacketForwarding()
        do {
            try await connection.connect(initialPayload: initialPayload)
            isConnecting = false
            hasConnected = true
        } catch {
            isConnecting = false
            hasConnected = false
            packetTask?.cancel()
            packetTask = nil
            throw error
        }
    }

    public func send(_ data: Data) async throws {
        guard hasConnected, !isClosed else { throw ETClientError.connectionClosed }
        var terminalBuffer = Et_TerminalBuffer()
        terminalBuffer.buffer = data
        try await connection.send(
            Packet(
                header: UInt8(Et_TerminalPacketType.terminalBuffer.rawValue),
                payload: try terminalBuffer.serializedData()
            )
        )
    }

    public func resize(rows: Int, cols: Int) async throws {
        guard hasConnected, !isClosed else { throw ETClientError.connectionClosed }
        guard rows > 0, cols > 0,
              let wireRows = Int32(exactly: rows),
              let wireColumns = Int32(exactly: cols) else {
            throw ETClientError.invalidTerminalSize(rows: rows, columns: cols)
        }

        var terminalInfo = Et_TerminalInfo()
        terminalInfo.row = wireRows
        terminalInfo.column = wireColumns
        try await connection.send(
            Packet(
                header: UInt8(Et_TerminalPacketType.terminalInfo.rawValue),
                payload: try terminalInfo.serializedData()
            )
        )
    }

    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        packetTask?.cancel()
        packetTask = nil
        await connection.close()
        outputContinuation.finish()
    }

    private func startPacketForwarding() {
        guard packetTask == nil else { return }
        let packets = connection.packets
        packetTask = Task { [weak self] in
            for await packet in packets {
                guard !Task.isCancelled else { return }
                guard packet.header == UInt8(Et_TerminalPacketType.terminalBuffer.rawValue),
                      let terminalBuffer = try? Et_TerminalBuffer(
                        serializedBytes: packet.payload
                      ) else {
                    continue
                }
                await self?.yieldOutput(terminalBuffer.buffer)
            }
            guard !Task.isCancelled else { return }
            await self?.finishOutput()
        }
    }

    private func yieldOutput(_ data: Data) {
        outputContinuation.yield(data)
    }

    private func finishOutput() {
        outputContinuation.finish()
    }
}
