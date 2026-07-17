import ETProtocol
import Foundation

public actor ETTerminalSession {
    public nonisolated let output: AsyncStream<Data>
    public nonisolated let stateChanges: AsyncStream<ETConnectionState>

    private let outputContinuation: AsyncStream<Data>.Continuation
    private let connection: ETConnection
    private let portForwardHandler: PortForwardHandler
    private let forwardTunnels: [ETTunnel]
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
        tunnels: [ETTunnel] = [],
        reverseTunnels: [ETTunnel] = [],
        jumphost: Bool = false,
        environmentVariables: [String: String] = [:]
    ) throws {
        try self.init(
            endpoint: TransportEndpoint(host: host, port: port),
            clientID: clientID,
            passkey: passkey,
            tunnels: tunnels,
            reverseTunnels: reverseTunnels,
            jumphost: jumphost,
            environmentVariables: environmentVariables,
            transportFactory: NWTransportFactory(),
            configuration: ETConnectionConfiguration(),
            listenerFactory: SystemForwardingListenerFactory(),
            forwardingSocketFactory: SystemForwardingSocketFactory()
        )
    }

    public init(
        host: String,
        port: UInt16 = 2022,
        clientID: String,
        passkey: Data,
        tunnelSpecification: String,
        reverseTunnelSpecification: String = "",
        jumphost: Bool = false,
        environmentVariables: [String: String] = [:]
    ) throws {
        let tunnels = tunnelSpecification.isEmpty
            ? []
            : try ETTunnel.parse(tunnelSpecification)
        let reverseTunnels = reverseTunnelSpecification.isEmpty
            ? []
            : try ETTunnel.parse(reverseTunnelSpecification)
        try self.init(
            host: host,
            port: port,
            clientID: clientID,
            passkey: passkey,
            tunnels: tunnels,
            reverseTunnels: reverseTunnels,
            jumphost: jumphost,
            environmentVariables: environmentVariables
        )
    }

    init(
        endpoint: TransportEndpoint,
        clientID: String,
        passkey: Data,
        tunnels: [ETTunnel] = [],
        reverseTunnels: [ETTunnel] = [],
        jumphost: Bool = false,
        environmentVariables: [String: String] = [:],
        transportFactory: any TransportFactory,
        configuration: ETConnectionConfiguration,
        listenerFactory: any ForwardingListenerFactory = SystemForwardingListenerFactory(),
        forwardingSocketFactory: any ForwardingSocketFactory = SystemForwardingSocketFactory()
    ) throws {
        let outputPair = AsyncStream<Data>.makeStream(bufferingPolicy: .unbounded)
        output = outputPair.stream
        outputContinuation = outputPair.continuation

        var payload = Et_InitialPayload()
        payload.jumphost = jumphost
        payload.reversetunnels = reverseTunnels.map { $0.protobufRequest() }
        payload.environmentvariables = environmentVariables
        initialPayload = payload
        forwardTunnels = tunnels

        let newConnection = try ETConnection(
            endpoint: endpoint,
            clientID: clientID,
            passkey: passkey,
            transportFactory: transportFactory,
            configuration: configuration
        )
        connection = newConnection
        portForwardHandler = PortForwardHandler(
            connection: newConnection,
            listenerFactory: listenerFactory,
            socketFactory: forwardingSocketFactory
        )
        stateChanges = newConnection.stateChanges
    }

    public func connect() async throws {
        guard !isClosed else { throw ETClientError.connectionClosed }
        guard !isConnecting else { throw ETClientError.connectionInProgress }
        guard !hasConnected else { return }
        isConnecting = true
        startPacketForwarding()
        do {
            try await portForwardHandler.start(forwardTunnels: forwardTunnels)
            try await connection.connect(initialPayload: initialPayload)
            isConnecting = false
            hasConnected = true
        } catch {
            isConnecting = false
            hasConnected = false
            packetTask?.cancel()
            packetTask = nil
            await portForwardHandler.close()
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
        await portForwardHandler.close()
        await connection.close()
        outputContinuation.finish()
    }

    private func startPacketForwarding() {
        guard packetTask == nil else { return }
        let packets = connection.packets
        packetTask = Task { [weak self] in
            for await packet in packets {
                guard !Task.isCancelled else { return }
                if packet.header == UInt8(Et_TerminalPacketType.terminalBuffer.rawValue),
                   let terminalBuffer = try? Et_TerminalBuffer(
                    serializedBytes: packet.payload
                   ) {
                    await self?.yieldOutput(terminalBuffer.buffer)
                } else if packet.header == UInt8(
                    Et_TerminalPacketType.portForwardData.rawValue
                ) || packet.header == UInt8(
                    Et_TerminalPacketType.portForwardDestinationRequest.rawValue
                ) || packet.header == UInt8(
                    Et_TerminalPacketType.portForwardDestinationResponse.rawValue
                ) {
                    do {
                        try await self?.portForwardHandler.handle(packet)
                    } catch {
                        await self?.close()
                        return
                    }
                }
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
