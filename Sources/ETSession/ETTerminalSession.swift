import ETBootstrap
import ETCore
import ETCrypto
import ETTransport
import Foundation

/// A resumable Eternal Terminal client session.
public actor ETTerminalSession {
    /// Decrypted terminal output in wire order.
    ///
    /// The stream is deliberately unbounded: dropping terminal bytes would corrupt terminal
    /// state, while terminal-scale traffic makes sustained buffer growth a practical non-issue.
    public nonisolated let output: AsyncStream<Data>

    /// Connection lifecycle changes for the session.
    public nonisolated let stateChanges: AsyncStream<ETConnectionState>

    private let outputContinuation: AsyncStream<Data>.Continuation
    private let stateContinuation: AsyncStream<ETConnectionState>.Continuation
    private let forwardTunnels: [ETTunnel]
    private let transportFactory: any TransportFactory
    private let configuration: ETConnectionConfiguration
    private let listenerFactory: any ForwardingListenerFactory
    private let forwardingSocketFactory: any ForwardingSocketFactory
    private var setup: ConnectionSetup
    private var initialPayload: Et_InitialPayload
    private var portForwardHandler: PortForwardHandler?
    private var packetTask: Task<Void, Never>?
    private var stateTask: Task<Void, Never>?
    private var currentState: ETConnectionState = .idle
    private var isConnecting = false
    private var hasConnected = false
    private var isClosed = false

    /// Creates a session from credentials acquired out of band.
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

    /// Restores a previously checkpointed session without starting a new remote shell.
    public init(
        host: String,
        port: UInt16 = 2022,
        clientID: String,
        passkey: Data,
        checkpoint: ETSessionCheckpoint,
        tunnels: [ETTunnel] = [],
        reverseTunnels: [ETTunnel] = [],
        jumphost: Bool = false,
        environmentVariables: [String: String] = [:]
    ) throws {
        try self.init(
            endpoint: TransportEndpoint(host: host, port: port),
            clientID: clientID,
            passkey: passkey,
            checkpoint: checkpoint,
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

    /// Creates a session from parsed forward and reverse tunnel strings.
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

    /// Creates a session that acquires credentials by running `etterminal` through an executor.
    public init(
        host: String,
        port: UInt16 = 2022,
        bootstrapExecutor: any ETBootstrapExecutor,
        bootstrapOptions: ETBootstrapOptions = ETBootstrapOptions(),
        tunnels: [ETTunnel] = [],
        reverseTunnels: [ETTunnel] = [],
        jumphost: Bool = false,
        environmentVariables: [String: String] = [:]
    ) {
        self.init(
            endpoint: TransportEndpoint(host: host, port: port),
            bootstrapExecutor: bootstrapExecutor,
            bootstrapOptions: bootstrapOptions,
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

    init(
        endpoint: TransportEndpoint,
        bootstrapExecutor: any ETBootstrapExecutor,
        bootstrapOptions: ETBootstrapOptions = ETBootstrapOptions(),
        tunnels: [ETTunnel] = [],
        reverseTunnels: [ETTunnel] = [],
        jumphost: Bool = false,
        environmentVariables: [String: String] = [:],
        transportFactory: any TransportFactory,
        configuration: ETConnectionConfiguration,
        listenerFactory: any ForwardingListenerFactory = SystemForwardingListenerFactory(),
        forwardingSocketFactory: any ForwardingSocketFactory = SystemForwardingSocketFactory()
    ) {
        let outputPair = AsyncStream<Data>.makeStream(bufferingPolicy: .unbounded)
        output = outputPair.stream
        outputContinuation = outputPair.continuation
        let statePair = AsyncStream<ETConnectionState>.makeStream(
            bufferingPolicy: .bufferingNewest(16)
        )
        stateChanges = statePair.stream
        stateContinuation = statePair.continuation
        stateContinuation.yield(.idle)

        setup = .bootstrap(
            BootstrapRequest(
                endpoint: endpoint,
                executor: bootstrapExecutor,
                options: bootstrapOptions
            )
        )
        forwardTunnels = tunnels
        self.transportFactory = transportFactory
        self.configuration = configuration
        self.listenerFactory = listenerFactory
        self.forwardingSocketFactory = forwardingSocketFactory
        initialPayload = Self.makeInitialPayload(
            reverseTunnels: reverseTunnels,
            jumphost: jumphost,
            environmentVariables: environmentVariables
        )
    }

    init(
        endpoint: TransportEndpoint,
        clientID: String,
        passkey: Data,
        checkpoint: ETSessionCheckpoint? = nil,
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
        let statePair = AsyncStream<ETConnectionState>.makeStream(
            bufferingPolicy: .bufferingNewest(16)
        )
        stateChanges = statePair.stream
        stateContinuation = statePair.continuation
        stateContinuation.yield(.idle)

        setup = .ready(
            try ETConnection(
                endpoint: endpoint,
                clientID: clientID,
                passkey: passkey,
                checkpoint: checkpoint,
                transportFactory: transportFactory,
                configuration: configuration
            )
        )
        forwardTunnels = tunnels
        self.transportFactory = transportFactory
        self.configuration = configuration
        self.listenerFactory = listenerFactory
        self.forwardingSocketFactory = forwardingSocketFactory
        initialPayload = Self.makeInitialPayload(
            reverseTunnels: reverseTunnels,
            jumphost: jumphost,
            environmentVariables: environmentVariables
        )
    }

    /// Bootstraps when necessary and connects the terminal session.
    public func connect() async throws {
        guard !isClosed else { throw ETClientError.connectionClosed }
        guard !isConnecting else { throw ETClientError.connectionInProgress }
        guard !hasConnected else { return }
        isConnecting = true

        do {
            let connection = try await prepareConnection()
            let handler = PortForwardHandler(
                connection: connection,
                listenerFactory: listenerFactory,
                socketFactory: forwardingSocketFactory
            )
            portForwardHandler = handler
            startStateForwarding(connection)
            startPacketForwarding(connection: connection, handler: handler)
            try await handler.start(forwardTunnels: forwardTunnels)
            try await connection.connect(initialPayload: initialPayload)
            isConnecting = false
            hasConnected = true
        } catch {
            isConnecting = false
            hasConnected = false
            packetTask?.cancel()
            packetTask = nil
            await portForwardHandler?.close()
            portForwardHandler = nil
            throw error
        }
    }

    /// Sends terminal input bytes.
    public func send(_ data: Data) async throws {
        guard hasConnected, !isClosed, let connection else {
            throw ETClientError.connectionClosed
        }
        var terminalBuffer = Et_TerminalBuffer()
        terminalBuffer.buffer = data
        try await connection.send(
            Packet(
                header: UInt8(Et_TerminalPacketType.terminalBuffer.rawValue),
                payload: try terminalBuffer.serializedData()
            )
        )
    }

    /// Sends terminal dimensions, optionally including pixel dimensions.
    public func resize(
        rows: Int,
        cols: Int,
        pixelWidth: Int? = nil,
        pixelHeight: Int? = nil
    ) async throws {
        guard hasConnected, !isClosed, let connection else {
            throw ETClientError.connectionClosed
        }
        guard rows > 0, cols > 0,
              let wireRows = Int32(exactly: rows),
              let wireColumns = Int32(exactly: cols) else {
            throw ETClientError.invalidTerminalSize(rows: rows, columns: cols)
        }
        guard pixelWidth.map({ $0 >= 0 && Int32(exactly: $0) != nil }) ?? true,
              pixelHeight.map({ $0 >= 0 && Int32(exactly: $0) != nil }) ?? true else {
            throw ETClientError.invalidTerminalPixels(
                width: pixelWidth,
                height: pixelHeight
            )
        }

        var terminalInfo = Et_TerminalInfo()
        terminalInfo.row = wireRows
        terminalInfo.column = wireColumns
        if let pixelWidth { terminalInfo.width = Int32(pixelWidth) }
        if let pixelHeight { terminalInfo.height = Int32(pixelHeight) }
        try await connection.send(
            Packet(
                header: UInt8(Et_TerminalPacketType.terminalInfo.rawValue),
                payload: try terminalInfo.serializedData()
            )
        )
    }

    /// Nudges recovery after the consumer observes a network-path change.
    public func notifyNetworkPathChanged() async {
        await connection?.notifyNetworkPathChanged()
    }

    /// Captures the protocol state needed to reconnect this session from a new process.
    public func checkpoint() async throws -> ETSessionCheckpoint {
        guard hasConnected, !isClosed, let connection else {
            throw ETClientError.connectionClosed
        }
        return try await connection.checkpoint()
    }

    /// Stops client writes and heartbeats after producing a durable background checkpoint.
    /// The transport stays open and incoming output continues to be processed.
    public func prepareForApplicationBackground() async throws -> ETSessionCheckpoint {
        guard hasConnected, !isClosed, let connection else {
            throw ETClientError.connectionClosed
        }
        return try await connection.prepareForApplicationBackground()
    }

    /// Resumes client writes and heartbeat monitoring after foreground activation.
    public func resumeFromApplicationBackground() async {
        await connection?.resumeFromApplicationBackground()
    }

    /// Closes the terminal session and finishes its streams.
    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        packetTask?.cancel()
        packetTask = nil
        stateTask?.cancel()
        stateTask = nil
        await portForwardHandler?.close()
        portForwardHandler = nil
        await connection?.close()
        outputContinuation.finish()
        emitState(.closed)
        stateContinuation.finish()
    }

    private var connection: ETConnection? {
        guard case .ready(let connection) = setup else { return nil }
        return connection
    }

    private func prepareConnection() async throws -> ETConnection {
        switch setup {
        case .ready(let connection):
            return connection
        case .bootstrap(let request):
            emitState(.bootstrapping)
            let credentials = try await ETBootstrap(options: request.options).run(
                using: request.executor
            )
            let newConnection = try ETConnection(
                endpoint: request.endpoint,
                clientID: credentials.clientID,
                passkey: credentials.passkey,
                transportFactory: transportFactory,
                configuration: configuration
            )
            setup = .ready(newConnection)
            return newConnection
        }
    }

    private func startStateForwarding(_ connection: ETConnection) {
        guard stateTask == nil else { return }
        let states = connection.stateChanges
        stateTask = Task { [weak self] in
            for await state in states {
                guard !Task.isCancelled else { return }
                guard state != .idle else { continue }
                await self?.emitState(state)
            }
            await self?.finishStateChangesIfTerminal()
        }
    }

    private func startPacketForwarding(
        connection: ETConnection,
        handler: PortForwardHandler
    ) {
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
                        try await handler.handle(packet)
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

    private func emitState(_ state: ETConnectionState) {
        guard currentState != state else { return }
        currentState = state
        stateContinuation.yield(state)
    }

    private func finishStateChangesIfTerminal() {
        switch currentState {
        case .failed, .closed:
            stateContinuation.finish()
        case .idle, .bootstrapping, .connecting, .connected, .disconnected, .reconnecting:
            return
        }
    }

    private func yieldOutput(_ data: Data) {
        outputContinuation.yield(data)
    }

    private func finishOutput() {
        outputContinuation.finish()
    }

    private static func makeInitialPayload(
        reverseTunnels: [ETTunnel],
        jumphost: Bool,
        environmentVariables: [String: String]
    ) -> Et_InitialPayload {
        var payload = Et_InitialPayload()
        payload.jumphost = jumphost
        payload.reversetunnels = reverseTunnels.map { $0.protobufRequest() }
        payload.environmentvariables = environmentVariables
        return payload
    }
}

private enum ConnectionSetup: Sendable {
    case ready(ETConnection)
    case bootstrap(BootstrapRequest)
}

private struct BootstrapRequest: Sendable {
    let endpoint: TransportEndpoint
    let executor: any ETBootstrapExecutor
    let options: ETBootstrapOptions
}
