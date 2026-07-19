import ETCore
import ETCrypto
import ETTransport
import Foundation
import SwiftProtobuf

actor PortForwardHandler {
    private let connection: ETConnection
    private let listenerFactory: any ForwardingListenerFactory
    private let socketFactory: any ForwardingSocketFactory

    private var listeners: [any ForwardingListener] = []
    private var listenerTasks: [Task<Void, Never>] = []
    private var pendingSources: [Int32: any ForwardingSocket] = [:]
    private var sourceSockets: [Int32: any ForwardingSocket] = [:]
    private var destinationSockets: [Int32: any ForwardingSocket] = [:]
    private var sourceReadTasks: [Int32: Task<Void, Never>] = [:]
    private var destinationReadTasks: [Int32: Task<Void, Never>] = [:]
    private var nextClientHandle: Int32 = 1
    private var isClosed = false

    init(
        connection: ETConnection,
        listenerFactory: any ForwardingListenerFactory,
        socketFactory: any ForwardingSocketFactory
    ) {
        self.connection = connection
        self.listenerFactory = listenerFactory
        self.socketFactory = socketFactory
    }

    func start(forwardTunnels: [ETTunnel]) async throws {
        guard !isClosed else { throw ETClientError.connectionClosed }
        do {
            for tunnel in forwardTunnels {
                guard case .endpoint(let source) = tunnel.source else {
                    throw ETClientError.forwardingFailure(
                        "Environment-variable tunnel sources are supported only for reverse tunnels"
                    )
                }
                let listener = try await listenerFactory.makeListener(for: source)
                try await listener.start()
                listeners.append(listener)
                startAccepting(on: listener, destination: tunnel.destination)
            }
        } catch {
            await close()
            if let error = error as? ETClientError { throw error }
            throw ETClientError.forwardingFailure(forwardingMessage(for: error))
        }
    }

    func handle(_ packet: Packet) async throws {
        guard !isClosed else { return }
        switch packet.header {
        case UInt8(Et_TerminalPacketType.portForwardDestinationRequest.rawValue):
            let request = try Et_PortForwardDestinationRequest(
                serializedBytes: packet.payload
            )
            try await handleDestinationRequest(request)
        case UInt8(Et_TerminalPacketType.portForwardDestinationResponse.rawValue):
            let response = try Et_PortForwardDestinationResponse(
                serializedBytes: packet.payload
            )
            await handleDestinationResponse(response)
        case UInt8(Et_TerminalPacketType.portForwardData.rawValue):
            let data = try Et_PortForwardData(serializedBytes: packet.payload)
            await handleForwardedData(data)
        default:
            throw ETClientError.forwardingFailure(
                "Unexpected forwarding packet \(packet.header)"
            )
        }
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true

        let tasks = listenerTasks
            + Array(sourceReadTasks.values)
            + Array(destinationReadTasks.values)
        listenerTasks.removeAll()
        sourceReadTasks.removeAll()
        destinationReadTasks.removeAll()
        tasks.forEach { $0.cancel() }

        let activeListeners = listeners
        listeners.removeAll()
        for listener in activeListeners {
            await listener.close()
        }

        let sockets = Array(pendingSources.values)
            + Array(sourceSockets.values)
            + Array(destinationSockets.values)
        pendingSources.removeAll()
        sourceSockets.removeAll()
        destinationSockets.removeAll()
        for socket in sockets {
            await socket.close()
        }
    }

    private func startAccepting(
        on listener: any ForwardingListener,
        destination: ETTunnelEndpoint
    ) {
        let task = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    let socket = try await listener.accept()
                    await self?.accepted(socket, destination: destination)
                } catch {
                    return
                }
            }
        }
        listenerTasks.append(task)
    }

    private func accepted(
        _ socket: any ForwardingSocket,
        destination: ETTunnelEndpoint
    ) async {
        guard !isClosed else {
            await socket.close()
            return
        }
        let clientHandle: Int32
        do {
            clientHandle = try allocateClientHandle()
        } catch {
            await socket.close()
            return
        }
        pendingSources[clientHandle] = socket
        do {
            var request = Et_PortForwardDestinationRequest()
            request.destination = destination.protobufEndpoint()
            request.fd = clientHandle
            try await send(
                header: .portForwardDestinationRequest,
                message: request
            )
        } catch {
            let pendingSocket = pendingSources.removeValue(forKey: clientHandle)
            await pendingSocket?.close()
        }
    }

    private func handleDestinationResponse(
        _ response: Et_PortForwardDestinationResponse
    ) async {
        guard let socket = pendingSources.removeValue(forKey: response.clientfd) else {
            return
        }
        if response.hasError {
            await socket.close()
            return
        }
        let socketID = response.socketid
        if let replaced = sourceSockets.updateValue(socket, forKey: socketID) {
            await replaced.close()
        }
        startReading(socket, socketID: socketID, sourceToDestination: true)
    }

    private func handleDestinationRequest(
        _ request: Et_PortForwardDestinationRequest
    ) async throws {
        var response = Et_PortForwardDestinationResponse()
        response.clientfd = request.fd
        do {
            let endpoint = try ETTunnelEndpoint(protobuf: request.destination)
            let socket = try await connectToLocalDestination(endpoint)
            let socketID = try allocateDestinationSocketID()
            destinationSockets[socketID] = socket
            response.socketid = socketID
            startReading(socket, socketID: socketID, sourceToDestination: false)
        } catch {
            response.error = forwardingMessage(for: error)
        }
        try await send(
            header: .portForwardDestinationResponse,
            message: response
        )
    }

    private func handleForwardedData(_ data: Et_PortForwardData) async {
        let socket: (any ForwardingSocket)?
        if data.sourcetodestination {
            socket = destinationSockets[data.socketid]
        } else {
            socket = sourceSockets[data.socketid]
        }
        guard let socket else { return }

        if data.hasClosed || data.hasError {
            await removeSocket(
                socketID: data.socketid,
                sourceToDestination: !data.sourcetodestination
            )
            return
        }
        do {
            try await socket.write(data.buffer)
        } catch {
            await socketEnded(
                socketID: data.socketid,
                sourceToDestination: !data.sourcetodestination,
                error: error
            )
        }
    }

    private func connectToLocalDestination(
        _ endpoint: ETTunnelEndpoint
    ) async throws -> any ForwardingSocket {
        switch endpoint {
        case .tcp(_, let port):
            do {
                return try await socketFactory.connect(
                    to: .tcp(host: "::1", port: port)
                )
            } catch {
                return try await socketFactory.connect(
                    to: .tcp(host: "127.0.0.1", port: port)
                )
            }
        case .unix:
            return try await socketFactory.connect(to: endpoint)
        }
    }

    private func startReading(
        _ socket: any ForwardingSocket,
        socketID: Int32,
        sourceToDestination: Bool
    ) {
        let task = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    let bytes = try await socket.read()
                    guard !bytes.isEmpty else { continue }
                    try await self?.sendForwardedData(
                        bytes,
                        socketID: socketID,
                        sourceToDestination: sourceToDestination
                    )
                } catch {
                    await self?.socketEnded(
                        socketID: socketID,
                        sourceToDestination: sourceToDestination,
                        error: error
                    )
                    return
                }
            }
        }
        if sourceToDestination {
            sourceReadTasks[socketID]?.cancel()
            sourceReadTasks[socketID] = task
        } else {
            destinationReadTasks[socketID]?.cancel()
            destinationReadTasks[socketID] = task
        }
    }

    private func sendForwardedData(
        _ bytes: Data,
        socketID: Int32,
        sourceToDestination: Bool
    ) async throws {
        var data = Et_PortForwardData()
        data.socketid = socketID
        data.sourcetodestination = sourceToDestination
        data.buffer = bytes
        try await send(header: .portForwardData, message: data)
    }

    private func socketEnded(
        socketID: Int32,
        sourceToDestination: Bool,
        error: any Error
    ) async {
        guard !isClosed else { return }
        var data = Et_PortForwardData()
        data.socketid = socketID
        data.sourcetodestination = sourceToDestination
        if error as? TransportError == .connectionClosed {
            data.closed = true
        } else {
            data.error = forwardingMessage(for: error)
        }
        try? await send(header: .portForwardData, message: data)
        await removeSocket(
            socketID: socketID,
            sourceToDestination: sourceToDestination
        )
    }

    private func removeSocket(
        socketID: Int32,
        sourceToDestination: Bool
    ) async {
        let socket: (any ForwardingSocket)?
        if sourceToDestination {
            sourceReadTasks.removeValue(forKey: socketID)?.cancel()
            socket = sourceSockets.removeValue(forKey: socketID)
        } else {
            destinationReadTasks.removeValue(forKey: socketID)?.cancel()
            socket = destinationSockets.removeValue(forKey: socketID)
        }
        await socket?.close()
    }

    private func send<Message: SwiftProtobuf.Message>(
        header: Et_TerminalPacketType,
        message: Message
    ) async throws {
        try await connection.send(
            Packet(
                header: UInt8(header.rawValue),
                payload: try message.serializedData()
            )
        )
    }

    private func allocateClientHandle() throws -> Int32 {
        let value = try allocateIdentifier(
            startingAt: &nextClientHandle,
            occupied: Set(pendingSources.keys)
        )
        return value
    }

    private func allocateDestinationSocketID() throws -> Int32 {
        for _ in 0..<100_000 {
            let candidate = Int32.random(in: 0...Int32.max)
            if destinationSockets[candidate] == nil {
                return candidate
            }
        }
        throw ETClientError.forwardingFailure("Could not allocate forwarding socket id")
    }

    private func allocateIdentifier(
        startingAt next: inout Int32,
        occupied: Set<Int32>
    ) throws -> Int32 {
        let (maximumAttempts, overflowed) = occupied.count.addingReportingOverflow(1)
        guard !overflowed else {
            throw ETClientError.forwardingFailure("Could not allocate forwarding socket id")
        }
        for _ in 0..<maximumAttempts {
            let candidate = next
            next = next == Int32.max ? 1 : next + 1
            if !occupied.contains(candidate) {
                return candidate
            }
        }
        throw ETClientError.forwardingFailure("Could not allocate forwarding socket id")
    }
}

private func forwardingMessage(for error: any Error) -> String {
    if case .forwardingFailure(let message) = error as? ETClientError {
        return message
    }
    if case .failed(let message) = error as? TransportError {
        return message
    }
    return String(describing: error)
}
