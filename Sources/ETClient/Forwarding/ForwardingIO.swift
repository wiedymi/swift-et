import Darwin
import Foundation
import Network

protocol ForwardingSocket: AnyObject, Sendable {
    func read() async throws -> Data
    func write(_ data: Data) async throws
    func close() async
}

protocol ForwardingSocketFactory: Sendable {
    func connect(to endpoint: ETTunnelEndpoint) async throws -> any ForwardingSocket
}

protocol ForwardingListener: AnyObject, Sendable {
    func start() async throws
    func accept() async throws -> any ForwardingSocket
    func close() async
}

protocol ForwardingListenerFactory: Sendable {
    func makeListener(for endpoint: ETTunnelEndpoint) async throws -> any ForwardingListener
}

struct SystemForwardingSocketFactory: ForwardingSocketFactory {
    func connect(to endpoint: ETTunnelEndpoint) async throws -> any ForwardingSocket {
        let socket = NWForwardingSocket(endpoint: endpoint.networkEndpoint())
        try await socket.start()
        return socket
    }
}

struct SystemForwardingListenerFactory: ForwardingListenerFactory {
    func makeListener(for endpoint: ETTunnelEndpoint) async throws -> any ForwardingListener {
        switch endpoint {
        case .tcp(let host, let port):
            return try NWForwardingListener(host: host ?? "localhost", port: port)
        case .unix(let path):
            return UnixForwardingListener(path: path)
        }
    }
}

private extension ETTunnelEndpoint {
    func networkEndpoint() -> NWEndpoint {
        switch self {
        case .tcp(let host, let port):
            return .hostPort(
                host: NWEndpoint.Host(host ?? "localhost"),
                port: NWEndpoint.Port(rawValue: port) ?? .any
            )
        case .unix(let path):
            return .unix(path: path)
        }
    }
}

private actor NWForwardingSocket: ForwardingSocket {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "ETClient.NWForwardingSocket")
    private var startContinuation: CheckedContinuation<Void, any Error>?
    private var hasStarted = false
    private var isClosed = false

    init(endpoint: NWEndpoint) {
        connection = NWConnection(to: endpoint, using: .tcp)
    }

    init(connection: NWConnection) {
        self.connection = connection
    }

    func start() async throws {
        guard !hasStarted else { return }
        guard !isClosed else { throw TransportError.connectionClosed }
        hasStarted = true
        connection.stateUpdateHandler = { [weak self] state in
            let event: ForwardingConnectionEvent
            switch state {
            case .setup, .preparing:
                return
            case .ready:
                event = .ready
            case .waiting(let error), .failed(let error):
                event = .failed(String(describing: error))
            case .cancelled:
                event = .closed
            @unknown default:
                event = .failed("Unknown Network.framework connection state")
            }
            Task { [weak self] in
                await self?.handle(event)
            }
        }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            startContinuation = continuation
            connection.start(queue: queue)
        }
    }

    func read() async throws -> Data {
        guard hasStarted, !isClosed else { throw TransportError.connectionClosed }
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, any Error>) in
            connection.receive(
                minimumIncompleteLength: 1,
                maximumLength: 16 * 1024
            ) { content, _, isComplete, error in
                if let error {
                    continuation.resume(
                        throwing: TransportError.failed(String(describing: error))
                    )
                } else if let content, !content.isEmpty {
                    continuation.resume(returning: content)
                } else if isComplete {
                    continuation.resume(throwing: TransportError.connectionClosed)
                } else {
                    continuation.resume(returning: Data())
                }
            }
        }
    }

    func write(_ data: Data) async throws {
        guard hasStarted, !isClosed else { throw TransportError.connectionClosed }
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(
                        throwing: TransportError.failed(String(describing: error))
                    )
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
        resumeStart(throwing: TransportError.connectionClosed)
    }

    private func handle(_ event: ForwardingConnectionEvent) {
        switch event {
        case .ready:
            resumeStart()
        case .failed(let message):
            resumeStart(throwing: TransportError.failed(message))
        case .closed:
            resumeStart(throwing: TransportError.connectionClosed)
        }
    }

    private func resumeStart(throwing error: (any Error)? = nil) {
        guard let continuation = startContinuation else { return }
        startContinuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}

private enum ForwardingConnectionEvent: Sendable {
    case ready
    case failed(String)
    case closed
}

private actor NWForwardingListener: ForwardingListener {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "ETClient.NWForwardingListener")
    private var startContinuation: CheckedContinuation<Void, any Error>?
    private var sockets: [any ForwardingSocket] = []
    private var acceptWaiter: CheckedContinuation<any ForwardingSocket, any Error>?
    private var hasStarted = false
    private var isClosed = false

    init(host: String, port: UInt16) throws {
        guard let networkPort = NWEndpoint.Port(rawValue: port) else {
            throw ETClientError.forwardingFailure("Invalid listener port \(port)")
        }
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(
            host: NWEndpoint.Host(host),
            port: networkPort
        )
        listener = try NWListener(using: parameters)
    }

    func start() async throws {
        guard !hasStarted else { return }
        guard !isClosed else { throw TransportError.connectionClosed }
        hasStarted = true
        listener.stateUpdateHandler = { [weak self] state in
            let event: ForwardingListenerEvent
            switch state {
            case .setup:
                return
            case .ready:
                event = .ready
            case .waiting(let error), .failed(let error):
                event = .failed(String(describing: error))
            case .cancelled:
                event = .closed
            @unknown default:
                event = .failed("Unknown Network.framework listener state")
            }
            Task { [weak self] in
                await self?.handle(event)
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            let socket = NWForwardingSocket(connection: connection)
            Task { [weak self] in
                do {
                    try await socket.start()
                    await self?.enqueue(socket)
                } catch {
                    await socket.close()
                }
            }
        }
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            startContinuation = continuation
            listener.start(queue: queue)
        }
    }

    func accept() async throws -> any ForwardingSocket {
        if !sockets.isEmpty {
            return sockets.removeFirst()
        }
        guard !isClosed else { throw TransportError.connectionClosed }
        guard acceptWaiter == nil else {
            throw ETClientError.forwardingFailure("Concurrent listener accept")
        }
        return try await withCheckedThrowingContinuation { continuation in
            acceptWaiter = continuation
        }
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        listener.stateUpdateHandler = nil
        listener.newConnectionHandler = nil
        listener.cancel()
        resumeStart(throwing: TransportError.connectionClosed)
        let waiter = acceptWaiter
        acceptWaiter = nil
        waiter?.resume(throwing: TransportError.connectionClosed)
        let pendingSockets = sockets
        sockets.removeAll()
        for socket in pendingSockets {
            await socket.close()
        }
    }

    private func enqueue(_ socket: any ForwardingSocket) async {
        guard !isClosed else {
            await socket.close()
            return
        }
        if let waiter = acceptWaiter {
            acceptWaiter = nil
            waiter.resume(returning: socket)
        } else {
            sockets.append(socket)
        }
    }

    private func handle(_ event: ForwardingListenerEvent) async {
        switch event {
        case .ready:
            resumeStart()
        case .failed(let message):
            resumeStart(throwing: ETClientError.forwardingFailure(message))
            await close()
        case .closed:
            resumeStart(throwing: TransportError.connectionClosed)
            await close()
        }
    }

    private func resumeStart(throwing error: (any Error)? = nil) {
        guard let continuation = startContinuation else { return }
        startContinuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}

private enum ForwardingListenerEvent: Sendable {
    case ready
    case failed(String)
    case closed
}

private actor UnixForwardingListener: ForwardingListener {
    private let path: String
    private let queue = DispatchQueue(label: "ETClient.UnixForwardingListener")
    private var descriptor: Int32 = -1
    private var source: DispatchSourceRead?
    private var sockets: [any ForwardingSocket] = []
    private var acceptWaiter: CheckedContinuation<any ForwardingSocket, any Error>?
    private var isClosed = false
    private var ownsSocketPath = false

    init(path: String) {
        self.path = path
    }

    func start() throws {
        guard descriptor == -1, !isClosed else { throw TransportError.alreadyConnected }
        let socketDescriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else { throw posixError("socket") }

        do {
            var address = try unixAddress(path: path)
            let addressLength = socklen_t(address.sun_len)
            let bindResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(socketDescriptor, $0, addressLength)
                }
            }
            guard bindResult == 0 else { throw posixError("bind") }
            ownsSocketPath = true
            guard Darwin.listen(socketDescriptor, SOMAXCONN) == 0 else {
                throw posixError("listen")
            }
            let flags = fcntl(socketDescriptor, F_GETFL)
            guard flags >= 0, fcntl(socketDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw posixError("fcntl")
            }

            descriptor = socketDescriptor
            let readSource = DispatchSource.makeReadSource(
                fileDescriptor: socketDescriptor,
                queue: queue
            )
            readSource.setEventHandler { [weak self] in
                Task { [weak self] in
                    await self?.acceptAvailableSockets()
                }
            }
            source = readSource
            readSource.resume()
        } catch {
            Darwin.close(socketDescriptor)
            if ownsSocketPath {
                Darwin.unlink(path)
                ownsSocketPath = false
            }
            throw error
        }
    }

    func accept() async throws -> any ForwardingSocket {
        if !sockets.isEmpty {
            return sockets.removeFirst()
        }
        guard !isClosed else { throw TransportError.connectionClosed }
        guard acceptWaiter == nil else {
            throw ETClientError.forwardingFailure("Concurrent listener accept")
        }
        return try await withCheckedThrowingContinuation { continuation in
            acceptWaiter = continuation
        }
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        source?.cancel()
        source = nil
        if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
        if ownsSocketPath {
            Darwin.unlink(path)
            ownsSocketPath = false
        }
        let waiter = acceptWaiter
        acceptWaiter = nil
        waiter?.resume(throwing: TransportError.connectionClosed)
        let pendingSockets = sockets
        sockets.removeAll()
        for socket in pendingSockets {
            await socket.close()
        }
    }

    private func acceptAvailableSockets() {
        guard descriptor >= 0, !isClosed else { return }
        while true {
            let acceptedDescriptor = Darwin.accept(descriptor, nil, nil)
            if acceptedDescriptor >= 0 {
                enqueue(POSIXForwardingSocket(descriptor: acceptedDescriptor))
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK { return }
            return
        }
    }

    private func enqueue(_ socket: any ForwardingSocket) {
        if let waiter = acceptWaiter {
            acceptWaiter = nil
            waiter.resume(returning: socket)
        } else {
            sockets.append(socket)
        }
    }
}

private actor POSIXForwardingSocket: ForwardingSocket {
    private static let queue = DispatchQueue(
        label: "ETClient.POSIXForwardingSocket",
        attributes: .concurrent
    )

    private let descriptor: Int32
    private var isClosed = false
    private var activeOperationCount = 0
    private var isDescriptorClosed = false

    init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    func read() async throws -> Data {
        guard !isClosed else { throw TransportError.connectionClosed }
        let descriptor = descriptor
        activeOperationCount += 1
        defer { operationEnded() }
        do {
            return try await withCheckedThrowingContinuation { continuation in
                Self.queue.async {
                    var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                    let count = Darwin.read(descriptor, &bytes, bytes.count)
                    if count > 0 {
                        continuation.resume(returning: Data(bytes.prefix(count)))
                    } else if count == 0 {
                        continuation.resume(throwing: TransportError.connectionClosed)
                    } else {
                        continuation.resume(throwing: posixError("read"))
                    }
                }
            }
        } catch {
            if isClosed { throw TransportError.connectionClosed }
            throw error
        }
    }

    func write(_ data: Data) async throws {
        guard !isClosed else { throw TransportError.connectionClosed }
        guard !data.isEmpty else { return }
        let descriptor = descriptor
        activeOperationCount += 1
        defer { operationEnded() }
        do {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, any Error>) in
                Self.queue.async {
                    do {
                        try data.withUnsafeBytes { rawBuffer in
                            guard let baseAddress = rawBuffer.baseAddress else { return }
                            var written = 0
                            while written < rawBuffer.count {
                                let result = Darwin.send(
                                    descriptor,
                                    baseAddress.advanced(by: written),
                                    rawBuffer.count - written,
                                    MSG_NOSIGNAL
                                )
                                guard result > 0 else { throw posixError("write") }
                                written += result
                            }
                        }
                        continuation.resume()
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } catch {
            if isClosed { throw TransportError.connectionClosed }
            throw error
        }
    }

    func close() {
        guard !isClosed else { return }
        isClosed = true
        Darwin.shutdown(descriptor, SHUT_RDWR)
        closeDescriptorIfPossible()
    }

    private func operationEnded() {
        activeOperationCount -= 1
        closeDescriptorIfPossible()
    }

    private func closeDescriptorIfPossible() {
        guard isClosed, activeOperationCount == 0, !isDescriptorClosed else { return }
        isDescriptorClosed = true
        Darwin.close(descriptor)
    }
}

private func unixAddress(path: String) throws -> sockaddr_un {
    let pathBytes = Array(path.utf8CString)
    var address = sockaddr_un()
    let maximumPathBytes = MemoryLayout.size(ofValue: address.sun_path)
    guard pathBytes.count <= maximumPathBytes else {
        throw ETClientError.forwardingFailure("Unix socket path is too long: \(path)")
    }
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { destination in
        pathBytes.withUnsafeBytes { source in
            destination.copyBytes(from: source)
        }
    }
    let pathOffset = MemoryLayout<sockaddr_un>.offset(of: \.sun_path) ?? 0
    let length = pathOffset + pathBytes.count
    guard let wireLength = UInt8(exactly: length) else {
        throw ETClientError.forwardingFailure("Unix socket address is too long")
    }
    address.sun_len = wireLength
    return address
}

private func posixError(_ operation: String) -> ETClientError {
    let message = String(cString: strerror(errno))
    return .forwardingFailure("\(operation): \(message)")
}
