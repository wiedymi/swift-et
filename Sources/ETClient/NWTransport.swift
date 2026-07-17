import Foundation
import Network

actor NWTransport: Transport {
    nonisolated let stateChanges: AsyncStream<TransportState>

    private let stateContinuation: AsyncStream<TransportState>.Continuation
    private let queue = DispatchQueue(label: "ETClient.NWTransport")
    private var connection: NWConnection?
    private var connectContinuation: CheckedContinuation<Void, any Error>?
    private var state: TransportState = .idle

    init() {
        let pair = AsyncStream<TransportState>.makeStream(
            bufferingPolicy: .bufferingNewest(8)
        )
        stateChanges = pair.stream
        stateContinuation = pair.continuation
        stateContinuation.yield(.idle)
    }

    func connect(to endpoint: TransportEndpoint) async throws {
        guard connection == nil else { throw TransportError.alreadyConnected }
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw TransportError.failed("Invalid TCP port: \(endpoint.port)")
        }

        let nwConnection = NWConnection(
            host: NWEndpoint.Host(endpoint.host),
            port: port,
            using: .tcp
        )
        connection = nwConnection
        updateState(.connecting)

        nwConnection.stateUpdateHandler = { [weak self] nwState in
            let event: NWStateEvent
            switch nwState {
            case .setup, .preparing:
                return
            case .ready:
                event = .ready
            case .waiting(let error):
                event = .waiting(String(describing: error))
            case .failed(let error):
                event = .failed(String(describing: error))
            case .cancelled:
                event = .cancelled
            @unknown default:
                event = .failed("Unknown Network.framework connection state")
            }
            Task { [weak self] in
                await self?.handle(event)
            }
        }

        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connectContinuation = continuation
            nwConnection.start(queue: queue)
        }
    }

    func read() async throws -> Data {
        guard let connection else { throw TransportError.notConnected }

        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, any Error>) in
            connection.receive(
                minimumIncompleteLength: 1,
                maximumLength: 64 * 1024
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
        guard let connection else { throw TransportError.notConnected }
        guard !data.isEmpty else { return }

        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(
                            throwing: TransportError.failed(String(describing: error))
                        )
                    } else {
                        continuation.resume()
                    }
                }
            )
        }
    }

    func close() {
        let currentConnection = connection
        connection = nil
        currentConnection?.stateUpdateHandler = nil
        currentConnection?.cancel()
        resumeConnect(throwing: TransportError.connectionClosed)
        updateState(.closed)
        stateContinuation.finish()
    }

    private func handle(_ event: NWStateEvent) {
        switch event {
        case .ready:
            updateState(.ready)
            resumeConnect()
        case .waiting:
            updateState(.waiting)
        case .failed(let message):
            updateState(.failed(message))
            resumeConnect(throwing: TransportError.failed(message))
        case .cancelled:
            updateState(.closed)
            resumeConnect(throwing: TransportError.connectionClosed)
        }
    }

    private func updateState(_ newState: TransportState) {
        guard state != newState else { return }
        state = newState
        stateContinuation.yield(newState)
    }

    private func resumeConnect(throwing error: (any Error)? = nil) {
        guard let continuation = connectContinuation else { return }
        connectContinuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}

private enum NWStateEvent: Sendable {
    case ready
    case waiting(String)
    case failed(String)
    case cancelled
}
