import Foundation

struct TransportEndpoint: Equatable, Sendable {
    let host: String
    let port: UInt16
}

enum TransportState: Equatable, Sendable {
    case idle
    case connecting
    case ready
    case waiting
    case failed(String)
    case closed
}

enum TransportError: Error, Equatable, Sendable {
    case alreadyConnected
    case notConnected
    case connectionClosed
    case failed(String)
}

protocol Transport: Sendable {
    var stateChanges: AsyncStream<TransportState> { get }

    func connect(to endpoint: TransportEndpoint) async throws
    func read() async throws -> Data
    func write(_ data: Data) async throws
    func close() async
}

protocol TransportFactory: Sendable {
    func makeTransport() async -> any Transport
}

struct NWTransportFactory: TransportFactory {
    func makeTransport() async -> any Transport {
        NWTransport()
    }
}
