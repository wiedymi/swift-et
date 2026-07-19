import Foundation

package struct TransportEndpoint: Equatable, Sendable {
    package let host: String
    package let port: UInt16

    package init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

package enum TransportState: Equatable, Sendable {
    case idle
    case connecting
    case ready
    case waiting
    case failed(String)
    case closed
}

package enum TransportError: Error, Equatable, Sendable {
    case alreadyConnected
    case notConnected
    case connectionClosed
    case failed(String)
}

package protocol Transport: Sendable {
    var stateChanges: AsyncStream<TransportState> { get }

    func connect(to endpoint: TransportEndpoint) async throws
    func read() async throws -> Data
    func write(_ data: Data) async throws
    func close() async
}

package protocol TransportFactory: Sendable {
    func makeTransport() async -> any Transport
}

package struct NWTransportFactory: TransportFactory {
    package init() {}

    package func makeTransport() async -> any Transport {
        NWTransport()
    }
}
