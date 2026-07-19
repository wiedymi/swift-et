import ETCore
import ETCrypto
import Foundation

/// A TCP or Unix-domain forwarding endpoint.
public enum ETTunnelEndpoint: Hashable, Sendable {
    /// A TCP endpoint; a nil host uses the protocol-side default.
    case tcp(host: String?, port: UInt16)
    /// A named Unix-domain socket path.
    case unix(path: String)
}

/// The local source binding for a forward tunnel.
public enum ETTunnelSource: Equatable, Sendable {
    /// A concrete TCP or Unix-domain endpoint.
    case endpoint(ETTunnelEndpoint)
    /// A Unix socket path read from an environment variable.
    case environmentVariable(String)
}

/// A parsed forward or reverse tunnel mapping.
public struct ETTunnel: Equatable, Sendable {
    /// Source binding.
    public let source: ETTunnelSource
    /// Destination endpoint.
    public let destination: ETTunnelEndpoint

    /// Creates a tunnel mapping.
    public init(source: ETTunnelSource, destination: ETTunnelEndpoint) {
        self.source = source
        self.destination = destination
    }

    /// Parses the C++ client's comma-separated tunnel grammar, expanding port ranges.
    public static func parse(_ specification: String) throws -> [ETTunnel] {
        try ETTunnelParser.parse(specification)
    }
}

/// Typed reasons a tunnel specification can be rejected.
public enum ETTunnelParseReason: Equatable, Sendable {
    /// The specification was empty.
    case emptySpecification
    /// Source or destination syntax was absent.
    case missingSourceOrDestination
    /// A source or destination port was invalid.
    case invalidPort(String)
    /// A port range was malformed or descending.
    case invalidRange(String)
    /// A range appeared without a matching range endpoint.
    case rangePairRequired
    /// Source and destination ranges had different lengths.
    case rangeLengthMismatch
    /// SSH-style host syntax did not contain all four fields.
    case sshStyleRequiresFourParts
    /// An IPv6 address was not bracketed.
    case unbracketedIPv6
}

enum ETTunnelParser {
    static func parse(_ input: String) throws -> [ETTunnel] {
        guard !input.isEmpty else {
            throw ETClientError.invalidTunnelSpecification(
                input,
                .emptySpecification
            )
        }

        let commaParts = input.split(separator: ",", omittingEmptySubsequences: false)
        if commaParts.count > 1 {
            return try commaParts.flatMap { part in
                guard !part.isEmpty else {
                    throw ETClientError.invalidTunnelSpecification(
                        input,
                        .missingSourceOrDestination
                    )
                }
                return try parseETStyle(String(part), wholeInput: input)
            }
        }

        let parts = try splitSSHStyle(input)
        if parts.count <= 2 {
            return try parseETStyle(input, wholeInput: input)
        }
        guard parts.count == 4 else {
            throw ETClientError.invalidTunnelSpecification(
                input,
                parts.count < 4 ? .sshStyleRequiresFourParts : .unbracketedIPv6
            )
        }

        let sourcePort = try parsePort(parts[1], input: input)
        let destinationPort = try parsePort(parts[3], input: input)
        return [
            ETTunnel(
                source: .endpoint(.tcp(host: parts[0], port: sourcePort)),
                destination: .tcp(host: parts[2], port: destinationPort)
            )
        ]
    }

    private static func parseETStyle(
        _ element: String,
        wholeInput: String
    ) throws -> [ETTunnel] {
        let parts = element.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
            throw ETClientError.invalidTunnelSpecification(
                wholeInput,
                .missingSourceOrDestination
            )
        }

        let source = String(parts[0])
        let destination = String(parts[1])
        let sourceIsSocket = source.hasPrefix("/")
        let destinationIsSocket = destination.hasPrefix("/")
        let sourceIsNumeric = isNumericRange(source)
        let destinationIsNumeric = isNumericRange(destination)

        if sourceIsSocket || (destinationIsSocket && sourceIsNumeric) {
            let parsedSource: ETTunnelEndpoint
            if sourceIsSocket {
                parsedSource = .unix(path: source)
            } else {
                parsedSource = .tcp(
                    host: "localhost",
                    port: try parsePort(source, input: wholeInput)
                )
            }
            let parsedDestination: ETTunnelEndpoint
            if destinationIsSocket {
                parsedDestination = .unix(path: destination)
            } else {
                parsedDestination = .tcp(
                    host: nil,
                    port: try parsePort(destination, input: wholeInput)
                )
            }
            return [ETTunnel(source: .endpoint(parsedSource), destination: parsedDestination)]
        }

        if !sourceIsNumeric, !destinationIsNumeric {
            return [
                ETTunnel(
                    source: .environmentVariable(source),
                    destination: .unix(path: destination)
                )
            ]
        }

        let sourceHasRange = source.contains("-")
        let destinationHasRange = destination.contains("-")
        if sourceHasRange, destinationHasRange {
            let sourceRange = try parseRange(source, input: wholeInput)
            let destinationRange = try parseRange(destination, input: wholeInput)
            guard sourceRange.count == destinationRange.count else {
                throw ETClientError.invalidTunnelSpecification(
                    wholeInput,
                    .rangeLengthMismatch
                )
            }
            return zip(sourceRange, destinationRange).map { sourcePort, destinationPort in
                ETTunnel(
                    source: .endpoint(.tcp(host: "localhost", port: sourcePort)),
                    destination: .tcp(host: nil, port: destinationPort)
                )
            }
        }
        if sourceHasRange || destinationHasRange {
            throw ETClientError.invalidTunnelSpecification(
                wholeInput,
                .rangePairRequired
            )
        }

        return [
            ETTunnel(
                source: .endpoint(
                    .tcp(host: "localhost", port: try parsePort(source, input: wholeInput))
                ),
                destination: .tcp(
                    host: nil,
                    port: try parsePort(destination, input: wholeInput)
                )
            )
        ]
    }

    private static func splitSSHStyle(_ input: String) throws -> [String] {
        var parts: [String] = []
        var current = ""
        var bracketDepth = 0
        for character in input {
            switch character {
            case "[":
                bracketDepth += 1
                guard bracketDepth == 1 else {
                    throw ETClientError.invalidTunnelSpecification(input, .unbracketedIPv6)
                }
            case "]":
                bracketDepth -= 1
                guard bracketDepth == 0 else {
                    throw ETClientError.invalidTunnelSpecification(input, .unbracketedIPv6)
                }
            case ":" where bracketDepth == 0:
                parts.append(current)
                current.removeAll(keepingCapacity: true)
            default:
                current.append(character)
            }
        }
        guard bracketDepth == 0 else {
            throw ETClientError.invalidTunnelSpecification(input, .unbracketedIPv6)
        }
        parts.append(current)
        return parts
    }

    private static func parseRange(_ value: String, input: String) throws -> [UInt16] {
        let bounds = value.split(separator: "-", omittingEmptySubsequences: false)
        guard bounds.count == 2,
              let start = UInt16(bounds[0]),
              let end = UInt16(bounds[1]),
              start <= end else {
            throw ETClientError.invalidTunnelSpecification(input, .invalidRange(value))
        }
        return Array(start...end)
    }

    private static func parsePort(_ value: String, input: String) throws -> UInt16 {
        guard !value.isEmpty, value.allSatisfy(\.isNumber), let port = UInt16(value) else {
            throw ETClientError.invalidTunnelSpecification(input, .invalidPort(value))
        }
        return port
    }

    private static func isNumericRange(_ value: String) -> Bool {
        !value.isEmpty && value.allSatisfy { $0.isNumber || $0 == "-" }
    }
}

extension ETTunnel {
    func protobufRequest() -> Et_PortForwardSourceRequest {
        var request = Et_PortForwardSourceRequest()
        switch source {
        case .endpoint(let endpoint):
            request.source = endpoint.protobufEndpoint()
        case .environmentVariable(let name):
            request.environmentvariable = name
        }
        request.destination = destination.protobufEndpoint()
        return request
    }
}

extension ETTunnelEndpoint {
    func protobufEndpoint() -> Et_SocketEndpoint {
        var endpoint = Et_SocketEndpoint()
        switch self {
        case .tcp(let host, let port):
            if let host {
                endpoint.name = host
            }
            endpoint.port = Int32(port)
        case .unix(let path):
            endpoint.name = path
        }
        return endpoint
    }

    init(protobuf endpoint: Et_SocketEndpoint) throws {
        if endpoint.hasPort {
            guard let port = UInt16(exactly: endpoint.port) else {
                throw ETClientError.forwardingFailure("Invalid port \(endpoint.port)")
            }
            self = .tcp(host: endpoint.hasName ? endpoint.name : nil, port: port)
        } else if endpoint.hasName, !endpoint.name.isEmpty {
            self = .unix(path: endpoint.name)
        } else {
            throw ETClientError.forwardingFailure("Missing forwarding endpoint")
        }
    }
}
