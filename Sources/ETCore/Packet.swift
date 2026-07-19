import Foundation

/// Eternal Terminal's encrypted-flag, header, and payload packet.
public struct Packet: Equatable, Sendable {
    /// Whether the payload contains secretbox ciphertext.
    public let encrypted: Bool
    /// Protocol packet-type byte.
    public let header: UInt8
    /// Packet body bytes.
    public let payload: Data

    /// Creates a packet.
    public init(encrypted: Bool = false, header: UInt8, payload: Data) {
        self.encrypted = encrypted
        self.header = header
        self.payload = payload
    }

    /// Parses the packet body without its four-byte frame length.
    public init(serialized: Data) throws {
        guard serialized.count >= 2 else {
            throw ETProtocolError.malformedPacket(minimum: 2, actual: serialized.count)
        }
        encrypted = serialized[serialized.startIndex] != 0
        header = serialized[serialized.startIndex + 1]
        payload = Data(serialized.dropFirst(2))
    }

    /// Serialized packet size excluding the four-byte frame length.
    public var wireLength: Int {
        payload.count + 2
    }

    /// Serializes the packet body.
    public func serialized() -> Data {
        var bytes = Data(capacity: wireLength)
        bytes.append(encrypted ? 1 : 0)
        bytes.append(header)
        bytes.append(payload)
        return bytes
    }

    /// Serializes the packet with its big-endian four-byte frame length.
    public func framed() throws -> Data {
        guard wireLength <= Int(Int32.max) else {
            throw ETProtocolError.messageTooLarge(
                maximum: Int(Int32.max),
                actual: wireLength
            )
        }
        let length = UInt32(wireLength)
        var bytes = Data(capacity: wireLength + 4)
        bytes.append(UInt8(truncatingIfNeeded: length >> 24))
        bytes.append(UInt8(truncatingIfNeeded: length >> 16))
        bytes.append(UInt8(truncatingIfNeeded: length >> 8))
        bytes.append(UInt8(truncatingIfNeeded: length))
        bytes.append(serialized())
        return bytes
    }
}
