import Foundation

public struct Packet: Equatable, Sendable {
    public let encrypted: Bool
    public let header: UInt8
    public let payload: Data

    public init(encrypted: Bool = false, header: UInt8, payload: Data) {
        self.encrypted = encrypted
        self.header = header
        self.payload = payload
    }

    public init(serialized: Data) throws {
        guard serialized.count >= 2 else {
            throw ETProtocolError.malformedPacket(minimum: 2, actual: serialized.count)
        }
        encrypted = serialized[serialized.startIndex] != 0
        header = serialized[serialized.startIndex + 1]
        payload = Data(serialized.dropFirst(2))
    }

    public var wireLength: Int {
        payload.count + 2
    }

    public func serialized() -> Data {
        var bytes = Data(capacity: wireLength)
        bytes.append(encrypted ? 1 : 0)
        bytes.append(header)
        bytes.append(payload)
        return bytes
    }

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
