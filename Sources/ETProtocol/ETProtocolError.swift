public enum ETProtocolError: Error, Equatable, Sendable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidNonceLength(expected: Int, actual: Int)
    case ciphertextTooShort(minimum: Int, actual: Int)
    case authenticationFailed
    case malformedPacket(minimum: Int, actual: Int)
    case packetAlreadyEncrypted
    case packetNotEncrypted
    case invalidFrameLength(Int)
    case messageTooLarge(maximum: Int, actual: Int)
    case arithmeticOverflow
    case sequenceNumberOutOfRange
    case sequenceNumberOverflow
    case recoveryRequiresDisconnected
    case recoveryUnavailable(requested: Int64, available: Int)
    case invalidCapacity(Int)
}
