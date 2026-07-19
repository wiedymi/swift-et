/// Errors raised by Eternal Terminal cryptography and reliable packet framing.
public enum ETProtocolError: Error, Equatable, Sendable {
    /// A key did not have the required byte count.
    case invalidKeyLength(expected: Int, actual: Int)
    /// A nonce did not have the required byte count.
    case invalidNonceLength(expected: Int, actual: Int)
    /// A secretbox ciphertext was too short to contain its authenticator.
    case ciphertextTooShort(minimum: Int, actual: Int)
    /// Poly1305 authentication failed.
    case authenticationFailed
    /// A packet omitted its encrypted flag or header bytes.
    case malformedPacket(minimum: Int, actual: Int)
    /// A caller attempted to encrypt an already encrypted packet.
    case packetAlreadyEncrypted
    /// A reliable reader received an unencrypted packet.
    case packetNotEncrypted
    /// A packet frame declared an invalid length.
    case invalidFrameLength(Int)
    /// A packet exceeded the C++ protocol's maximum representable size.
    case messageTooLarge(maximum: Int, actual: Int)
    /// Size arithmetic overflowed.
    case arithmeticOverflow
    /// A requested sequence number cannot be represented or recovered.
    case sequenceNumberOutOfRange
    /// Sequence-number arithmetic overflowed.
    case sequenceNumberOverflow
    /// Recovery was requested while a writer was connected.
    case recoveryRequiresDisconnected
    /// Requested ciphertext has already fallen out of the backup window.
    case recoveryUnavailable(requested: Int64, available: Int)
    /// A negative capacity was requested.
    case invalidCapacity(Int)
}
