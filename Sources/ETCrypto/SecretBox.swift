import Foundation

/// A serialized secretbox stream with Eternal Terminal nonce semantics.
public actor SecretBox {
    /// Nonce stream discriminator used for client-to-server packets.
    public static let clientToServerNonceMostSignificantByte: UInt8 = 0
    /// Nonce stream discriminator used for server-to-client packets.
    public static let serverToClientNonceMostSignificantByte: UInt8 = 1

    private var state: SecretBoxState

    /// Creates a secretbox stream from a 32-byte key and direction discriminator.
    public init<Key: ContiguousBytes & Sendable>(
        key: Key,
        nonceMostSignificantByte: UInt8
    ) throws {
        state = try SecretBoxState(
            key: key.withUnsafeBytes { Array($0) },
            nonceMostSignificantByte: nonceMostSignificantByte
        )
    }

    /// Increments the nonce and encrypts one message.
    public func seal<Message: ContiguousBytes & Sendable>(_ message: Message) throws -> Data {
        try state.seal(message)
    }

    /// Increments the nonce and authenticates one ciphertext.
    public func open<Ciphertext: ContiguousBytes & Sendable>(_ ciphertext: Ciphertext) throws -> Data {
        try state.open(ciphertext)
    }
}

package struct SecretBoxState: Sendable {
    private let key: SecretKey
    private var nonce: [UInt8]

    package init(key: [UInt8], nonceMostSignificantByte: UInt8) throws {
        guard key.count == XSalsa20Poly1305.keyByteCount else {
            throw ETProtocolError.invalidKeyLength(
                expected: XSalsa20Poly1305.keyByteCount,
                actual: key.count
            )
        }
        self.key = SecretKey(key)
        nonce = [UInt8](repeating: 0, count: XSalsa20Poly1305.nonceByteCount)
        nonce[XSalsa20Poly1305.nonceByteCount - 1] = nonceMostSignificantByte
    }

    package init(key: [UInt8], nonce: Data) throws {
        guard key.count == XSalsa20Poly1305.keyByteCount else {
            throw ETProtocolError.invalidKeyLength(
                expected: XSalsa20Poly1305.keyByteCount,
                actual: key.count
            )
        }
        guard nonce.count == XSalsa20Poly1305.nonceByteCount else {
            throw ETProtocolError.invalidNonceLength(
                expected: XSalsa20Poly1305.nonceByteCount,
                actual: nonce.count
            )
        }
        self.key = SecretKey(key)
        self.nonce = Array(nonce)
    }

    package var checkpointNonce: Data {
        Data(nonce)
    }

    package mutating func seal<Message: ContiguousBytes>(_ message: Message) throws -> Data {
        incrementNonce()
        return try XSalsa20Poly1305.seal(message, nonce: nonce, key: key)
    }

    package mutating func open<Ciphertext: ContiguousBytes>(
        _ ciphertext: Ciphertext
    ) throws -> Data {
        incrementNonce()
        return try XSalsa20Poly1305.open(ciphertext, nonce: nonce, key: key)
    }

    private mutating func incrementNonce() {
        for index in nonce.indices {
            nonce[index] &+= 1
            if nonce[index] != 0 {
                break
            }
        }
    }
}
