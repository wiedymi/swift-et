import Foundation

public actor SecretBox {
    public static let clientToServerNonceMostSignificantByte: UInt8 = 0
    public static let serverToClientNonceMostSignificantByte: UInt8 = 1

    private var state: SecretBoxState

    public init<Key: ContiguousBytes & Sendable>(
        key: Key,
        nonceMostSignificantByte: UInt8
    ) throws {
        state = try SecretBoxState(
            key: key.withUnsafeBytes { Array($0) },
            nonceMostSignificantByte: nonceMostSignificantByte
        )
    }

    public func seal<Message: ContiguousBytes & Sendable>(_ message: Message) throws -> Data {
        try state.seal(message)
    }

    public func open<Ciphertext: ContiguousBytes & Sendable>(_ ciphertext: Ciphertext) throws -> Data {
        try state.open(ciphertext)
    }
}

struct SecretBoxState: Sendable {
    private let key: [UInt8]
    private var nonce: [UInt8]

    init(key: [UInt8], nonceMostSignificantByte: UInt8) throws {
        guard key.count == XSalsa20Poly1305.keyByteCount else {
            throw ETProtocolError.invalidKeyLength(
                expected: XSalsa20Poly1305.keyByteCount,
                actual: key.count
            )
        }
        self.key = key
        nonce = [UInt8](repeating: 0, count: XSalsa20Poly1305.nonceByteCount)
        nonce[XSalsa20Poly1305.nonceByteCount - 1] = nonceMostSignificantByte
    }

    mutating func seal<Message: ContiguousBytes>(_ message: Message) throws -> Data {
        incrementNonce()
        return try XSalsa20Poly1305.seal(message, nonce: nonce, key: key)
    }

    mutating func open<Ciphertext: ContiguousBytes>(_ ciphertext: Ciphertext) throws -> Data {
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
