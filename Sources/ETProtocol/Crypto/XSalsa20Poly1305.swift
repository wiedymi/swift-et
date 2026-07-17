import Foundation

public enum XSalsa20Poly1305 {
    public static let keyByteCount = 32
    public static let nonceByteCount = 24
    public static let tagByteCount = Poly1305.tagByteCount

    public static func seal<Message: ContiguousBytes, Nonce: ContiguousBytes, Key: ContiguousBytes>(
        _ message: Message,
        nonce: Nonce,
        key: Key
    ) throws -> Data {
        let keyBytes = key.withUnsafeBytes { Array($0) }
        let nonceBytes = nonce.withUnsafeBytes { Array($0) }
        let messageBytes = message.withUnsafeBytes { Array($0) }
        try validate(key: keyBytes, nonce: nonceBytes)

        let subkey = hsalsa20(key: keyBytes, nonce: Array(nonceBytes[0..<16]))
        let streamNonce = Array(nonceBytes[16..<24])
        let initialBlock = salsa20Block(key: subkey, nonce: streamNonce, counter: 0)
        let authenticationKey = Array(initialBlock[0..<32])
        let ciphertext = xor(messageBytes, key: subkey, nonce: streamNonce, initialBlock: initialBlock)
        let tag = Poly1305.authenticate(ciphertext, key: authenticationKey)
        return Data(tag + ciphertext)
    }

    public static func open<Ciphertext: ContiguousBytes, Nonce: ContiguousBytes, Key: ContiguousBytes>(
        _ sealed: Ciphertext,
        nonce: Nonce,
        key: Key
    ) throws -> Data {
        let keyBytes = key.withUnsafeBytes { Array($0) }
        let nonceBytes = nonce.withUnsafeBytes { Array($0) }
        let sealedBytes = sealed.withUnsafeBytes { Array($0) }
        try validate(key: keyBytes, nonce: nonceBytes)
        guard sealedBytes.count >= tagByteCount else {
            throw ETProtocolError.ciphertextTooShort(
                minimum: tagByteCount,
                actual: sealedBytes.count
            )
        }

        let subkey = hsalsa20(key: keyBytes, nonce: Array(nonceBytes[0..<16]))
        let streamNonce = Array(nonceBytes[16..<24])
        let initialBlock = salsa20Block(key: subkey, nonce: streamNonce, counter: 0)
        let authenticationKey = Array(initialBlock[0..<32])
        let tag = Array(sealedBytes[0..<tagByteCount])
        let ciphertext = Array(sealedBytes[tagByteCount...])
        let expectedTag = Poly1305.authenticate(ciphertext, key: authenticationKey)
        guard constantTimeEqual(tag, expectedTag) else {
            throw ETProtocolError.authenticationFailed
        }
        return Data(xor(ciphertext, key: subkey, nonce: streamNonce, initialBlock: initialBlock))
    }

    private static func validate(key: [UInt8], nonce: [UInt8]) throws {
        guard key.count == keyByteCount else {
            throw ETProtocolError.invalidKeyLength(expected: keyByteCount, actual: key.count)
        }
        guard nonce.count == nonceByteCount else {
            throw ETProtocolError.invalidNonceLength(expected: nonceByteCount, actual: nonce.count)
        }
    }

    private static func xor(
        _ input: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        initialBlock: [UInt8]
    ) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        var inputOffset = 0

        let firstCount = min(32, input.count)
        for index in 0..<firstCount {
            output[index] = input[index] ^ initialBlock[index + 32]
        }
        inputOffset += firstCount

        var counter: UInt64 = 1
        while inputOffset < input.count {
            let block = salsa20Block(key: key, nonce: nonce, counter: counter)
            let blockCount = min(64, input.count - inputOffset)
            for index in 0..<blockCount {
                output[inputOffset + index] = input[inputOffset + index] ^ block[index]
            }
            inputOffset += blockCount
            counter &+= 1
        }
        return output
    }

    private static func hsalsa20(key: [UInt8], nonce: [UInt8]) -> [UInt8] {
        var state = initialState(key: key)
        state[6] = load32(nonce, at: 0)
        state[7] = load32(nonce, at: 4)
        state[8] = load32(nonce, at: 8)
        state[9] = load32(nonce, at: 12)
        salsa20Rounds(&state)

        var output = [UInt8](repeating: 0, count: 32)
        for (index, wordIndex) in [0, 5, 10, 15, 6, 7, 8, 9].enumerated() {
            store32(state[wordIndex], into: &output, at: index * 4)
        }
        return output
    }

    private static func salsa20Block(key: [UInt8], nonce: [UInt8], counter: UInt64) -> [UInt8] {
        var original = initialState(key: key)
        original[6] = load32(nonce, at: 0)
        original[7] = load32(nonce, at: 4)
        original[8] = UInt32(truncatingIfNeeded: counter)
        original[9] = UInt32(truncatingIfNeeded: counter >> 32)
        var state = original
        salsa20Rounds(&state)

        var output = [UInt8](repeating: 0, count: 64)
        for index in state.indices {
            store32(state[index] &+ original[index], into: &output, at: index * 4)
        }
        return output
    }

    private static func initialState(key: [UInt8]) -> [UInt32] {
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = 0x6170_7865
        state[5] = 0x3320_646e
        state[10] = 0x7962_2d32
        state[15] = 0x6b20_6574
        state[1] = load32(key, at: 0)
        state[2] = load32(key, at: 4)
        state[3] = load32(key, at: 8)
        state[4] = load32(key, at: 12)
        state[11] = load32(key, at: 16)
        state[12] = load32(key, at: 20)
        state[13] = load32(key, at: 24)
        state[14] = load32(key, at: 28)
        return state
    }

    private static func salsa20Rounds(_ x: inout [UInt32]) {
        for _ in 0..<10 {
            x[4] ^= rotateLeft(x[0] &+ x[12], by: 7)
            x[8] ^= rotateLeft(x[4] &+ x[0], by: 9)
            x[12] ^= rotateLeft(x[8] &+ x[4], by: 13)
            x[0] ^= rotateLeft(x[12] &+ x[8], by: 18)
            x[9] ^= rotateLeft(x[5] &+ x[1], by: 7)
            x[13] ^= rotateLeft(x[9] &+ x[5], by: 9)
            x[1] ^= rotateLeft(x[13] &+ x[9], by: 13)
            x[5] ^= rotateLeft(x[1] &+ x[13], by: 18)
            x[14] ^= rotateLeft(x[10] &+ x[6], by: 7)
            x[2] ^= rotateLeft(x[14] &+ x[10], by: 9)
            x[6] ^= rotateLeft(x[2] &+ x[14], by: 13)
            x[10] ^= rotateLeft(x[6] &+ x[2], by: 18)
            x[3] ^= rotateLeft(x[15] &+ x[11], by: 7)
            x[7] ^= rotateLeft(x[3] &+ x[15], by: 9)
            x[11] ^= rotateLeft(x[7] &+ x[3], by: 13)
            x[15] ^= rotateLeft(x[11] &+ x[7], by: 18)

            x[1] ^= rotateLeft(x[0] &+ x[3], by: 7)
            x[2] ^= rotateLeft(x[1] &+ x[0], by: 9)
            x[3] ^= rotateLeft(x[2] &+ x[1], by: 13)
            x[0] ^= rotateLeft(x[3] &+ x[2], by: 18)
            x[6] ^= rotateLeft(x[5] &+ x[4], by: 7)
            x[7] ^= rotateLeft(x[6] &+ x[5], by: 9)
            x[4] ^= rotateLeft(x[7] &+ x[6], by: 13)
            x[5] ^= rotateLeft(x[4] &+ x[7], by: 18)
            x[11] ^= rotateLeft(x[10] &+ x[9], by: 7)
            x[8] ^= rotateLeft(x[11] &+ x[10], by: 9)
            x[9] ^= rotateLeft(x[8] &+ x[11], by: 13)
            x[10] ^= rotateLeft(x[9] &+ x[8], by: 18)
            x[12] ^= rotateLeft(x[15] &+ x[14], by: 7)
            x[13] ^= rotateLeft(x[12] &+ x[15], by: 9)
            x[14] ^= rotateLeft(x[13] &+ x[12], by: 13)
            x[15] ^= rotateLeft(x[14] &+ x[13], by: 18)
        }
    }

    @inline(__always)
    private static func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    @inline(__always)
    private static func load32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    @inline(__always)
    private static func store32(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(truncatingIfNeeded: value)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    @inline(__always)
    private static func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}
