import Foundation

/// Pure Swift XSalsa20-Poly1305 compatible with libsodium secretbox easy APIs.
public enum XSalsa20Poly1305 {
    /// Required secret-key size.
    public static let keyByteCount = 32
    /// Required nonce size.
    public static let nonceByteCount = 24
    /// Prepended authenticator size.
    public static let tagByteCount = Poly1305.tagByteCount

    /// Authenticates and encrypts a message.
    public static func seal<Message: ContiguousBytes, Nonce: ContiguousBytes, Key: ContiguousBytes>(
        _ message: Message,
        nonce: Nonce,
        key: Key
    ) throws -> Data {
        try key.withUnsafeBytes { keyBytes in
            try nonce.withUnsafeBytes { nonceBytes in
                try validate(key: keyBytes, nonce: nonceBytes)
                return try message.withUnsafeBytes { messageBytes in
                    let (sealedByteCount, overflow) = messageBytes.count.addingReportingOverflow(
                        tagByteCount
                    )
                    guard !overflow else { throw ETProtocolError.arithmeticOverflow }
                    let subkey = hsalsa20(key: keyBytes, nonce: nonceBytes)
                    return subkey.withUnsafeBytes { subkeyBytes in
                        let initialBlock = salsa20Block(
                            key: subkeyBytes,
                            nonce: UnsafeRawBufferPointer(
                                start: nonceBytes.baseAddress?.advanced(by: 16),
                                count: 8
                            ),
                            counter: 0
                        )
                        var sealed = Data(count: sealedByteCount)
                        sealed.withUnsafeMutableBytes { sealedBytes in
                            let ciphertext = UnsafeMutableRawBufferPointer(
                                start: sealedBytes.baseAddress?.advanced(by: tagByteCount),
                                count: messageBytes.count
                            )
                            xor(
                                messageBytes,
                                into: ciphertext,
                                key: subkeyBytes,
                                nonce: nonceBytes,
                                initialBlock: initialBlock
                            )

                            var authenticationKey = [UInt8](repeating: 0, count: 32)
                            authenticationKey.withUnsafeMutableBytes { keyBuffer in
                                storeFirstEightWords(initialBlock, into: keyBuffer)
                            }
                            authenticationKey.withUnsafeBytes { authenticationKeyBytes in
                                Poly1305.authenticate(
                                    UnsafeRawBufferPointer(ciphertext),
                                    key: authenticationKeyBytes,
                                    into: UnsafeMutableRawBufferPointer(
                                        start: sealedBytes.baseAddress,
                                        count: tagByteCount
                                    )
                                )
                            }
                        }
                        return sealed
                    }
                }
            }
        }
    }

    /// Authenticates and decrypts a secretbox ciphertext.
    public static func open<Ciphertext: ContiguousBytes, Nonce: ContiguousBytes, Key: ContiguousBytes>(
        _ sealed: Ciphertext,
        nonce: Nonce,
        key: Key
    ) throws -> Data {
        try key.withUnsafeBytes { keyBytes in
            try nonce.withUnsafeBytes { nonceBytes in
                try validate(key: keyBytes, nonce: nonceBytes)
                return try sealed.withUnsafeBytes { sealedBytes in
                    guard sealedBytes.count >= tagByteCount else {
                        throw ETProtocolError.ciphertextTooShort(
                            minimum: tagByteCount,
                            actual: sealedBytes.count
                        )
                    }

                    let subkey = hsalsa20(key: keyBytes, nonce: nonceBytes)
                    return try subkey.withUnsafeBytes { subkeyBytes in
                        let initialBlock = salsa20Block(
                            key: subkeyBytes,
                            nonce: UnsafeRawBufferPointer(
                                start: nonceBytes.baseAddress?.advanced(by: 16),
                                count: 8
                            ),
                            counter: 0
                        )
                        let ciphertext = UnsafeRawBufferPointer(
                            start: sealedBytes.baseAddress?.advanced(by: tagByteCount),
                            count: sealedBytes.count - tagByteCount
                        )

                        var authenticationKey = [UInt8](repeating: 0, count: 32)
                        authenticationKey.withUnsafeMutableBytes { keyBuffer in
                            storeFirstEightWords(initialBlock, into: keyBuffer)
                        }
                        var expectedTag = [UInt8](repeating: 0, count: tagByteCount)
                        authenticationKey.withUnsafeBytes { authenticationKeyBytes in
                            expectedTag.withUnsafeMutableBytes { tagBytes in
                                Poly1305.authenticate(
                                    ciphertext,
                                    key: authenticationKeyBytes,
                                    into: tagBytes
                                )
                            }
                        }
                        let isValid = expectedTag.withUnsafeBytes { expectedTagBytes in
                            constantTimeEqual(
                                UnsafeRawBufferPointer(
                                    start: sealedBytes.baseAddress,
                                    count: tagByteCount
                                ),
                                expectedTagBytes
                            )
                        }
                        guard isValid else { throw ETProtocolError.authenticationFailed }

                        var message = Data(count: ciphertext.count)
                        message.withUnsafeMutableBytes { messageBytes in
                            xor(
                                ciphertext,
                                into: messageBytes,
                                key: subkeyBytes,
                                nonce: nonceBytes,
                                initialBlock: initialBlock
                            )
                        }
                        return message
                    }
                }
            }
        }
    }

    private static func validate(
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer
    ) throws {
        guard key.count == keyByteCount else {
            throw ETProtocolError.invalidKeyLength(expected: keyByteCount, actual: key.count)
        }
        guard nonce.count == nonceByteCount else {
            throw ETProtocolError.invalidNonceLength(expected: nonceByteCount, actual: nonce.count)
        }
    }

    private static func xor(
        _ input: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer,
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer,
        initialBlock: SalsaState
    ) {
        guard !input.isEmpty else { return }
        let streamNonce = UnsafeRawBufferPointer(
            start: nonce.baseAddress?.advanced(by: 16),
            count: 8
        )
        var inputOffset = 0
        for wordIndex in 8..<16 where inputOffset < input.count {
            xorWord(
                initialBlock[wordIndex],
                input: input,
                output: output,
                offset: inputOffset
            )
            inputOffset += min(4, input.count - inputOffset)
        }

        var counter: UInt64 = 1
        while inputOffset < input.count {
            let block = salsa20Block(key: key, nonce: streamNonce, counter: counter)
            for wordIndex in 0..<16 where inputOffset < input.count {
                xorWord(block[wordIndex], input: input, output: output, offset: inputOffset)
                inputOffset += min(4, input.count - inputOffset)
            }
            counter &+= 1
        }
    }

    @inline(__always)
    private static func xorWord(
        _ word: UInt32,
        input: UnsafeRawBufferPointer,
        output: UnsafeMutableRawBufferPointer,
        offset: Int
    ) {
        let count = min(4, input.count - offset)
        for byteIndex in 0..<count {
            output[offset + byteIndex] = input[offset + byteIndex]
                ^ UInt8(truncatingIfNeeded: word >> UInt32(byteIndex * 8))
        }
    }

    private static func hsalsa20(
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer
    ) -> [UInt8] {
        var state = SalsaState(key: key)
        state.x6 = load32(nonce, at: 0)
        state.x7 = load32(nonce, at: 4)
        state.x8 = load32(nonce, at: 8)
        state.x9 = load32(nonce, at: 12)
        state.rounds()

        var output = [UInt8](repeating: 0, count: 32)
        output.withUnsafeMutableBytes { bytes in
            for (index, word) in [
                state.x0, state.x5, state.x10, state.x15,
                state.x6, state.x7, state.x8, state.x9,
            ].enumerated() {
                store32(word, into: bytes, at: index * 4)
            }
        }
        return output
    }

    private static func salsa20Block(
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer,
        counter: UInt64
    ) -> SalsaState {
        var original = SalsaState(key: key)
        original.x6 = load32(nonce, at: 0)
        original.x7 = load32(nonce, at: 4)
        original.x8 = UInt32(truncatingIfNeeded: counter)
        original.x9 = UInt32(truncatingIfNeeded: counter >> 32)
        var state = original
        state.rounds()
        state.add(original)
        return state
    }

    private static func storeFirstEightWords(
        _ state: SalsaState,
        into bytes: UnsafeMutableRawBufferPointer
    ) {
        for index in 0..<8 {
            store32(state[index], into: bytes, at: index * 4)
        }
    }

    @inline(__always)
    private static func load32(_ bytes: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    @inline(__always)
    private static func store32(
        _ value: UInt32,
        into bytes: UnsafeMutableRawBufferPointer,
        at offset: Int
    ) {
        bytes[offset] = UInt8(truncatingIfNeeded: value)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    @inline(__always)
    private static func constantTimeEqual(
        _ lhs: UnsafeRawBufferPointer,
        _ rhs: UnsafeRawBufferPointer
    ) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    private struct SalsaState {
        var x0: UInt32 = 0x6170_7865
        var x1: UInt32
        var x2: UInt32
        var x3: UInt32
        var x4: UInt32
        var x5: UInt32 = 0x3320_646e
        var x6: UInt32 = 0
        var x7: UInt32 = 0
        var x8: UInt32 = 0
        var x9: UInt32 = 0
        var x10: UInt32 = 0x7962_2d32
        var x11: UInt32
        var x12: UInt32
        var x13: UInt32
        var x14: UInt32
        var x15: UInt32 = 0x6b20_6574

        init(key: UnsafeRawBufferPointer) {
            x1 = XSalsa20Poly1305.load32(key, at: 0)
            x2 = XSalsa20Poly1305.load32(key, at: 4)
            x3 = XSalsa20Poly1305.load32(key, at: 8)
            x4 = XSalsa20Poly1305.load32(key, at: 12)
            x11 = XSalsa20Poly1305.load32(key, at: 16)
            x12 = XSalsa20Poly1305.load32(key, at: 20)
            x13 = XSalsa20Poly1305.load32(key, at: 24)
            x14 = XSalsa20Poly1305.load32(key, at: 28)
        }

        subscript(index: Int) -> UInt32 {
            switch index {
            case 0: x0
            case 1: x1
            case 2: x2
            case 3: x3
            case 4: x4
            case 5: x5
            case 6: x6
            case 7: x7
            case 8: x8
            case 9: x9
            case 10: x10
            case 11: x11
            case 12: x12
            case 13: x13
            case 14: x14
            case 15: x15
            default: preconditionFailure("Invalid Salsa20 state index")
            }
        }

        @inline(__always)
        mutating func rounds() {
            for _ in 0..<10 {
                x4 ^= rotateLeft(x0 &+ x12, by: 7)
                x8 ^= rotateLeft(x4 &+ x0, by: 9)
                x12 ^= rotateLeft(x8 &+ x4, by: 13)
                x0 ^= rotateLeft(x12 &+ x8, by: 18)
                x9 ^= rotateLeft(x5 &+ x1, by: 7)
                x13 ^= rotateLeft(x9 &+ x5, by: 9)
                x1 ^= rotateLeft(x13 &+ x9, by: 13)
                x5 ^= rotateLeft(x1 &+ x13, by: 18)
                x14 ^= rotateLeft(x10 &+ x6, by: 7)
                x2 ^= rotateLeft(x14 &+ x10, by: 9)
                x6 ^= rotateLeft(x2 &+ x14, by: 13)
                x10 ^= rotateLeft(x6 &+ x2, by: 18)
                x3 ^= rotateLeft(x15 &+ x11, by: 7)
                x7 ^= rotateLeft(x3 &+ x15, by: 9)
                x11 ^= rotateLeft(x7 &+ x3, by: 13)
                x15 ^= rotateLeft(x11 &+ x7, by: 18)

                x1 ^= rotateLeft(x0 &+ x3, by: 7)
                x2 ^= rotateLeft(x1 &+ x0, by: 9)
                x3 ^= rotateLeft(x2 &+ x1, by: 13)
                x0 ^= rotateLeft(x3 &+ x2, by: 18)
                x6 ^= rotateLeft(x5 &+ x4, by: 7)
                x7 ^= rotateLeft(x6 &+ x5, by: 9)
                x4 ^= rotateLeft(x7 &+ x6, by: 13)
                x5 ^= rotateLeft(x4 &+ x7, by: 18)
                x11 ^= rotateLeft(x10 &+ x9, by: 7)
                x8 ^= rotateLeft(x11 &+ x10, by: 9)
                x9 ^= rotateLeft(x8 &+ x11, by: 13)
                x10 ^= rotateLeft(x9 &+ x8, by: 18)
                x12 ^= rotateLeft(x15 &+ x14, by: 7)
                x13 ^= rotateLeft(x12 &+ x15, by: 9)
                x14 ^= rotateLeft(x13 &+ x12, by: 13)
                x15 ^= rotateLeft(x14 &+ x13, by: 18)
            }
        }

        @inline(__always)
        mutating func add(_ other: SalsaState) {
            x0 &+= other.x0
            x1 &+= other.x1
            x2 &+= other.x2
            x3 &+= other.x3
            x4 &+= other.x4
            x5 &+= other.x5
            x6 &+= other.x6
            x7 &+= other.x7
            x8 &+= other.x8
            x9 &+= other.x9
            x10 &+= other.x10
            x11 &+= other.x11
            x12 &+= other.x12
            x13 &+= other.x13
            x14 &+= other.x14
            x15 &+= other.x15
        }

        @inline(__always)
        private func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
            (value << count) | (value >> (32 - count))
        }
    }
}
