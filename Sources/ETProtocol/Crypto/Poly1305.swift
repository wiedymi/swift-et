import Foundation

public enum Poly1305 {
    public static let keyByteCount = 32
    public static let tagByteCount = 16

    public static func authenticate<Message: ContiguousBytes, Key: ContiguousBytes>(
        _ message: Message,
        key: Key
    ) throws -> Data {
        let keyBytes = key.withUnsafeBytes { Array($0) }
        guard keyBytes.count == keyByteCount else {
            throw ETProtocolError.invalidKeyLength(
                expected: keyByteCount,
                actual: keyBytes.count
            )
        }
        let messageBytes = message.withUnsafeBytes { Array($0) }
        return Data(authenticate(messageBytes, key: keyBytes))
    }

    static func authenticate(_ message: [UInt8], key: [UInt8]) -> [UInt8] {
        let mask26: UInt64 = 0x3ff_ffff
        let r0 = UInt64(load32(key, at: 0)) & 0x3ff_ffff
        let r1 = (UInt64(load32(key, at: 3)) >> 2) & 0x3ff_ff03
        let r2 = (UInt64(load32(key, at: 6)) >> 4) & 0x3ff_c0ff
        let r3 = (UInt64(load32(key, at: 9)) >> 6) & 0x3f0_3fff
        let r4 = (UInt64(load32(key, at: 12)) >> 8) & 0x00f_ffff

        let s1 = r1 * 5
        let s2 = r2 * 5
        let s3 = r3 * 5
        let s4 = r4 * 5

        var h0: UInt64 = 0
        var h1: UInt64 = 0
        var h2: UInt64 = 0
        var h3: UInt64 = 0
        var h4: UInt64 = 0

        @inline(__always)
        func process(_ block: [UInt8], at offset: Int, highBit: UInt64) -> (
            UInt64, UInt64, UInt64, UInt64, UInt64
        ) {
            var blockH0 = h0 + (UInt64(load32(block, at: offset)) & mask26)
            var blockH1 = h1 + ((UInt64(load32(block, at: offset + 3)) >> 2) & mask26)
            var blockH2 = h2 + ((UInt64(load32(block, at: offset + 6)) >> 4) & mask26)
            var blockH3 = h3 + ((UInt64(load32(block, at: offset + 9)) >> 6) & mask26)
            var blockH4 = h4 + ((UInt64(load32(block, at: offset + 12)) >> 8) | highBit)

            let d0 = blockH0 * r0 + blockH1 * s4 + blockH2 * s3 + blockH3 * s2 + blockH4 * s1
            let d1 = blockH0 * r1 + blockH1 * r0 + blockH2 * s4 + blockH3 * s3 + blockH4 * s2
            let d2 = blockH0 * r2 + blockH1 * r1 + blockH2 * r0 + blockH3 * s4 + blockH4 * s3
            let d3 = blockH0 * r3 + blockH1 * r2 + blockH2 * r1 + blockH3 * r0 + blockH4 * s4
            let d4 = blockH0 * r4 + blockH1 * r3 + blockH2 * r2 + blockH3 * r1 + blockH4 * r0

            var carry = d0 >> 26
            blockH0 = d0 & mask26
            var accumulator = d1 + carry
            carry = accumulator >> 26
            blockH1 = accumulator & mask26
            accumulator = d2 + carry
            carry = accumulator >> 26
            blockH2 = accumulator & mask26
            accumulator = d3 + carry
            carry = accumulator >> 26
            blockH3 = accumulator & mask26
            accumulator = d4 + carry
            carry = accumulator >> 26
            blockH4 = accumulator & mask26
            blockH0 += carry * 5
            carry = blockH0 >> 26
            blockH0 &= mask26
            blockH1 += carry

            return (blockH0, blockH1, blockH2, blockH3, blockH4)
        }

        var offset = 0
        while message.count - offset >= 16 {
            (h0, h1, h2, h3, h4) = process(message, at: offset, highBit: 1 << 24)
            offset += 16
        }

        if offset < message.count {
            var block = [UInt8](repeating: 0, count: 16)
            let remaining = message.count - offset
            block.replaceSubrange(0..<remaining, with: message[offset...])
            block[remaining] = 1
            (h0, h1, h2, h3, h4) = process(block, at: 0, highBit: 0)
        }

        var carry = h1 >> 26
        h1 &= mask26
        h2 += carry
        carry = h2 >> 26
        h2 &= mask26
        h3 += carry
        carry = h3 >> 26
        h3 &= mask26
        h4 += carry
        carry = h4 >> 26
        h4 &= mask26
        h0 += carry * 5
        carry = h0 >> 26
        h0 &= mask26
        h1 += carry

        var g0 = h0 + 5
        carry = g0 >> 26
        g0 &= mask26
        var g1 = h1 + carry
        carry = g1 >> 26
        g1 &= mask26
        var g2 = h2 + carry
        carry = g2 >> 26
        g2 &= mask26
        var g3 = h3 + carry
        carry = g3 >> 26
        g3 &= mask26
        var g4 = h4 + carry
        g4 = g4 &- (1 << 26)

        let selectG = (g4 >> 63) &- 1
        let selectH = ~selectG
        h0 = (h0 & selectH) | (g0 & selectG)
        h1 = (h1 & selectH) | (g1 & selectG)
        h2 = (h2 & selectH) | (g2 & selectG)
        h3 = (h3 & selectH) | (g3 & selectG)
        h4 = (h4 & selectH) | ((g4 & mask26) & selectG)

        var f0 = ((h0 | (h1 << 26)) & 0xffff_ffff) + UInt64(load32(key, at: 16))
        var f1 = (((h1 >> 6) | (h2 << 20)) & 0xffff_ffff)
            + UInt64(load32(key, at: 20))
            + (f0 >> 32)
        var f2 = (((h2 >> 12) | (h3 << 14)) & 0xffff_ffff)
            + UInt64(load32(key, at: 24))
            + (f1 >> 32)
        let f3 = (((h3 >> 18) | (h4 << 8)) & 0xffff_ffff)
            + UInt64(load32(key, at: 28))
            + (f2 >> 32)
        f0 &= 0xffff_ffff
        f1 &= 0xffff_ffff
        f2 &= 0xffff_ffff

        var tag = [UInt8](repeating: 0, count: tagByteCount)
        store32(UInt32(f0), into: &tag, at: 0)
        store32(UInt32(f1), into: &tag, at: 4)
        store32(UInt32(f2), into: &tag, at: 8)
        store32(UInt32(f3 & 0xffff_ffff), into: &tag, at: 12)
        return tag
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
}
