import Foundation

extension Data {
    init(hex: String) {
        let compact = hex.filter { !$0.isWhitespace }
        precondition(compact.count.isMultiple(of: 2))
        var bytes: [UInt8] = []
        bytes.reserveCapacity(compact.count / 2)
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            bytes.append(UInt8(compact[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}

struct DeterministicBytes {
    private var state: UInt64 = 0x6a09_e667_f3bc_c909

    mutating func bytes(count: Int) -> [UInt8] {
        (0..<count).map { _ in
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: state >> 32)
        }
    }
}
