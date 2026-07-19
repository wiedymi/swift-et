import Foundation

/// Heap-backed secret bytes that are overwritten when the final reference is released.
///
/// Safety invariant: storage is initialized once and exposed only through immutable
/// `ContiguousBytes` borrows. Its sole mutation occurs during exclusive ARC deinitialization.
package final class SecretKey: ContiguousBytes, @unchecked Sendable {
    private var bytes: [UInt8]

    package init<Bytes: ContiguousBytes>(_ bytes: Bytes) {
        self.bytes = bytes.withUnsafeBytes { Array($0) }
    }

    package func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
    ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
    }

    deinit {
        _ = bytes.withUnsafeMutableBytes { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }
}
