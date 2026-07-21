import ETCore
import Foundation

/// Opaque reliable-stream state required to resume an ET session in a new process.
///
/// Store this checkpoint alongside the client identifier. Keep the passkey in a
/// credential store and provide it separately when restoring the session.
public struct ETSessionCheckpoint: Codable, Equatable, Sendable {
    package let reader: BackedReaderCheckpoint
    package let writer: BackedWriterCheckpoint

    package init(reader: BackedReaderCheckpoint, writer: BackedWriterCheckpoint) {
        self.reader = reader
        self.writer = writer
    }
}
