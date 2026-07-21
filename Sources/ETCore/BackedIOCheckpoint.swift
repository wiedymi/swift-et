import Foundation

package struct BackedReaderCheckpoint: Codable, Equatable, Sendable {
    package let nonce: Data
    package let sequenceNumber: Int64
}

package struct BackedWriterCheckpoint: Codable, Equatable, Sendable {
    package let nonce: Data
    package let sequenceNumber: Int64
    package let serializedBackupPackets: [Data]
}
