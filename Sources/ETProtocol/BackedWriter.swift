import Foundation

public enum BackedWriterWriteState: Equatable, Sendable {
    case skipped
    case success
    case bufferedOnly
}

public struct BackedWriterWrite: Sendable {
    public let state: BackedWriterWriteState
    public let framedBytes: Data?

    init(state: BackedWriterWriteState, framedBytes: Data? = nil) {
        self.state = state
        self.framedBytes = framedBytes
    }
}

public actor BackedWriter {
    public static let maximumBackupBytes = 64 * 1024 * 1024
    public static let disconnectBufferBytes = 64 * 1024 * 1024

    private var crypto: SecretBoxState
    private var isConnected: Bool
    private var backupBuffer: [Packet] = []
    private var backupSize = 0
    private var disconnectedBytes = 0
    private var sequenceNumber: Int64 = 0

    public init<Key: ContiguousBytes & Sendable>(
        key: Key,
        nonceMostSignificantByte: UInt8,
        connected: Bool = true
    ) throws {
        crypto = try SecretBoxState(
            key: key.withUnsafeBytes { Array($0) },
            nonceMostSignificantByte: nonceMostSignificantByte
        )
        isConnected = connected
    }

    public func write(_ packet: Packet) throws -> BackedWriterWrite {
        guard !packet.encrypted else {
            throw ETProtocolError.packetAlreadyEncrypted
        }

        if !isConnected {
            let (prospectiveBytes, overflow) = disconnectedBytes.addingReportingOverflow(packet.wireLength)
            if overflow || prospectiveBytes > Self.disconnectBufferBytes {
                return BackedWriterWrite(state: .skipped)
            }
        }

        let encryptedPayload = try crypto.seal(Array(packet.payload))
        let encryptedPacket = Packet(
            encrypted: true,
            header: packet.header,
            payload: encryptedPayload
        )
        let encryptedLength = encryptedPacket.wireLength

        let (nextBackupSize, backupOverflow) = backupSize.addingReportingOverflow(encryptedLength)
        guard !backupOverflow else { throw ETProtocolError.arithmeticOverflow }
        let (nextSequenceNumber, sequenceOverflow) = sequenceNumber.addingReportingOverflow(1)
        guard !sequenceOverflow else { throw ETProtocolError.sequenceNumberOverflow }

        backupBuffer.append(encryptedPacket)
        backupSize = nextBackupSize
        sequenceNumber = nextSequenceNumber

        if isConnected {
            while backupSize > Self.maximumBackupBytes, !backupBuffer.isEmpty {
                backupSize -= backupBuffer.removeFirst().wireLength
            }
            return BackedWriterWrite(
                state: .success,
                framedBytes: try encryptedPacket.framed()
            )
        }

        let (nextDisconnectedBytes, disconnectedOverflow) = disconnectedBytes.addingReportingOverflow(
            encryptedLength
        )
        guard !disconnectedOverflow else { throw ETProtocolError.arithmeticOverflow }
        disconnectedBytes = nextDisconnectedBytes
        return BackedWriterWrite(state: .bufferedOnly)
    }

    public func hasBufferCapacity(forByteCount byteCount: Int) throws -> Bool {
        guard byteCount >= 0 else { throw ETProtocolError.invalidCapacity(byteCount) }
        guard !isConnected else { return true }
        let (prospectiveBytes, overflow) = disconnectedBytes.addingReportingOverflow(byteCount)
        return !overflow && prospectiveBytes <= Self.disconnectBufferBytes
    }

    public func recover(after lastValidSequenceNumber: Int64) throws -> [Data] {
        guard !isConnected else { throw ETProtocolError.recoveryRequiresDisconnected }
        guard lastValidSequenceNumber >= 0, lastValidSequenceNumber <= sequenceNumber else {
            throw ETProtocolError.sequenceNumberOutOfRange
        }
        let requested = sequenceNumber - lastValidSequenceNumber
        guard requested > 0 else { return [] }
        guard let requestedCount = Int(exactly: requested), requestedCount <= backupBuffer.count else {
            throw ETProtocolError.recoveryUnavailable(
                requested: requested,
                available: backupBuffer.count
            )
        }
        return backupBuffer.suffix(requestedCount).map { $0.serialized() }
    }

    public func catchupBuffer(after lastValidSequenceNumber: Int64) throws -> Et_CatchupBuffer {
        var catchup = Et_CatchupBuffer()
        catchup.buffer = try recover(after: lastValidSequenceNumber)
        return catchup
    }

    public func invalidate() {
        isConnected = false
    }

    public func revive() {
        isConnected = true
        disconnectedBytes = 0
    }

    public func currentSequenceNumber() -> Int64 {
        sequenceNumber
    }
}
