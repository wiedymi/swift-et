import ETCrypto
import Foundation

/// Result state for a reliable writer operation.
public enum BackedWriterWriteState: Equatable, Sendable {
    /// The disconnected buffer had no remaining capacity.
    case skipped
    /// Ciphertext was produced for immediate transport.
    case success
    /// Ciphertext was retained for recovery while disconnected.
    case bufferedOnly
}

/// The result of encrypting and sequencing one packet.
public struct BackedWriterWrite: Sendable {
    /// How the writer handled the packet.
    public let state: BackedWriterWriteState
    /// Original framed ciphertext when it should be written immediately.
    public let framedBytes: Data?

    init(state: BackedWriterWriteState, framedBytes: Data? = nil) {
        self.state = state
        self.framedBytes = framedBytes
    }
}

/// Encrypts packets and retains original ciphertext for reconnect catchup.
public actor BackedWriter {
    /// Maximum retained ciphertext window.
    public static let maximumBackupBytes = 64 * 1024 * 1024
    /// Maximum data accepted while disconnected.
    public static let disconnectBufferBytes = 64 * 1024 * 1024

    private var crypto: SecretBoxState
    private var isConnected: Bool
    private var backupBuffer: [Packet] = []
    private var backupSize = 0
    private var disconnectedBytes = 0
    private var sequenceNumber: Int64 = 0

    /// Creates a writer for one directional nonce stream.
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

    package init<Key: ContiguousBytes & Sendable>(
        key: Key,
        checkpoint: BackedWriterCheckpoint
    ) throws {
        guard checkpoint.sequenceNumber >= 0,
              let packetCount = Int64(exactly: checkpoint.serializedBackupPackets.count),
              packetCount <= checkpoint.sequenceNumber else {
            throw ETProtocolError.sequenceNumberOutOfRange
        }
        let restoredPackets = try checkpoint.serializedBackupPackets.map(Packet.init(serialized:))
        guard restoredPackets.allSatisfy(\.encrypted) else {
            throw ETProtocolError.packetNotEncrypted
        }
        var restoredSize = 0
        for packet in restoredPackets {
            let (nextSize, overflow) = restoredSize.addingReportingOverflow(packet.wireLength)
            guard !overflow, nextSize <= Self.maximumBackupBytes else {
                throw ETProtocolError.arithmeticOverflow
            }
            restoredSize = nextSize
        }
        crypto = try SecretBoxState(
            key: key.withUnsafeBytes { Array($0) },
            nonce: checkpoint.nonce
        )
        isConnected = false
        backupBuffer = restoredPackets
        backupSize = restoredSize
        sequenceNumber = checkpoint.sequenceNumber
    }

    /// Encrypts, sequences, and optionally frames one packet.
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

        let encryptedPayload = try crypto.seal(packet.payload)
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

    /// Reports whether a disconnected write of the given size can be accepted.
    public func hasBufferCapacity(forByteCount byteCount: Int) throws -> Bool {
        guard byteCount >= 0 else { throw ETProtocolError.invalidCapacity(byteCount) }
        guard !isConnected else { return true }
        let (prospectiveBytes, overflow) = disconnectedBytes.addingReportingOverflow(byteCount)
        return !overflow && prospectiveBytes <= Self.disconnectBufferBytes
    }

    /// Returns original serialized ciphertext after a peer's last valid sequence number.
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

    /// Builds the protobuf catchup payload for a reconnect handshake.
    public func catchupBuffer(after lastValidSequenceNumber: Int64) throws -> Et_CatchupBuffer {
        var catchup = Et_CatchupBuffer()
        catchup.buffer = try recover(after: lastValidSequenceNumber)
        return catchup
    }

    /// Marks the writer disconnected while retaining its ciphertext window.
    public func invalidate() {
        isConnected = false
    }

    /// Marks a recovered writer connected and resets disconnected-byte accounting.
    public func revive() {
        isConnected = true
        disconnectedBytes = 0
    }

    /// Returns the full-width local sequence number.
    public func currentSequenceNumber() -> Int64 {
        sequenceNumber
    }

    package func checkpoint() -> BackedWriterCheckpoint {
        BackedWriterCheckpoint(
            nonce: crypto.checkpointNonce,
            sequenceNumber: sequenceNumber,
            serializedBackupPackets: backupBuffer.map { $0.serialized() }
        )
    }
}
