import Foundation

public actor BackedReader {
    public static let maximumFrameBytes = Int(Int32.max)

    private var crypto: SecretBoxState
    private var isConnected: Bool
    private var sequenceNumber: Int64 = 0
    private var localBuffer: [Data] = []
    private var localBufferIndex = 0
    private var partialMessage = Data()

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

    public func receive(_ bytes: Data = Data()) throws -> [Packet] {
        guard isConnected else { return [] }
        var packets: [Packet] = []

        while localBufferIndex < localBuffer.count {
            let serialized = localBuffer[localBufferIndex]
            localBufferIndex += 1
            packets.append(try decrypt(serializedPacket: serialized))
        }
        if localBufferIndex == localBuffer.count, !localBuffer.isEmpty {
            localBuffer.removeAll(keepingCapacity: true)
            localBufferIndex = 0
        }

        partialMessage.append(bytes)
        var consumed = 0
        while partialMessage.count - consumed >= 4 {
            let length = try frameLength(in: partialMessage, at: consumed)
            let (totalLength, overflow) = length.addingReportingOverflow(4)
            guard !overflow else { throw ETProtocolError.invalidFrameLength(length) }
            guard partialMessage.count - consumed >= totalLength else { break }

            let packetStart = partialMessage.index(
                partialMessage.startIndex,
                offsetBy: consumed + 4
            )
            let packetEnd = partialMessage.index(packetStart, offsetBy: length)
            let serialized = Data(partialMessage[packetStart..<packetEnd])
            let packet = try decrypt(serializedPacket: serialized)
            let (nextSequenceNumber, sequenceOverflow) = sequenceNumber.addingReportingOverflow(1)
            guard !sequenceOverflow else { throw ETProtocolError.sequenceNumberOverflow }
            sequenceNumber = nextSequenceNumber
            packets.append(packet)
            consumed += totalLength
        }

        if consumed > 0 {
            partialMessage = Data(partialMessage.dropFirst(consumed))
        }
        return packets
    }

    public func invalidate() {
        isConnected = false
    }

    public func revive(with recoveredSerializedPackets: [Data]) throws {
        partialMessage.removeAll(keepingCapacity: true)
        if localBufferIndex > 0 {
            localBuffer.removeFirst(localBufferIndex)
            localBufferIndex = 0
        }
        localBuffer.append(contentsOf: recoveredSerializedPackets)
        guard let recoveredCount = Int64(exactly: recoveredSerializedPackets.count) else {
            throw ETProtocolError.sequenceNumberOverflow
        }
        let (nextSequenceNumber, overflow) = sequenceNumber.addingReportingOverflow(recoveredCount)
        guard !overflow else { throw ETProtocolError.sequenceNumberOverflow }
        sequenceNumber = nextSequenceNumber
        isConnected = true
    }

    public func sequenceHeader() throws -> Et_SequenceHeader {
        guard let wireSequenceNumber = Int32(exactly: sequenceNumber) else {
            throw ETProtocolError.sequenceNumberOutOfRange
        }
        var header = Et_SequenceHeader()
        header.sequenceNumber = wireSequenceNumber
        return header
    }

    public func currentSequenceNumber() -> Int64 {
        sequenceNumber
    }

    public func hasRecoveredPackets() -> Bool {
        localBufferIndex < localBuffer.count
    }

    private func frameLength(in bytes: Data, at offset: Int) throws -> Int {
        let start = bytes.index(bytes.startIndex, offsetBy: offset)
        let value = (UInt32(bytes[start]) << 24)
            | (UInt32(bytes[bytes.index(start, offsetBy: 1)]) << 16)
            | (UInt32(bytes[bytes.index(start, offsetBy: 2)]) << 8)
            | UInt32(bytes[bytes.index(start, offsetBy: 3)])
        guard value <= UInt32(Int32.max) else {
            throw ETProtocolError.invalidFrameLength(Int(value))
        }
        let length = Int(value)
        guard length >= 2, length <= Self.maximumFrameBytes else {
            throw ETProtocolError.invalidFrameLength(length)
        }
        return length
    }

    private func decrypt(serializedPacket: Data) throws -> Packet {
        let encryptedPacket = try Packet(serialized: serializedPacket)
        guard encryptedPacket.encrypted else {
            throw ETProtocolError.packetNotEncrypted
        }
        let plaintext = try crypto.open(encryptedPacket.payload)
        return Packet(
            encrypted: false,
            header: encryptedPacket.header,
            payload: plaintext
        )
    }
}
