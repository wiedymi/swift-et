import ETCore
import ETCrypto
import Foundation
import XCTest

@MainActor
final class BackedIOTests: XCTestCase {
    private let key = Data("12345678901234567890123456789012".utf8)

    func testWriterReaderRoundTripAcrossPartialFrames() async throws {
        let writer = try BackedWriter(
            key: key,
            nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
        )
        let reader = try BackedReader(
            key: key,
            nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
        )
        let input = (0..<20).map { index in
            Packet(header: UInt8(index), payload: Data(repeating: UInt8(index), count: index * 7))
        }
        var stream = Data()
        for packet in input {
            let result = try await writer.write(packet)
            XCTAssertEqual(result.state, .success)
            stream.append(try XCTUnwrap(result.framedBytes))
        }

        var output: [Packet] = []
        var offset = 0
        var chunkSize = 1
        while offset < stream.count {
            let end = min(stream.count, offset + chunkSize)
            output += try await reader.receive(Data(stream[offset..<end]))
            offset = end
            chunkSize = chunkSize % 17 + 1
        }

        XCTAssertEqual(output, input)
        let sequenceNumber = await reader.currentSequenceNumber()
        XCTAssertEqual(sequenceNumber, Int64(input.count))
    }

    func testCatchupConvergesForEveryDroppedByteOffset() async throws {
        var input: [Packet] = []
        for index in 0..<8 {
            let payloadCount = index * 5 + 1
            let payload = (0..<payloadCount).map { byteIndex in
                UInt8(truncatingIfNeeded: byteIndex + index)
            }
            input.append(Packet(header: UInt8(index + 30), payload: Data(payload)))
        }
        let completeStream = try await framedStream(for: input)

        for dropOffset in 0...completeStream.count {
            let writer = try BackedWriter(
                key: key,
                nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
            )
            let reader = try BackedReader(
                key: key,
                nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
            )
            var liveStream = Data()
            for packet in input {
                let write = try await writer.write(packet)
                liveStream.append(try XCTUnwrap(write.framedBytes))
            }
            XCTAssertEqual(liveStream, completeStream)

            var received = try await reader.receive(Data(liveStream.prefix(dropOffset)))
            await reader.invalidate()
            await writer.invalidate()
            let lastSeen = await reader.currentSequenceNumber()
            let recovered = try await writer.recover(after: lastSeen)
            try await reader.revive(with: recovered)
            await writer.revive()
            received += try await reader.receive()

            XCTAssertEqual(received, input, "drop offset: \(dropOffset)")
            let finalSequenceNumber = await reader.currentSequenceNumber()
            XCTAssertEqual(
                finalSequenceNumber,
                Int64(input.count),
                "drop offset: \(dropOffset)"
            )
        }
    }

    func testRecoveryIsOldestFirstAndReplaysOriginalCiphertext() async throws {
        let writer = try BackedWriter(
            key: key,
            nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
        )
        let packets = [
            Packet(header: 1, payload: Data("first".utf8)),
            Packet(header: 2, payload: Data("second".utf8)),
            Packet(header: 3, payload: Data("third".utf8)),
        ]
        var serializedCiphertext: [Data] = []
        for packet in packets {
            let write = try await writer.write(packet)
            let frame = try XCTUnwrap(write.framedBytes)
            serializedCiphertext.append(Data(frame.dropFirst(4)))
        }

        await writer.invalidate()
        let completeRecovery = try await writer.recover(after: 0)
        let partialRecovery = try await writer.recover(after: 1)
        XCTAssertEqual(completeRecovery, serializedCiphertext)
        XCTAssertEqual(partialRecovery, Array(serializedCiphertext.suffix(2)))

        let catchup = try await writer.catchupBuffer(after: 2)
        XCTAssertEqual(catchup.buffer, [serializedCiphertext[2]])
        do {
            _ = try await writer.recover(after: 4)
            XCTFail("Expected an out-of-range recovery to fail")
        } catch {
            XCTAssertEqual(error as? ETProtocolError, .sequenceNumberOutOfRange)
        }
    }

    func testDisconnectedWritesAreBufferedAndCapacityIsBounded() async throws {
        let writer = try BackedWriter(
            key: key,
            nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
        )
        await writer.invalidate()
        let initialCapacity = try await writer.hasBufferCapacity(forByteCount: 1_024)
        XCTAssertTrue(initialCapacity)

        let packet = Packet(header: 1, payload: Data("buffered".utf8))
        let result = try await writer.write(packet)
        XCTAssertEqual(result.state, .bufferedOnly)
        XCTAssertNil(result.framedBytes)
        let bufferedSequenceNumber = await writer.currentSequenceNumber()
        XCTAssertEqual(bufferedSequenceNumber, 1)

        let remainingCapacity = try await writer.hasBufferCapacity(
            forByteCount: BackedWriter.disconnectBufferBytes
        )
        XCTAssertFalse(remainingCapacity)
        await writer.revive()
        let revivedCapacity = try await writer.hasBufferCapacity(forByteCount: Int.max)
        XCTAssertTrue(revivedCapacity)
    }

    func testSequenceHeaderAndCatchupSequenceAccounting() async throws {
        let encryptor = try SecretBox(
            key: key,
            nonceMostSignificantByte: SecretBox.serverToClientNonceMostSignificantByte
        )
        let reader = try BackedReader(
            key: key,
            nonceMostSignificantByte: SecretBox.serverToClientNonceMostSignificantByte,
            connected: false
        )
        var recovered: [Data] = []
        for index in 0..<3 {
            let encrypted = try await encryptor.seal(Data([UInt8(index)]))
            recovered.append(Packet(encrypted: true, header: UInt8(index), payload: encrypted).serialized())
        }

        try await reader.revive(with: recovered)
        let sequenceHeader = try await reader.sequenceHeader()
        let sequenceBeforeDrain = await reader.currentSequenceNumber()
        let recoveredPackets = try await reader.receive()
        let sequenceAfterDrain = await reader.currentSequenceNumber()
        XCTAssertEqual(sequenceHeader.sequenceNumber, 3)
        XCTAssertEqual(sequenceBeforeDrain, 3)
        XCTAssertEqual(recoveredPackets.map(\.payload), [Data([0]), Data([1]), Data([2])])
        XCTAssertEqual(sequenceAfterDrain, 3)
    }

    private func framedStream(for packets: [Packet]) async throws -> Data {
        let writer = try BackedWriter(
            key: key,
            nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
        )
        var stream = Data()
        for packet in packets {
            let write = try await writer.write(packet)
            stream.append(try XCTUnwrap(write.framedBytes))
        }
        return stream
    }
}
