import ETProtocol
import Foundation
import Sodium

private struct Measurement: Sendable {
    let benchmark: String
    let size: Int
    let implementation: String
    let iterations: Int
    let seconds: Double
    let megabytesPerSecond: Double
    let ratio: Double?
    let gate: String
}

private enum BenchmarkError: Error {
    case sodiumFailure
    case invalidRoundTrip
    case writerDidNotProduceFrame
}

@main
private struct BenchmarkMain {
    private static let sizes = [64, 1_024, 65_536, 1_048_576]
    private static let bytesPerDirection = 16 * 1_024 * 1_024

    static func main() async throws {
        let key = [UInt8](0..<32)
        let nonce = [UInt8](0..<24)
        let sodium = Sodium()
        var measurements: [Measurement] = []

        print("swift-et release benchmarks")
        print("Secretbox throughput includes one encrypt and one decrypt per iteration.")
        print("Throughput counts bytes processed in both directions.")
        print("")
        print("size_bytes  pure_swift_MBps  libsodium_MBps  pure/libsodium  gate")

        for size in sizes {
            let message = deterministicBytes(count: size)
            let iterations = max(4, bytesPerDirection / size)
            let warmupIterations = max(1, min(1_024, iterations / 16))

            _ = try measurePureSwift(
                message: message,
                key: key,
                nonce: nonce,
                iterations: warmupIterations
            )
            _ = try measureSodium(
                sodium: sodium,
                message: message,
                key: key,
                nonce: nonce,
                iterations: warmupIterations
            )

            let pure = try measurePureSwift(
                message: message,
                key: key,
                nonce: nonce,
                iterations: iterations
            )
            let baseline = try measureSodium(
                sodium: sodium,
                message: message,
                key: key,
                nonce: nonce,
                iterations: iterations
            )
            let ratio = pure.megabytesPerSecond / baseline.megabytesPerSecond
            let isGatedSize = size >= 65_536
            let gate = isGatedSize ? (ratio >= 0.5 ? "PASS" : "FAIL") : "N/A"

            measurements.append(
                Measurement(
                    benchmark: "secretbox_roundtrip",
                    size: size,
                    implementation: "pure_swift",
                    iterations: iterations,
                    seconds: pure.seconds,
                    megabytesPerSecond: pure.megabytesPerSecond,
                    ratio: ratio,
                    gate: gate
                )
            )
            measurements.append(
                Measurement(
                    benchmark: "secretbox_roundtrip",
                    size: size,
                    implementation: "libsodium",
                    iterations: iterations,
                    seconds: baseline.seconds,
                    megabytesPerSecond: baseline.megabytesPerSecond,
                    ratio: 1,
                    gate: "BASELINE"
                )
            )
            print(
                String(
                    format: "%10d  %15.2f  %14.2f  %14.3f  %@",
                    size,
                    pure.megabytesPerSecond,
                    baseline.megabytesPerSecond,
                    ratio,
                    gate
                )
            )
        }

        let framing = try measurePacketFraming(size: 65_536)
        measurements.append(framing)
        let writer = try await measureBackedWriter(size: 65_536, key: key)
        measurements.append(writer)

        print("")
        print(String(format: "Packet framing 64KiB: %.2f MB/s", framing.megabytesPerSecond))
        print(String(format: "BackedWriter write 64KiB: %.2f MB/s", writer.megabytesPerSecond))
        print("")
        print("BEGIN_BENCHMARK_CSV")
        print("benchmark,size_bytes,implementation,iterations,seconds,mb_per_second,pure_over_sodium,gate")
        for measurement in measurements {
            let ratio = measurement.ratio.map { String(format: "%.6f", $0) } ?? ""
            print(
                "\(measurement.benchmark),\(measurement.size),\(measurement.implementation),"
                    + "\(measurement.iterations),\(String(format: "%.6f", measurement.seconds)),"
                    + "\(String(format: "%.6f", measurement.megabytesPerSecond)),"
                    + "\(ratio),\(measurement.gate)"
            )
        }
        print("END_BENCHMARK_CSV")
    }

    private static func measurePureSwift(
        message: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        iterations: Int
    ) throws -> (seconds: Double, megabytesPerSecond: Double) {
        var checksum: UInt8 = 0
        let start = ContinuousClock.now
        for _ in 0..<iterations {
            let sealed = try XSalsa20Poly1305.seal(message, nonce: nonce, key: key)
            let opened = try XSalsa20Poly1305.open(sealed, nonce: nonce, key: key)
            guard opened.count == message.count else { throw BenchmarkError.invalidRoundTrip }
            checksum ^= sealed[sealed.startIndex]
            if let first = opened.first { checksum ^= first }
        }
        let duration = elapsedSeconds(since: start)
        consume(checksum)
        return (duration, throughput(size: message.count, iterations: iterations, seconds: duration))
    }

    private static func measureSodium(
        sodium: Sodium,
        message: [UInt8],
        key: [UInt8],
        nonce: [UInt8],
        iterations: Int
    ) throws -> (seconds: Double, megabytesPerSecond: Double) {
        var checksum: UInt8 = 0
        let start = ContinuousClock.now
        for _ in 0..<iterations {
            guard let sealed = sodium.secretBox.seal(
                message: message,
                secretKey: key,
                nonce: nonce
            ), let opened = sodium.secretBox.open(
                authenticatedCipherText: sealed,
                secretKey: key,
                nonce: nonce
            ) else {
                throw BenchmarkError.sodiumFailure
            }
            guard opened.count == message.count else { throw BenchmarkError.invalidRoundTrip }
            checksum ^= sealed[0]
            if let first = opened.first { checksum ^= first }
        }
        let duration = elapsedSeconds(since: start)
        consume(checksum)
        return (duration, throughput(size: message.count, iterations: iterations, seconds: duration))
    }

    private static func measurePacketFraming(size: Int) throws -> Measurement {
        let packet = Packet(header: 1, payload: Data(deterministicBytes(count: size)))
        let iterations = max(16, bytesPerDirection / size)
        var checksum: UInt8 = 0
        let start = ContinuousClock.now
        for _ in 0..<iterations {
            let framed = try packet.framed()
            checksum ^= framed[framed.startIndex]
        }
        let duration = elapsedSeconds(since: start)
        consume(checksum)
        return Measurement(
            benchmark: "packet_framing",
            size: size,
            implementation: "pure_swift",
            iterations: iterations,
            seconds: duration,
            megabytesPerSecond: singleDirectionThroughput(
                size: size,
                iterations: iterations,
                seconds: duration
            ),
            ratio: nil,
            gate: "N/A"
        )
    }

    private static func measureBackedWriter(size: Int, key: [UInt8]) async throws -> Measurement {
        let packet = Packet(header: 1, payload: Data(deterministicBytes(count: size)))
        let iterations = max(16, bytesPerDirection / size)
        let writer = try BackedWriter(
            key: key,
            nonceMostSignificantByte: SecretBox.clientToServerNonceMostSignificantByte
        )
        var checksum: UInt8 = 0
        let start = ContinuousClock.now
        for _ in 0..<iterations {
            let write = try await writer.write(packet)
            guard write.state == .success, let framed = write.framedBytes else {
                throw BenchmarkError.writerDidNotProduceFrame
            }
            checksum ^= framed[framed.startIndex]
        }
        let duration = elapsedSeconds(since: start)
        consume(checksum)
        return Measurement(
            benchmark: "backed_writer_write",
            size: size,
            implementation: "pure_swift",
            iterations: iterations,
            seconds: duration,
            megabytesPerSecond: singleDirectionThroughput(
                size: size,
                iterations: iterations,
                seconds: duration
            ),
            ratio: nil,
            gate: "N/A"
        )
    }

    private static func throughput(size: Int, iterations: Int, seconds: Double) -> Double {
        2 * singleDirectionThroughput(size: size, iterations: iterations, seconds: seconds)
    }

    private static func singleDirectionThroughput(
        size: Int,
        iterations: Int,
        seconds: Double
    ) -> Double {
        Double(size * iterations) / 1_048_576 / seconds
    }

    private static func elapsedSeconds(since start: ContinuousClock.Instant) -> Double {
        let duration = start.duration(to: .now)
        let components = duration.components
        return Double(components.seconds) + Double(components.attoseconds) / 1e18
    }

    private static func deterministicBytes(count: Int) -> [UInt8] {
        (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 17) }
    }

    @inline(never)
    private static func consume(_ value: UInt8) {
        if value == 255 { print("checksum=255") }
    }
}
