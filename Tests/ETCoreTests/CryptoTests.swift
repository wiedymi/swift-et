import ETCore
import ETCrypto
import Foundation
import Sodium
import XCTest

@MainActor
final class CryptoTests: XCTestCase {
    func testPublishedPoly1305Vector() throws {
        let key = Data(hex: "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        let message = Data("Cryptographic Forum Research Group".utf8)
        let expected = Data(hex: "a8061dc1305136c6c22b8baf0c0127a9")

        XCTAssertEqual(try Poly1305.authenticate(message, key: key), expected)
    }

    func testPublishedNaClXSalsa20Poly1305Vector() throws {
        let key = Data(hex: "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
        let nonce = Data(hex: "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
        let message = Data(hex: """
            be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc
            e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31
            0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde
            048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864
            5e0705
            """)
        let expected = Data(hex: """
            f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce
            48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972
            71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae
            90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3
            7973f622a43d14a6599b1f654cb45a74e355a5
            """)

        let sealed = try XSalsa20Poly1305.seal(message, nonce: nonce, key: key)
        XCTAssertEqual(sealed, expected)
        XCTAssertEqual(try XSalsa20Poly1305.open(sealed, nonce: nonce, key: key), message)
    }

    func testMatchesLibsodiumAcrossBoundarySizes() throws {
        let sodium = Sodium()
        let lengths = [0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 1_024, 65_536, 1_048_576]
        var generator = DeterministicBytes()

        for length in lengths {
            let key = generator.bytes(count: XSalsa20Poly1305.keyByteCount)
            let nonce = generator.bytes(count: XSalsa20Poly1305.nonceByteCount)
            let message = generator.bytes(count: length)
            let sodiumCiphertext = try XCTUnwrap(
                sodium.secretBox.seal(message: message, secretKey: key, nonce: nonce)
            )
            let swiftCiphertext = try XSalsa20Poly1305.seal(message, nonce: nonce, key: key)

            XCTAssertEqual(Array(swiftCiphertext), sodiumCiphertext, "length: \(length)")
            XCTAssertEqual(
                try XSalsa20Poly1305.open(sodiumCiphertext, nonce: nonce, key: key),
                Data(message),
                "length: \(length)"
            )
            XCTAssertEqual(
                sodium.secretBox.open(
                    authenticatedCipherText: Array(swiftCiphertext),
                    secretKey: key,
                    nonce: nonce
                ),
                message,
                "length: \(length)"
            )
        }
    }

    func testRejectsTagAndCiphertextTampering() throws {
        let key = [UInt8](0..<32)
        let nonce = [UInt8](0..<24)
        let sealed = try XSalsa20Poly1305.seal([UInt8](0..<65), nonce: nonce, key: key)

        for index in [0, 15, 16, sealed.count - 1] {
            var tampered = sealed
            tampered[index] ^= 0x80
            XCTAssertThrowsError(try XSalsa20Poly1305.open(tampered, nonce: nonce, key: key)) {
                XCTAssertEqual($0 as? ETProtocolError, .authenticationFailed)
            }
        }
    }

    func testRejectsTamperedTagOnlyCiphertextAndTruncatedInput() throws {
        let key = [UInt8](0..<32)
        let nonce = [UInt8](0..<24)
        let sealed = try XSalsa20Poly1305.seal([UInt8](), nonce: nonce, key: key)
        XCTAssertEqual(sealed.count, XSalsa20Poly1305.tagByteCount)

        for index in 0..<sealed.count {
            var tampered = sealed
            tampered[index] ^= 0x01
            XCTAssertThrowsError(try XSalsa20Poly1305.open(tampered, nonce: nonce, key: key)) {
                XCTAssertEqual($0 as? ETProtocolError, .authenticationFailed)
            }
        }

        XCTAssertThrowsError(
            try XSalsa20Poly1305.open(sealed.prefix(15), nonce: nonce, key: key)
        ) {
            XCTAssertEqual(
                $0 as? ETProtocolError,
                .ciphertextTooShort(minimum: XSalsa20Poly1305.tagByteCount, actual: 15)
            )
        }
    }

    func testNonceCarryPropagatesAcrossBytesAgainstLibsodium() async throws {
        let sodium = Sodium()
        let key = Data(repeating: 3, count: 32)
        let box = try SecretBox(key: key, nonceMostSignificantByte: 1)
        let message = [UInt8]("carry".utf8)

        for _ in 0..<255 {
            _ = try await box.seal(Data(message))
        }

        // The 256th pre-increment rolls nonce byte 0 over to 0 and carries into byte 1.
        var expectedNonce = [UInt8](repeating: 0, count: 24)
        expectedNonce[0] = 0
        expectedNonce[1] = 1
        expectedNonce[23] = 1
        let expected = try XCTUnwrap(
            sodium.secretBox.seal(
                message: message,
                secretKey: Array(key),
                nonce: expectedNonce
            )
        )
        let sealed = try await box.seal(Data(message))
        XCTAssertEqual(Array(sealed), expected)
    }

    func testSecretBoxUsesPreincrementedLittleEndianNonceAndConsumesFailures() async throws {
        let key = Data(repeating: 7, count: 32)
        let encryptor = try SecretBox(key: key, nonceMostSignificantByte: 1)
        let decryptor = try SecretBox(key: key, nonceMostSignificantByte: 1)
        let firstMessage = Data("first".utf8)
        let secondMessage = Data("second".utf8)

        var firstNonce = Data(repeating: 0, count: 24)
        firstNonce[0] = 1
        firstNonce[23] = 1
        let first = try await encryptor.seal(firstMessage)
        XCTAssertEqual(first, try XSalsa20Poly1305.seal(firstMessage, nonce: firstNonce, key: key))

        var tampered = first
        tampered[0] ^= 1
        await XCTAssertThrowsErrorAsync(try await decryptor.open(tampered))

        var secondNonce = firstNonce
        secondNonce[0] = 2
        let second = try await encryptor.seal(secondMessage)
        XCTAssertEqual(second, try XSalsa20Poly1305.seal(secondMessage, nonce: secondNonce, key: key))
        let openedSecond = try await decryptor.open(second)
        XCTAssertEqual(openedSecond, secondMessage)
    }
}

@MainActor
private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        // Expected.
    }
}
