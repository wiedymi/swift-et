@testable import ETBootstrap
import Foundation
import XCTest

@MainActor
final class ETBootstrapTests: XCTestCase {
    private let id = "XXXabcdefghijklm"
    private let passkey = "0123456789abcdefghijklmnopqrstuv"

    func testCommandMatchesCppGenCommandDefaults() {
        let command = ETBootstrap().command(clientID: id, passkey: passkey)
        XCTAssertEqual(
            command,
            "echo '\(id)/\(passkey)_xterm-256color' | etterminal --verbose=0"
        )
    }

    func testCommandMatchesCppGenCommandWithCustomOptions() {
        let bootstrap = ETBootstrap(
            options: ETBootstrapOptions(
                term: "screen-256color",
                etterminalPath: "/opt/et/bin/etterminal",
                verbosity: 3,
                serverFifo: "/tmp/et router.sock"
            )
        )
        XCTAssertEqual(
            bootstrap.command(clientID: id, passkey: passkey),
            "echo '\(id)/\(passkey)_screen-256color' | "
                + "/opt/et/bin/etterminal --verbose=3 --serverfifo=/tmp/et router.sock"
        )
    }

    func testCommandMatchesCppGenCommandWithKillPrefix() {
        let bootstrap = ETBootstrap(
            options: ETBootstrapOptions(killOldSessionsForUser: "alice")
        )
        XCTAssertEqual(
            bootstrap.command(clientID: id, passkey: passkey),
            "pkill etterminal -u alice; sleep 0.5; "
                + "echo '\(id)/\(passkey)_xterm-256color' | etterminal --verbose=0"
        )
    }

    func testParsesMarkerAfterShellNoise() async throws {
        let executor = CapturingBootstrapExecutor(
            output: "Welcome from shell\nwarning\r\nIDPASSKEY:\(id)/\(passkey) trailing"
        )
        let credentials = try await ETBootstrap().run(using: executor)
        XCTAssertEqual(credentials.clientID, id)
        XCTAssertEqual(credentials.passkey, Data(passkey.utf8))
    }

    func testEmptyOutputIsSSHFailure() async {
        await assertBootstrapError(output: "", expected: .sshFailed)
    }

    func testMissingMarkerIncludesOnlySanitizedTruncatedExcerpt() async {
        let output = String(repeating: "shell-noise-", count: 30)
        let executor = CapturingBootstrapExecutor(output: output)
        do {
            _ = try await ETBootstrap().run(using: executor)
            XCTFail("Expected markerNotFound")
        } catch let ETBootstrapError.markerNotFound(excerpt) {
            XCTAssertLessThanOrEqual(excerpt.count, 200)
            XCTAssertTrue(output.hasPrefix(excerpt))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testShortCredentialsAreMalformed() async {
        await assertBootstrapError(
            output: "IDPASSKEY:short/value",
            expected: .malformedCredentials
        )
    }

    func testErrorsNeverExposeGeneratedIDOrPasskey() async throws {
        let executor = EchoCommandBootstrapExecutor()
        do {
            _ = try await ETBootstrap().run(using: executor)
            XCTFail("Expected markerNotFound")
        } catch {
            let capturedCommand = await executor.command()
            let command = try XCTUnwrap(capturedCommand)
            let input = try XCTUnwrap(
                command.split(separator: "'").dropFirst().first.map(String.init)
            )
            let credentials = try XCTUnwrap(input.split(separator: "_").first)
            let pieces = credentials.split(separator: "/")
            let generatedID = try XCTUnwrap(pieces.first.map(String.init))
            let generatedPasskey = try XCTUnwrap(pieces.last.map(String.init))
            XCTAssertEqual(generatedID.count, 16)
            XCTAssertTrue(generatedID.hasPrefix("XXX"))
            XCTAssertEqual(generatedPasskey.count, 32)
            let message = String(describing: error)
            XCTAssertFalse(message.contains(generatedID))
            XCTAssertFalse(message.contains(generatedPasskey))
        }
    }

    private func assertBootstrapError(output: String, expected: ETBootstrapError) async {
        do {
            _ = try await ETBootstrap().run(
                using: CapturingBootstrapExecutor(output: output)
            )
            XCTFail("Expected \(expected)")
        } catch {
            XCTAssertEqual(error as? ETBootstrapError, expected)
        }
    }
}

private actor CapturingBootstrapExecutor: ETBootstrapExecutor {
    private let output: String
    private var commands: [String] = []

    init(output: String) {
        self.output = output
    }

    func run(command: String) -> String {
        commands.append(command)
        return output
    }
}

private actor EchoCommandBootstrapExecutor: ETBootstrapExecutor {
    private var capturedCommand: String?

    func run(command: String) -> String {
        capturedCommand = command
        return command
    }

    func command() -> String? {
        capturedCommand
    }
}
