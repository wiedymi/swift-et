import Foundation

/// Executes the generated `etterminal` bootstrap command using a consumer-provided SSH stack.
public protocol ETBootstrapExecutor: Sendable {
    /// Runs a remote shell command and returns its combined captured output.
    func run(command: String) async throws -> String
}

/// Credentials returned by `etterminal` for connecting to `etserver`.
public struct ETCredentials: Equatable, Sendable {
    /// The 16-character ET client identifier.
    public let clientID: String

    /// The raw 32-byte secretbox key.
    public let passkey: Data

    /// Creates ET connection credentials.
    public init(clientID: String, passkey: Data) {
        self.clientID = clientID
        self.passkey = passkey
    }
}

/// Options used to generate the remote `etterminal` bootstrap command.
public struct ETBootstrapOptions: Equatable, Sendable {
    /// Terminal name passed to `etterminal`.
    public var term: String

    /// Remote path or command used to launch `etterminal`.
    public var etterminalPath: String

    /// Eternal Terminal verbosity level.
    public var verbosity: Int

    /// Optional server router socket path.
    public var serverFifo: String?

    /// Optional user whose existing `etterminal` processes should be killed first.
    public var killOldSessionsForUser: String?

    /// Creates bootstrap options matching the C++ client's defaults.
    public init(
        term: String = "xterm-256color",
        etterminalPath: String = "etterminal",
        verbosity: Int = 0,
        serverFifo: String? = nil,
        killOldSessionsForUser: String? = nil
    ) {
        self.term = term
        self.etterminalPath = etterminalPath
        self.verbosity = verbosity
        self.serverFifo = serverFifo
        self.killOldSessionsForUser = killOldSessionsForUser
    }
}

/// Errors produced while launching or parsing the `etterminal` bootstrap exchange.
public enum ETBootstrapError: Error, Equatable, Sendable {
    /// The executor failed or returned no output.
    case sshFailed

    /// Output did not contain `IDPASSKEY:`; the associated excerpt is sanitized and truncated.
    case markerNotFound(String)

    /// The marker was present but was not followed by a 16-character ID and 32-byte passkey.
    case malformedCredentials
}

/// Generates and parses the consumer-executed Eternal Terminal bootstrap command.
public struct ETBootstrap: Sendable {
    /// Command-generation options.
    public let options: ETBootstrapOptions

    /// Creates a bootstrap operation.
    public init(options: ETBootstrapOptions = ETBootstrapOptions()) {
        self.options = options
    }

    /// Runs the bootstrap command and returns credentials reported by `etterminal`.
    public func run(using executor: any ETBootstrapExecutor) async throws -> ETCredentials {
        let generatedPasskey = Self.randomAlphaNumeric(count: 32)
        var generatedID = Self.randomAlphaNumeric(count: 16)
        generatedID.replaceSubrange(generatedID.startIndex..<generatedID.index(
            generatedID.startIndex,
            offsetBy: 3
        ), with: "XXX")
        let command = command(clientID: generatedID, passkey: generatedPasskey)

        let output: String
        do {
            output = try await executor.run(command: command)
        } catch {
            throw ETBootstrapError.sshFailed
        }
        guard !output.isEmpty else { throw ETBootstrapError.sshFailed }
        return try parse(
            output: output,
            generatedID: generatedID,
            generatedPasskey: generatedPasskey
        )
    }

    package func command(clientID: String, passkey: String) -> String {
        var optionsString = "--verbose=\(options.verbosity)"
        if let serverFifo = options.serverFifo, !serverFifo.isEmpty {
            optionsString += " --serverfifo=\(serverFifo)"
        }
        let command = "echo '\(clientID)/\(passkey)_\(options.term)' | "
            + "\(options.etterminalPath) \(optionsString)"
        guard let user = options.killOldSessionsForUser else { return command }
        return "pkill etterminal -u \(user); sleep 0.5; \(command)"
    }

    private func parse(
        output: String,
        generatedID: String,
        generatedPasskey: String
    ) throws -> ETCredentials {
        let marker = Data("IDPASSKEY:".utf8)
        let bytes = Data(output.utf8)
        guard let markerRange = bytes.range(of: marker) else {
            throw ETBootstrapError.markerNotFound(
                Self.sanitizedExcerpt(
                    output,
                    generatedID: generatedID,
                    generatedPasskey: generatedPasskey
                )
            )
        }
        let credentialStart = markerRange.upperBound
        let credentialLength = 16 + 1 + 32
        guard bytes.distance(from: credentialStart, to: bytes.endIndex) >= credentialLength else {
            throw ETBootstrapError.malformedCredentials
        }
        let credentialEnd = bytes.index(credentialStart, offsetBy: credentialLength)
        let credential = Data(bytes[credentialStart..<credentialEnd])
        guard credential[credential.startIndex + 16] == Character("/").asciiValue else {
            throw ETBootstrapError.malformedCredentials
        }
        let idBytes = credential.prefix(16)
        let passkeyBytes = credential.suffix(32)
        guard idBytes.allSatisfy(Self.isAlphaNumeric),
              passkeyBytes.allSatisfy(Self.isAlphaNumeric) else {
            throw ETBootstrapError.malformedCredentials
        }
        return ETCredentials(
            clientID: String(decoding: idBytes, as: UTF8.self),
            passkey: Data(passkeyBytes)
        )
    }

    private static func randomAlphaNumeric(count: Int) -> String {
        let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        var generator = SystemRandomNumberGenerator()
        return String((0..<count).map { _ in
            alphabet.randomElement(using: &generator)!
        })
    }

    private static func isAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57)
            || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122)
    }

    private static func sanitizedExcerpt(
        _ output: String,
        generatedID: String,
        generatedPasskey: String
    ) -> String {
        let redacted = output
            .replacingOccurrences(of: generatedPasskey, with: "[redacted]")
            .replacingOccurrences(of: generatedID, with: "[redacted]")
        let singleLine = redacted
            .unicodeScalars
            .map { CharacterSet.controlCharacters.contains($0) ? " " : String($0) }
            .joined()
        return String(singleLine.prefix(200))
    }
}
