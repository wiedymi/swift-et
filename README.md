# swift-et

[![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/wiedymi)
[![Twitter](https://img.shields.io/badge/-Twitter-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://x.com/wiedymi)
[![Email](https://img.shields.io/badge/-Email-EA4335?style=flat-square&logo=gmail&logoColor=white)](mailto:contact@wiedymi.com)
[![Discord](https://img.shields.io/badge/-Discord-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/zemMZtrkSb)
[![Support me](https://img.shields.io/badge/-Support%20me-ff69b4?style=flat-square&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/vivy-company)

Pure Swift Eternal Terminal (ET) protocol client for Apple platforms.

This library implements the client side of the [Eternal Terminal](https://github.com/MisterTea/EternalTerminal) wire protocol (protocol version 6): encrypted transport, reconnect/resume, terminal I/O, and port forwarding. The server, the SSH bootstrap that exchanges credentials, and terminal UI/rendering are intentionally out of scope so consumers can integrate with any SSH stack and any renderer.

## Features

- Wire-compatible with the C++ `etserver` (verified end-to-end against Eternal Terminal 7.0.0)
- Pure Swift XSalsa20-Poly1305, byte-compatible with libsodium `crypto_secretbox` — no runtime crypto dependency
- Seamless reconnection: sequence-numbered packet backup with ciphertext catchup replay, so sessions survive network drops with no data loss
- Terminal session API: async/await, `AsyncStream` output, keystroke input, window resize
- Forward and reverse port tunnels, port ranges, Unix sockets, jumphost support
- Split modules:
  - `ETProtocol` — packets, framing, crypto, reliability layer (pure logic, no I/O)
  - `ETClient` — Network.framework transport, connection state machine, session API
- Real local `etserver` E2E test harness
- Release-mode benchmarks with a libsodium baseline

## Platforms

- iOS 16+
- macOS 13+
- Swift tools 6.0+

## Installation

Add to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/wiedymi/swift-et", from: "0.1.0")
]
```

Then add `ETClient` to your target dependencies:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "ETClient", package: "swift-et")
    ]
)
```

## Usage

The library takes a host, port, client id, and 32-byte passkey. Your app is responsible for delivering the id/passkey pair to the server out-of-band (the same exchange `et` performs over SSH by running `etterminal`).

```swift
import ETClient

let session = try ETTerminalSession(
    host: "example.com",
    port: 2022,
    clientID: clientID,
    passkey: passkey
)

try await session.connect()

Task {
    for await data in session.output {
        renderer.feed(data)
    }
}

try await session.send(Data("ls -la\n".utf8))
try await session.resize(rows: 40, cols: 120)
```

Port forwarding:

```swift
let session = try ETTerminalSession(
    host: "example.com",
    port: 2022,
    clientID: clientID,
    passkey: passkey,
    tunnelSpecification: "8080:8080",
    reverseTunnelSpecification: "9090:9090"
)
```

Connection state (connected, reconnecting, failed) is observable via `session.stateChanges`.

## Testing

```sh
swift test
```

End-to-end tests against a real `etserver` (`brew install MisterTea/et/et`):

```sh
ET_INTEGRATION=1 swift test --filter ETIntegrationTests
```

Benchmarks:

```sh
swift run -c release Benchmarks
```

## License

MIT
