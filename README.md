# swift-et

[![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/wiedymi)
[![Twitter](https://img.shields.io/badge/-Twitter-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://x.com/wiedymi)
[![Email](https://img.shields.io/badge/-Email-EA4335?style=flat-square&logo=gmail&logoColor=white)](mailto:contact@wiedymi.com)
[![Discord](https://img.shields.io/badge/-Discord-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/zemMZtrkSb)
[![Support me](https://img.shields.io/badge/-Support%20me-ff69b4?style=flat-square&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/vivy-company)

Pure Swift Eternal Terminal (ET) protocol client for Apple platforms.

This library implements the client side of the [Eternal Terminal](https://github.com/MisterTea/EternalTerminal) wire protocol (protocol version 6): bootstrap command generation/parsing, encrypted transport, reconnect/resume, terminal I/O, and port forwarding. The server, an SSH implementation, and terminal UI/rendering are intentionally out of scope so consumers can integrate their preferred SSH stack and renderer.

## Features

- Wire-compatible with the C++ `etserver` (verified end-to-end against Eternal Terminal 7.0.0)
- Pure Swift XSalsa20-Poly1305, byte-compatible with libsodium `crypto_secretbox` — no runtime crypto dependency
- Seamless reconnection and process relaunch recovery using sequence-numbered ciphertext checkpoints
- Terminal session API: async/await, `AsyncStream` output, keystroke input, window resize
- SSH bootstrap adapter with bring-your-own-SSH execution
- Forward and reverse port tunnels, port ranges, Unix sockets, jumphost support
- Split modules:
  - `ETCrypto` — pure Swift XSalsa20-Poly1305 and nonce management
  - `ETCore` — protobuf messages, packets, framing, and reliable catchup
  - `ETTransport` — internal transport abstraction and Network.framework implementation
  - `ETBootstrap` — injected `etterminal` launch command and credential parser
  - `ETSession` — connection lifecycle, terminal API, forwarding, and jumphost support
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
    .package(url: "https://github.com/wiedymi/swift-et", from: "0.1.5")
]
```

Then add `ETSession` and `ETBootstrap` to your app target dependencies:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "ETSession", package: "swift-et"),
        .product(name: "ETBootstrap", package: "swift-et")
    ]
)
```

## Usage

Apps normally import the session and bootstrap surfaces:

```swift
import ETBootstrap
import ETSession
```

You can supply credentials acquired out of band:

```swift
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
try await session.resize(
    rows: 40,
    cols: 120,
    pixelWidth: 1440,
    pixelHeight: 900
)
```

## Bootstrap

`ETBootstrap` mirrors the C++ client's `etterminal` command and `IDPASSKEY:` parser. The
library never opens SSH itself; inject your existing SSH client:

```swift
struct AppSSHExecutor: ETBootstrapExecutor {
    let ssh: MySSHClient

    func run(command: String) async throws -> String {
        try await ssh.run(command, captureOutput: true)
    }
}

let session = ETTerminalSession(
    host: "example.com",
    port: 2022,
    bootstrapExecutor: AppSSHExecutor(ssh: ssh),
    bootstrapOptions: ETBootstrapOptions(
        term: "xterm-256color",
        serverFifo: "/tmp/etserver.fifo"
    )
)

try await session.connect()
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

The full lifecycle (`bootstrapping`, `connecting`, `connected`, `disconnected`,
`reconnecting`, and terminal states) is observable via `session.stateChanges`. If your network
monitor reports a meaningful path change, nudge recovery without waiting for the normal retry:

```swift
await session.notifyNetworkPathChanged()
```

To resume the same server-side session after an app relaunch, persist
`ETSessionCheckpoint` separately from the passkey, then restore both:

```swift
let checkpoint = try await session.prepareForApplicationBackground()
// Persist checkpoint; keep the passkey in Keychain or another credential store.

let restored = try ETTerminalSession(
    host: "example.com",
    clientID: clientID,
    passkey: passkey,
    checkpoint: checkpoint
)
try await restored.connect()
```

If the process remains alive, call `resumeFromApplicationBackground()` after foregrounding.

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
