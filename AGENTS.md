# swift-et

Pure Swift SPM package implementing the Eternal Terminal (ET) protocol **client**. No server. Wire-compatible with the C++ `etserver` from https://github.com/MisterTea/EternalTerminal (protocol version 6).

## Reference source

`refs/EternalTerminal` is a git submodule with the canonical C++ implementation. It is read-only reference material — never modify it, never compile it into the package. When any wire-format detail is ambiguous, the C++ source is the source of truth, not this document.

Key reference files:

| C++ (refs/EternalTerminal) | Purpose |
|---|---|
| `proto/ET.proto`, `proto/ETerminal.proto` | All protobuf messages (proto2, LITE_RUNTIME) |
| `src/base/Packet.hpp` | Packet = `[encrypted: u8][header: u8][payload]`, length-encoded serialization |
| `src/base/CryptoHandler.{hpp,cpp}` | libsodium `crypto_secretbox` (XSalsa20-Poly1305), 32-byte key, 24-byte nonce, incrementing nonce, MSB of nonce distinguishes client/server streams |
| `src/base/BackedReader.{hpp,cpp}`, `src/base/BackedWriter.{hpp,cpp}` | Sequence-numbered reliable layer; backup buffer of encrypted packets for catchup replay |
| `src/base/Connection.{hpp,cpp}`, `src/base/ClientConnection.{hpp,cpp}` | Connect/reconnect state machine, `SequenceHeader`/`CatchupBuffer` resume handshake, heartbeats |
| `src/base/TcpSocketHandler.cpp`, `src/base/SocketHandler.cpp` | Socket semantics the transport must match (framing reads, timeouts) |
| `src/base/Headers.hpp` | Constants: `PROTOCOL_VERSION = 6`, timeouts, buffer sizes |
| `src/terminal/TerminalClient.{hpp,cpp}` | Client run loop: TermInit, TerminalBuffer, TerminalInfo (winsize), heartbeat cadence |
| `src/terminal/forwarding/` | Port forwarding: `PortForwardHandler`, `PortForwardSourceHandler`, `PortForwardDestinationHandler`, `ForwardSourceHandler` |
| `src/terminal/UserJumphostHandler.cpp` | Jumphost flow (client side: jumphost info rides in `InitialPayload`) |
| `docs/protocol.md` | Prose protocol description |

## Locked decisions (do not relitigate)

- **Client only.** No `etserver`, no `etterminal` equivalents.
- **SSH implementation is out of scope; injected bootstrap is in scope.** The library generates the `etterminal` launch command and parses its credentials through a consumer-provided executor. Do not add an SSH dependency.
- **Networking: Network.framework** (`NWConnection`). Apple platforms only: macOS 13+, iOS 16+. Wrap it behind a small internal `Transport` protocol so an NIO transport can be added later without API changes.
- **Crypto: pure Swift** XSalsa20-Poly1305 implementation inside this package (Salsa20 core, HSalsa20 key derivation, Poly1305 MAC), byte-compatible with libsodium `crypto_secretbox_easy`/`crypto_secretbox_open_easy`. No runtime crypto dependency. Performance is a requirement, not an afterthought — see Benchmarks below. `swift-sodium` may appear **only** as a dependency of test/benchmark targets (cross-validation oracle), never of library products.
- **Runtime dependencies: swift-protobuf only.** Nothing else in the product dependency graph.
- **Full client parity for v1**: terminal I/O + resume, port forwarding (forward and reverse, port ranges, Unix sockets), jumphost support.

## Package layout

```
Package.swift              swift-tools-version 6.0+, strict concurrency
Sources/
  ETCrypto/                XSalsa20Poly1305, Poly1305, SecretBox; no dependencies
  ETCore/                  depends on ETCrypto + swift-protobuf
    Proto/                 Checked-in generated *.pb.swift from refs proto files
    Packet.swift           Packet model + wire serialization
    BackedReader.swift     \  sequence numbers, backup buffer,
    BackedWriter.swift     /  catchup logic — mirror C++ semantics exactly
  ETTransport/             transport abstraction and Network.framework implementation
    Transport.swift        protocol Transport (async read/write/close)
    NWTransport.swift      Network.framework implementation
  ETBootstrap/             injected etterminal command generation + credential parsing
  ETSession/               depends on ETCore, ETCrypto, ETTransport, ETBootstrap
    ETConnection.swift     actor: connect/reconnect/resume state machine, heartbeats
    ETTerminalSession.swift public API: AsyncStream<Data> output, send(_:), resize(rows:cols:)
    Forwarding/            port-forward routing (source/destination handlers)
Tests/
  ETCoreTests/             vectors, round-trips, catchup simulations
  ETBootstrapTests/        bootstrap command and parser tests
  ETSessionTests/          state machine tests with in-memory Transport
  ETIntegrationTests/      against a real etserver (skipped unless ET_INTEGRATION=1)
Benchmarks/                crypto + framing throughput; swift-sodium as oracle/baseline
refs/EternalTerminal/      submodule, reference only
```

Generated protobuf Swift files are **checked in** (regenerate with `scripts/gen-proto.sh`; `brew install swift-protobuf` provides `protoc-gen-swift`). Consumers must not need protoc.

## Protocol facts (verified against source; re-verify details in refs when implementing)

- TCP to etserver, default port 2022.
- Handshake: plaintext `ConnectRequest{clientId, version=6}` → `ConnectResponse{status}`. Statuses: `NEW_CLIENT`, `RETURNING_CLIENT`, `INVALID_KEY`, `MISMATCHED_PROTOCOL`.
- New client: exchange `InitialPayload`/`InitialResponse` (port-forward requests, jumphost flag). Returning client: exchange `SequenceHeader` (last seq seen by each side), then replay missing packets via `CatchupBuffer`.
- All post-handshake packets: `Packet{encrypted, header, payload}`; terminal data uses `TerminalBuffer`, winsize `TerminalInfo`, liveness `HEARTBEAT` (packet types count down from 254 to avoid collisions with `TerminalPacketType`).
- secretbox key = passkey (32 bytes, delivered out-of-band). Nonce: 24 bytes, starts at 0 except MSB set differently per direction, incremented per message under a lock. Encrypt/decrypt order therefore must be strictly serialized per direction.
- BackedWriter keeps ciphertext (post-encryption) for catchup — replayed bytes must be the original ciphertext, not re-encrypted (nonce would desync).

## Code standards

- Swift 6 language mode, `StrictConcurrency` enforced, zero warnings.
- Public API is `Sendable`-clean, async/await only — no callbacks, no Combine.
- No `@unchecked Sendable` unless a comment proves the invariant.
- Crypto code must be constant-time where libsodium is (Poly1305 verify via constant-time compare), operate on `ContiguousBytes`/`UnsafeRawBufferPointer` in hot loops, and avoid per-packet allocations where practical.
- Errors: one `ETError` enum per module boundary, typed, with the wire status embedded where relevant.

## Verification

- **Crypto vectors**: cross-check against libsodium (via swift-sodium in tests): random keys/nonces/lengths (0, 1, 15, 16, 17, 63, 64, 65, 1KiB, 64KiB, 1MiB), assert byte-identical ciphertext both directions, plus tamper-rejection tests. Include the standard XSalsa20 and Poly1305 published test vectors.
- **Framing/round-trip**: serialize→parse property tests for Packet and every protobuf message.
- **Catchup simulation**: in-memory transport that drops the connection at arbitrary byte offsets; assert both sides converge with no loss, duplication, or reordering — mirror the scenarios in `refs/EternalTerminal/test/`.
- **Integration**: `ET_INTEGRATION=1 swift test` runs against a local `etserver` (`brew install MisterTea/et/et`); test injects clientId/passkey via the same path `etterminal` uses. Document the harness setup in the test file header.
- **Benchmarks**: pure Swift secretbox vs swift-sodium on 64B/1KiB/64KiB/1MiB payloads. Gate: within 2× of libsodium on 64KiB+ on Apple Silicon. If the gate fails, report numbers — do not silently swap in sodium.
- `swift build && swift test` must pass before any task is considered done.

## Roadmap

1. Scaffold: Package.swift, targets, checked-in generated protobufs, CI-less local build green.
2. `ETCrypto` + `ETCore`: crypto (+vectors), Packet framing, BackedReader/Writer (+catchup tests).
3. `ETTransport` + `ETSession`: transport, ETConnection handshake/resume/heartbeat, ETTerminalSession API.
4. Forwarding + jumphost.
5. Benchmarks + integration harness.
