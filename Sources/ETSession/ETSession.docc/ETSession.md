# ``ETSession``

Build resumable Eternal Terminal clients that are wire-compatible with protocol version 6.

## Bootstrap injection

The package generates and parses the `etterminal` bootstrap exchange, but deliberately does
not choose an SSH implementation. Adopt ``ETBootstrap/ETBootstrapExecutor`` using your app's
SSH stack, then create ``ETTerminalSession`` with `bootstrapExecutor:`. Calling `connect()`
emits ``ETConnectionState/bootstrapping`` while the executor runs and then uses the returned
credentials for the ET transport connection.

## Session lifecycle

Observe ``ETTerminalSession/stateChanges`` for the lifecycle from
``ETConnectionState/idle`` through bootstrap, connection, and recovery. Read terminal bytes
from ``ETTerminalSession/output``, send keystrokes with ``ETTerminalSession/send(_:)``, and
update cell and pixel dimensions with
``ETTerminalSession/resize(rows:cols:pixelWidth:pixelHeight:)``. Close the session explicitly
when its owner is finished.

## Reconnection semantics

After transport loss, the session emits ``ETConnectionState/disconnected`` immediately before
``ETConnectionState/reconnecting``. Recovery exchanges sequence headers and replays the
original retained ciphertext, preserving nonce synchronization and packet order. Call
``ETTerminalSession/notifyNetworkPathChanged()`` after a platform path-change notification to
force a connected transport through recovery or cancel the current reconnect backoff.

For process relaunch recovery, persist the opaque ``ETSessionCheckpoint`` returned by
``ETTerminalSession/prepareForApplicationBackground()`` while storing the passkey separately
in a credential store. Restore both with the checkpoint initializer. If the original process
continues running, call ``ETTerminalSession/resumeFromApplicationBackground()`` on foreground
activation.

## Sequence ceiling

The C++ wire protocol encodes recovery sequence numbers as signed 32-bit integers. Internal
accounting uses 64-bit values, but recovery cannot represent a sequence beyond `Int32.max`.
Swift reports ``ETCrypto/ETProtocolError/sequenceNumberOutOfRange`` at that boundary, while
the C++ implementation silently wraps.

## Topics

### Session

- ``ETTerminalSession``
- ``ETConnectionState``
- ``ETClientError``
- ``ETSessionCheckpoint``

### Forwarding

- ``ETTunnel``
- ``ETTunnelSource``
- ``ETTunnelEndpoint``
