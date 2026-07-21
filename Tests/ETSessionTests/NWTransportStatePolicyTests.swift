import ETTransport
import XCTest

final class NWTransportStatePolicyTests: XCTestCase {
    func testWaitingNetworkStateKeepsConnectPending() {
        XCTAssertEqual(
            NWStateEvent.waiting("No route during app activation").connectResolution,
            .pending
        )
    }

    func testTerminalNetworkStatesResolveConnect() {
        XCTAssertEqual(NWStateEvent.ready.connectResolution, .connected)
        XCTAssertEqual(NWStateEvent.failed("denied").connectResolution, .failed("denied"))
        XCTAssertEqual(NWStateEvent.cancelled.connectResolution, .closed)
    }
}
