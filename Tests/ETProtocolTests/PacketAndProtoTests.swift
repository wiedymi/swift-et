import ETProtocol
import Foundation
import SwiftProtobuf
import XCTest

@MainActor
final class PacketAndProtoTests: XCTestCase {
    func testPacketSerializationMatchesCppLayout() throws {
        let packet = Packet(encrypted: true, header: 42, payload: Data([1, 2, 3]))
        XCTAssertEqual(packet.serialized(), Data([1, 42, 1, 2, 3]))
        XCTAssertEqual(try packet.framed(), Data([0, 0, 0, 5, 1, 42, 1, 2, 3]))
        XCTAssertEqual(try Packet(serialized: packet.serialized()), packet)

        XCTAssertThrowsError(try Packet(serialized: Data([1]))) {
            XCTAssertEqual($0 as? ETProtocolError, .malformedPacket(minimum: 2, actual: 1))
        }
    }

    func testPacketRoundTripsDeterministicPropertyCases() throws {
        var generator = DeterministicBytes()
        let lengths = [0, 1, 2, 15, 16, 255, 4_096, 65_536]

        for length in lengths {
            for encrypted in [false, true] {
                let header = generator.bytes(count: 1)[0]
                let packet = Packet(
                    encrypted: encrypted,
                    header: header,
                    payload: Data(generator.bytes(count: length))
                )
                XCTAssertEqual(try Packet(serialized: packet.serialized()), packet)
            }
        }
    }

    func testEveryProtobufMessageRoundTrips() throws {
        var connectRequest = Et_ConnectRequest()
        connectRequest.clientID = "client"
        connectRequest.version = 6
        try assertRoundTrip(connectRequest)

        var connectResponse = Et_ConnectResponse()
        connectResponse.status = .returningClient
        connectResponse.error = "none"
        try assertRoundTrip(connectResponse)

        var sequenceHeader = Et_SequenceHeader()
        sequenceHeader.sequenceNumber = 123
        try assertRoundTrip(sequenceHeader)

        var catchupBuffer = Et_CatchupBuffer()
        catchupBuffer.buffer = [Data([1, 2]), Data([3])]
        try assertRoundTrip(catchupBuffer)

        var endpoint = Et_SocketEndpoint()
        endpoint.name = "/tmp/et.sock"
        endpoint.port = 2022
        try assertRoundTrip(endpoint)

        var terminalBuffer = Et_TerminalBuffer()
        terminalBuffer.buffer = Data("terminal".utf8)
        try assertRoundTrip(terminalBuffer)

        var terminalInfo = Et_TerminalInfo()
        terminalInfo.id = "term"
        terminalInfo.row = 24
        terminalInfo.column = 80
        terminalInfo.width = 800
        terminalInfo.height = 600
        try assertRoundTrip(terminalInfo)

        var sourceRequest = Et_PortForwardSourceRequest()
        sourceRequest.source = endpoint
        sourceRequest.destination = endpoint
        sourceRequest.environmentvariable = "PORT"
        try assertRoundTrip(sourceRequest)

        var sourceResponse = Et_PortForwardSourceResponse()
        sourceResponse.error = "source error"
        try assertRoundTrip(sourceResponse)

        var destinationRequest = Et_PortForwardDestinationRequest()
        destinationRequest.destination = endpoint
        destinationRequest.fd = 7
        try assertRoundTrip(destinationRequest)

        var destinationResponse = Et_PortForwardDestinationResponse()
        destinationResponse.clientfd = 8
        destinationResponse.socketid = 9
        destinationResponse.error = "destination error"
        try assertRoundTrip(destinationResponse)

        var forwardData = Et_PortForwardData()
        forwardData.sourcetodestination = true
        forwardData.socketid = 10
        forwardData.buffer = Data([4, 5, 6])
        forwardData.error = "forward error"
        forwardData.closed = true
        try assertRoundTrip(forwardData)

        var initialPayload = Et_InitialPayload()
        initialPayload.jumphost = true
        initialPayload.reversetunnels = [sourceRequest]
        initialPayload.environmentvariables = ["TERM": "xterm-256color"]
        try assertRoundTrip(initialPayload)

        var initialResponse = Et_InitialResponse()
        initialResponse.error = "initial error"
        try assertRoundTrip(initialResponse)

        var config = Et_ConfigParams()
        config.vlevel = 2
        config.minloglevel = 1
        try assertRoundTrip(config)

        var termInit = Et_TermInit()
        termInit.environmentnames = ["TERM", "LANG"]
        termInit.environmentvalues = ["xterm-256color", "en_US.UTF-8"]
        try assertRoundTrip(termInit)

        var userInfo = Et_TerminalUserInfo()
        userInfo.id = "user"
        userInfo.passkey = "passkey"
        userInfo.uid = 501
        userInfo.gid = 20
        userInfo.fd = 11
        try assertRoundTrip(userInfo)
    }

    private func assertRoundTrip<MessageType: SwiftProtobuf.Message & Equatable>(
        _ message: MessageType,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let serialized = try message.serializedData()
        XCTAssertEqual(
            try MessageType(serializedBytes: serialized),
            message,
            file: file,
            line: line
        )
    }
}
