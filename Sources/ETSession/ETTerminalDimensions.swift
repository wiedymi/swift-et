import ETCore
import Foundation

/// Validated terminal dimensions sent to the Eternal Terminal server.
public struct ETTerminalDimensions: Equatable, Sendable {
    public let rows: Int
    public let columns: Int
    public let pixelWidth: Int?
    public let pixelHeight: Int?

    public init(
        rows: Int,
        columns: Int,
        pixelWidth: Int? = nil,
        pixelHeight: Int? = nil
    ) throws {
        guard rows > 0, columns > 0,
              Int32(exactly: rows) != nil,
              Int32(exactly: columns) != nil else {
            throw ETClientError.invalidTerminalSize(rows: rows, columns: columns)
        }
        guard pixelWidth.map({ $0 >= 0 && Int32(exactly: $0) != nil }) ?? true,
              pixelHeight.map({ $0 >= 0 && Int32(exactly: $0) != nil }) ?? true else {
            throw ETClientError.invalidTerminalPixels(
                width: pixelWidth,
                height: pixelHeight
            )
        }

        self.rows = rows
        self.columns = columns
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
    }

    func packet() throws -> Packet {
        var terminalInfo = Et_TerminalInfo()
        terminalInfo.row = Int32(rows)
        terminalInfo.column = Int32(columns)
        if let pixelWidth { terminalInfo.width = Int32(pixelWidth) }
        if let pixelHeight { terminalInfo.height = Int32(pixelHeight) }
        return Packet(
            header: UInt8(Et_TerminalPacketType.terminalInfo.rawValue),
            payload: try terminalInfo.serializedData()
        )
    }
}
