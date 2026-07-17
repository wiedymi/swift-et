// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "swift-et",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "ETProtocol", targets: ["ETProtocol"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-protobuf.git",
            from: "1.38.1"
        ),
        .package(
            url: "https://github.com/jedisct1/swift-sodium.git",
            from: "0.9.1"
        ),
    ],
    targets: [
        .target(
            name: "ETProtocol",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "ETProtocolTests",
            dependencies: [
                "ETProtocol",
                .product(name: "Sodium", package: "swift-sodium"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
