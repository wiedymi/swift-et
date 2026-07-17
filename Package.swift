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
        .library(name: "ETClient", targets: ["ETClient"]),
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
        .target(
            name: "ETClient",
            dependencies: [
                "ETProtocol",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .executableTarget(
            name: "Benchmarks",
            dependencies: [
                "ETProtocol",
                .product(name: "Sodium", package: "swift-sodium"),
            ],
            path: "Benchmarks",
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
        .testTarget(
            name: "ETClientTests",
            dependencies: [
                "ETClient",
                "ETProtocol",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "ETIntegrationTests",
            dependencies: [
                "ETClient",
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
