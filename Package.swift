// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "swift-et",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "ETCrypto", targets: ["ETCrypto"]),
        .library(name: "ETCore", targets: ["ETCore"]),
        .library(name: "ETTransport", targets: ["ETTransport"]),
        .library(name: "ETBootstrap", targets: ["ETBootstrap"]),
        .library(name: "ETSession", targets: ["ETSession"]),
        .executable(name: "ETDemo", targets: ["ETDemo"]),
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
            name: "ETCrypto",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .target(
            name: "ETCore",
            dependencies: [
                "ETCrypto",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .target(
            name: "ETTransport",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .target(
            name: "ETBootstrap",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .target(
            name: "ETSession",
            dependencies: [
                "ETCore",
                "ETCrypto",
                "ETTransport",
                "ETBootstrap",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .executableTarget(
            name: "Benchmarks",
            dependencies: [
                "ETCore",
                "ETCrypto",
                .product(name: "Sodium", package: "swift-sodium"),
            ],
            path: "Benchmarks",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .executableTarget(
            name: "ETDemo",
            dependencies: [
                "ETBootstrap",
                "ETSession",
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "ETCoreTests",
            dependencies: [
                "ETCore",
                "ETCrypto",
                .product(name: "Sodium", package: "swift-sodium"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "ETSessionTests",
            dependencies: [
                "ETSession",
                "ETCore",
                "ETCrypto",
                "ETTransport",
                "ETBootstrap",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "ETBootstrapTests",
            dependencies: [
                "ETBootstrap",
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "ETIntegrationTests",
            dependencies: [
                "ETSession",
                "ETBootstrap",
            ],
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
