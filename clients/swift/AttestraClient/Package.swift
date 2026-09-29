// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "AttestraClient",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "AttestraClient", targets: ["AttestraClient"]),
    ],
    targets: [
        .target(name: "AttestraClient"),
        .testTarget(name: "AttestraClientTests", dependencies: ["AttestraClient"]),
    ]
)
