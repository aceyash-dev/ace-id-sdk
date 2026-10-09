// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AceID",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "AceID", targets: ["AceID"])],
    dependencies: [.package(url: "https://github.com/openid/AppAuth-iOS.git", from: "1.7.6")],
    targets: [
        .target(name: "AceID", dependencies: [.product(name: "AppAuth", package: "AppAuth-iOS")]),
        .testTarget(name: "AceIDTests", dependencies: ["AceID"])
    ]
)
