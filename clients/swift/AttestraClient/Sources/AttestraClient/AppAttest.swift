import DeviceCheck
import Foundation

/// The subset of `DCAppAttestService` the client needs; injectable for tests.
public protocol AppAttestProviding: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// `DCAppAttestService.shared`.
public struct SystemAppAttest: AppAttestProviding {
    public init() {}

    public var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public func generateKey() async throws -> String {
        try await DCAppAttestService.shared.generateKey()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
    }
}

extension Error {
    /// `DCError.invalidKey`: the key no longer exists (app reinstalled, restored from backup,
    /// or invalidated by the system) and a new one must be generated and attested.
    var isInvalidAppAttestKey: Bool {
        (self as? DCError)?.code == .invalidKey
    }
}
