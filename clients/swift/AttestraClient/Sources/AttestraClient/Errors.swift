import Foundation

/// Errors surfaced by ``AttestraClient``.
public enum AttestraError: Error, Sendable, Equatable {
    /// App Attest is not available (simulator, old hardware, or macOS without it).
    /// `DCAppAttestService.shared.isSupported` returned `false`.
    case appAttestUnsupported
    /// The server answered with `{"error": code}` and a non-2xx status.
    case server(status: Int, code: String)
    /// The server answered with something that is not the documented JSON.
    case invalidResponse
    /// The request could not be built (e.g. an invalid provider or path).
    case invalidRequest(String)
}
