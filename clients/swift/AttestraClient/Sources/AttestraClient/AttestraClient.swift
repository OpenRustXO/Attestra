import CryptoKit
import Foundation

public struct AttestraConfiguration: Sendable {
    /// The worker origin, e.g. `https://attestra.example.workers.dev`. Routes are resolved
    /// from its root, so it must not carry a path.
    public var baseURL: URL
    /// Sessions are refreshed this long before they expire.
    public var refreshMargin: TimeInterval

    public init(baseURL: URL, refreshMargin: TimeInterval = 60) {
        self.baseURL = baseURL
        self.refreshMargin = refreshMargin
    }
}

/// A short-lived Attestra session.
public struct Session: Sendable, Equatable {
    public let token: String
    public let expiresAt: Date
}

/// A call to `ANY /p/{provider}/{path}`.
public struct ProxyRequest: Sendable {
    public var provider: String
    /// Unencoded path below the provider, e.g. `/v1/chat/completions`.
    public var path: String
    public var method: String
    public var query: [URLQueryItem]
    public var headers: [String: String]
    public var body: Data?
    /// Attach a per-request App Attest assertion (providers with `require_assertion = true`).
    public var requireAssertion: Bool

    public init(
        provider: String,
        path: String,
        method: String = "GET",
        query: [URLQueryItem] = [],
        headers: [String: String] = [:],
        body: Data? = nil,
        requireAssertion: Bool = false
    ) {
        self.provider = provider
        self.path = path
        self.method = method
        self.query = query
        self.headers = headers
        self.body = body
        self.requireAssertion = requireAssertion
    }
}

/// Attests the app with App Attest, keeps a session fresh, and calls providers through the
/// Attestra proxy. Safe to share; all state is actor-isolated.
public actor AttestraClient {
    private let configuration: AttestraConfiguration
    private let appAttest: any AppAttestProviding
    private let keyStore: any KeyStore
    private let transport: any HTTPTransport
    private let now: @Sendable () -> Date

    private var session: Session?
    private var refreshTask: Task<Session, Error>?

    public init(
        configuration: AttestraConfiguration,
        appAttest: any AppAttestProviding = SystemAppAttest(),
        keyStore: any KeyStore = KeychainKeyStore(),
        transport: any HTTPTransport = URLSessionTransport(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.configuration = configuration
        self.appAttest = appAttest
        self.keyStore = keyStore
        self.transport = transport
        self.now = now
    }

    /// Whether this device can use App Attest at all. When `false`, every call throws
    /// ``AttestraError/appAttestUnsupported``; offer a degraded experience instead.
    public nonisolated var isSupported: Bool {
        appAttest.isSupported
    }

    /// Returns a valid session, attesting (first run) or asserting (later runs) as needed.
    /// Concurrent callers share one refresh.
    public func currentSession(forceRefresh: Bool = false) async throws -> Session {
        if !forceRefresh, let session,
           session.expiresAt.timeIntervalSince(now()) > configuration.refreshMargin {
            return session
        }
        if let refreshTask {
            return try await refreshTask.value
        }
        let task = Task { try await self.establishSession() }
        refreshTask = task
        defer { refreshTask = nil }
        let fresh = try await task.value
        session = fresh
        return fresh
    }

    /// Sends a request through the proxy. If Attestra rejects the session or assertion with
    /// 401, the session is refreshed and the request retried exactly once. Upstream
    /// responses (including upstream 401s) are returned unchanged.
    public func send(_ request: ProxyRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await sendOnce(request, forceRefresh: false)
        guard response.statusCode == 401, Self.isAttestraAuthError(data) else {
            return (data, response)
        }
        return try await sendOnce(request, forceRefresh: true)
    }

    /// Forgets the session and the App Attest key; the next call attests a new key.
    public func reset() throws {
        session = nil
        try keyStore.delete()
    }

    // MARK: - Session establishment

    private func establishSession() async throws -> Session {
        guard appAttest.isSupported else { throw AttestraError.appAttestUnsupported }
        if let stored = try keyStore.load(), stored.attested {
            do {
                return try await assertedSession(keyId: stored.keyId)
            } catch where error.isInvalidAppAttestKey || Self.isUnknownKey(error) {
                // The key is gone (reinstall/restore) or the server no longer knows it.
                try keyStore.delete()
            }
        }
        return try await attestedSession()
    }

    private func attestedSession() async throws -> Session {
        let keyId: String
        if let stored = try keyStore.load(), !stored.attested {
            keyId = stored.keyId // retry a key whose attestation never reached the server
        } else {
            keyId = try await appAttest.generateKey()
            try keyStore.save(StoredKey(keyId: keyId, attested: false))
        }

        let challenge = try await fetchChallenge()
        let attestation: Data
        do {
            attestation = try await appAttest.attestKey(keyId, clientDataHash: Self.sha256(challenge))
        } catch where error.isInvalidAppAttestKey {
            try keyStore.delete()
            throw error
        }

        do {
            let session = try await postSession(path: "/attest/ios", body: [
                "key_id": keyId,
                "attestation": attestation.base64EncodedString(),
                "challenge": Base64URL.encode(challenge),
            ])
            try keyStore.save(StoredKey(keyId: keyId, attested: true))
            return session
        } catch {
            // A rejected attestation is never retried with the same key.
            if case AttestraError.server(401, _) = error { try keyStore.delete() }
            throw error
        }
    }

    private func assertedSession(keyId: String) async throws -> Session {
        let challenge = try await fetchChallenge()
        let assertion = try await appAttest.generateAssertion(keyId, clientDataHash: Self.sha256(challenge))
        return try await postSession(path: "/assert/ios", body: [
            "key_id": keyId,
            "assertion": assertion.base64EncodedString(),
            "challenge": Base64URL.encode(challenge),
        ])
    }

    private func fetchChallenge() async throws -> Data {
        struct ChallengeResponse: Decodable { let challenge: String }
        let data = try await postJSON(path: "/challenge", body: nil)
        guard let response = try? JSONDecoder().decode(ChallengeResponse.self, from: data),
              let challenge = Base64URL.decode(response.challenge), challenge.count == 32
        else { throw AttestraError.invalidResponse }
        return challenge
    }

    private func postSession(path: String, body: [String: String]) async throws -> Session {
        struct SessionResponse: Decodable {
            let token: String
            let expires_at: TimeInterval
        }
        let data = try await postJSON(path: path, body: body)
        guard let response = try? JSONDecoder().decode(SessionResponse.self, from: data) else {
            throw AttestraError.invalidResponse
        }
        return Session(token: response.token, expiresAt: Date(timeIntervalSince1970: response.expires_at))
    }

    private func postJSON(path: String, body: [String: String]?) async throws -> Data {
        var request = URLRequest(url: configuration.baseURL.appendingPathComponent(String(path.dropFirst())))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        }
        let (data, response) = try await transport.data(for: request)
        guard (200..<300).contains(response.statusCode) else {
            throw AttestraError.server(status: response.statusCode, code: Self.errorCode(data) ?? "unknown")
        }
        return data
    }

    // MARK: - Proxy

    private func sendOnce(_ request: ProxyRequest, forceRefresh: Bool) async throws -> (Data, HTTPURLResponse) {
        let session = try await currentSession(forceRefresh: forceRefresh)
        let url = try RequestBuilder.url(
            base: configuration.baseURL,
            provider: request.provider,
            path: request.path,
            query: request.query
        )
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.method.uppercased()
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        urlRequest.httpBody = request.body
        urlRequest.setValue("Bearer \(session.token)", forHTTPHeaderField: "Authorization")

        if request.requireAssertion {
            guard let stored = try keyStore.load(), stored.attested else {
                throw AttestraError.invalidRequest("no attested App Attest key")
            }
            let timestamp = Int(now().timeIntervalSince1970)
            let clientData = RequestBuilder.clientData(
                method: request.method.uppercased(),
                pathAndQuery: RequestBuilder.pathAndQuery(of: url),
                body: request.body ?? Data(),
                timestamp: timestamp
            )
            let assertion = try await appAttest.generateAssertion(stored.keyId, clientDataHash: Self.sha256(clientData))
            urlRequest.setValue(assertion.base64EncodedString(), forHTTPHeaderField: "X-Attestra-Assertion")
            urlRequest.setValue(String(timestamp), forHTTPHeaderField: "X-Attestra-Timestamp")
        }
        return try await transport.data(for: urlRequest)
    }

    // MARK: - Helpers

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func errorCode(_ data: Data) -> String? {
        struct ErrorBody: Decodable { let error: String }
        return (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error
    }

    /// A 401 produced by Attestra itself (as opposed to one relayed from the provider).
    static func isAttestraAuthError(_ data: Data) -> Bool {
        ["session_invalid", "attestation_invalid"].contains(errorCode(data) ?? "")
    }

    private static func isUnknownKey(_ error: Error) -> Bool {
        if case let AttestraError.server(status, code) = error {
            return status == 401 && code == "attestation_invalid"
        }
        return false
    }
}
