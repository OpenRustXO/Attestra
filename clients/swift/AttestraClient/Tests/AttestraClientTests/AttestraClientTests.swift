import CryptoKit
import DeviceCheck
import Foundation
import XCTest

@testable import AttestraClient

// MARK: - Test doubles

/// Scripted App Attest: records every call.
final class MockAppAttest: AppAttestProviding, @unchecked Sendable {
    private let lock = NSLock()
    let isSupported: Bool
    private var nextKey = 0
    private(set) var generatedKeys: [String] = []
    private(set) var attestedHashes: [Data] = []
    private(set) var assertionHashes: [Data] = []
    var assertionError: Error?

    init(isSupported: Bool = true) {
        self.isSupported = isSupported
    }

    func generateKey() async throws -> String {
        lock.withLock {
            nextKey += 1
            let key = "key-\(nextKey)"
            generatedKeys.append(key)
            return key
        }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        lock.withLock { attestedHashes.append(clientDataHash) }
        return Data("attestation-\(keyId)".utf8)
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try lock.withLock {
            if let error = assertionError {
                assertionError = nil
                throw error
            }
            assertionHashes.append(clientDataHash)
            return Data("assertion-\(assertionHashes.count)".utf8)
        }
    }
}

/// A fake worker: issues challenges and sessions, and replays scripted proxy responses.
final class MockTransport: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requests: [URLRequest] = []
    private(set) var challenges: [Data] = []
    var sessionTTL: TimeInterval = 900
    var attestResponse: (Int, String)?
    var assertResponse: (Int, String)?
    var proxyResponses: [(Int, String)] = []
    var clock: () -> Date = { Date() }

    func paths() -> [String] {
        lock.withLock { requests.compactMap { $0.url?.path } }
    }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (status, body): (Int, String) = lock.withLock {
            requests.append(request)
            let path = request.url?.path ?? ""
            switch path {
            case "/challenge":
                let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
                challenges.append(challenge)
                return (200, #"{"challenge":"\#(Base64URL.encode(challenge))","expires_at":0}"#)
            case "/attest/ios", "/assert/ios":
                let scripted = path == "/attest/ios" ? attestResponse : assertResponse
                if let scripted {
                    if path == "/attest/ios" { attestResponse = nil } else { assertResponse = nil }
                    return scripted
                }
                let expires = Int(clock().timeIntervalSince1970 + sessionTTL)
                return (200, #"{"token":"token-\#(requests.count)","expires_at":\#(expires)}"#)
            default:
                return proxyResponses.isEmpty ? (200, "upstream ok") : proxyResponses.removeFirst()
            }
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        return (Data(body.utf8), response)
    }

    func jsonBody(of request: URLRequest) -> [String: String] {
        (try? JSONSerialization.jsonObject(with: request.httpBody ?? Data())) as? [String: String] ?? [:]
    }
}

final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date(timeIntervalSince1970: 1_750_000_000)
    var now: Date { lock.withLock { current } }
    func advance(_ seconds: TimeInterval) { lock.withLock { current += seconds } }
}

// MARK: - Tests

final class AttestraClientTests: XCTestCase {
    let base = URL(string: "https://attestra.example.dev")!

    func makeClient(
        appAttest: MockAppAttest = MockAppAttest(),
        keyStore: InMemoryKeyStore = InMemoryKeyStore(),
        transport: MockTransport = MockTransport(),
        clock: Clock = Clock()
    ) -> AttestraClient {
        transport.clock = { clock.now }
        return AttestraClient(
            configuration: AttestraConfiguration(baseURL: base),
            appAttest: appAttest,
            keyStore: keyStore,
            transport: transport,
            now: { clock.now }
        )
    }

    func testFirstRunAttestsStoresKeyAndCachesSession() async throws {
        let attest = MockAppAttest(), store = InMemoryKeyStore(), transport = MockTransport()
        let client = makeClient(appAttest: attest, keyStore: store, transport: transport)

        let first = try await client.currentSession()
        let second = try await client.currentSession()
        XCTAssertEqual(first, second)
        XCTAssertEqual(transport.paths(), ["/challenge", "/attest/ios"])
        XCTAssertEqual(try store.load(), StoredKey(keyId: "key-1", attested: true))

        // clientDataHash = SHA256(raw challenge bytes)
        XCTAssertEqual(attest.attestedHashes, [Data(SHA256.hash(data: transport.challenges[0]))])
        let body = transport.jsonBody(of: transport.requests[1])
        XCTAssertEqual(body["key_id"], "key-1")
        XCTAssertEqual(body["attestation"], Data("attestation-key-1".utf8).base64EncodedString())
        XCTAssertEqual(body["challenge"], Base64URL.encode(transport.challenges[0]))
    }

    func testLaterLaunchAssertsWithStoredKey() async throws {
        let attest = MockAppAttest(), transport = MockTransport()
        let client = makeClient(
            appAttest: attest,
            keyStore: InMemoryKeyStore(StoredKey(keyId: "stored", attested: true)),
            transport: transport
        )
        _ = try await client.currentSession()
        XCTAssertEqual(transport.paths(), ["/challenge", "/assert/ios"])
        XCTAssertTrue(attest.generatedKeys.isEmpty)
        XCTAssertEqual(attest.assertionHashes, [Data(SHA256.hash(data: transport.challenges[0]))])
        XCTAssertEqual(transport.jsonBody(of: transport.requests[1])["key_id"], "stored")
    }

    func testRefreshesShortlyBeforeExpiry() async throws {
        let clock = Clock(), transport = MockTransport()
        let client = makeClient(transport: transport, clock: clock)
        _ = try await client.currentSession()
        clock.advance(900 - 61)
        _ = try await client.currentSession()
        XCTAssertEqual(transport.paths().filter { $0 != "/challenge" }, ["/attest/ios"])
        clock.advance(2) // now inside the 60 s refresh margin
        _ = try await client.currentSession()
        XCTAssertEqual(transport.paths().filter { $0 != "/challenge" }, ["/attest/ios", "/assert/ios"])
    }

    func testUnsupportedDeviceThrows() async {
        let client = makeClient(appAttest: MockAppAttest(isSupported: false))
        XCTAssertFalse(client.isSupported)
        do {
            _ = try await client.currentSession()
            XCTFail("expected appAttestUnsupported")
        } catch {
            XCTAssertEqual(error as? AttestraError, .appAttestUnsupported)
        }
    }

    func testInvalidatedKeyIsReplacedByANewAttestation() async throws {
        let attest = MockAppAttest(), store = InMemoryKeyStore(StoredKey(keyId: "old", attested: true))
        attest.assertionError = DCError(.invalidKey)
        let transport = MockTransport()
        let client = makeClient(appAttest: attest, keyStore: store, transport: transport)
        _ = try await client.currentSession()
        XCTAssertEqual(transport.paths(), ["/challenge", "/challenge", "/attest/ios"])
        XCTAssertEqual(try store.load(), StoredKey(keyId: "key-1", attested: true))
    }

    func testKeyUnknownToServerIsReattested() async throws {
        let store = InMemoryKeyStore(StoredKey(keyId: "old", attested: true)), transport = MockTransport()
        transport.assertResponse = (401, #"{"error":"attestation_invalid"}"#)
        let client = makeClient(keyStore: store, transport: transport)
        _ = try await client.currentSession()
        XCTAssertEqual(transport.paths(), ["/challenge", "/assert/ios", "/challenge", "/attest/ios"])
        XCTAssertEqual(try store.load()?.keyId, "key-1")
    }

    func testRevokedDeviceSurfacesForbiddenWithoutNewKey() async throws {
        let store = InMemoryKeyStore(StoredKey(keyId: "old", attested: true)), transport = MockTransport()
        transport.assertResponse = (403, #"{"error":"forbidden"}"#)
        let client = makeClient(keyStore: store, transport: transport)
        do {
            _ = try await client.currentSession()
            XCTFail("expected forbidden")
        } catch {
            XCTAssertEqual(error as? AttestraError, .server(status: 403, code: "forbidden"))
        }
        XCTAssertEqual(try store.load()?.keyId, "old")
    }

    func testRejectedAttestationDiscardsTheKey() async throws {
        let store = InMemoryKeyStore(), transport = MockTransport()
        transport.attestResponse = (401, #"{"error":"attestation_invalid"}"#)
        let client = makeClient(keyStore: store, transport: transport)
        do {
            _ = try await client.currentSession()
            XCTFail("expected attestation_invalid")
        } catch {
            XCTAssertEqual(error as? AttestraError, .server(status: 401, code: "attestation_invalid"))
        }
        XCTAssertNil(try store.load())
    }

    func testConcurrentCallersShareOneRefresh() async throws {
        let transport = MockTransport()
        let client = makeClient(transport: transport)
        async let a = client.currentSession()
        async let b = client.currentSession()
        async let c = client.currentSession()
        let sessions = try await [a, b, c]
        XCTAssertEqual(Set(sessions.map(\.token)).count, 1)
        XCTAssertEqual(transport.paths().filter { $0 == "/attest/ios" }.count, 1)
    }

    func testProxyRetriesOnceOnAttestra401() async throws {
        let transport = MockTransport()
        transport.proxyResponses = [(401, #"{"error":"session_invalid"}"#), (200, "ok")]
        let client = makeClient(transport: transport)
        let (data, response) = try await client.send(ProxyRequest(provider: "openai", path: "/v1/models"))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "ok")
        XCTAssertEqual(
            transport.paths(),
            ["/challenge", "/attest/ios", "/p/openai/v1/models", "/challenge", "/assert/ios", "/p/openai/v1/models"]
        )
        let auth = transport.requests.filter { $0.url?.path.hasPrefix("/p/") == true }
            .map { $0.value(forHTTPHeaderField: "Authorization") }
        XCTAssertNotEqual(auth[0], auth[1])
    }

    func testProxyPassesUpstream401Through() async throws {
        let transport = MockTransport()
        transport.proxyResponses = [(401, #"{"error":{"message":"Incorrect API key"}}"#)]
        let client = makeClient(transport: transport)
        let (_, response) = try await client.send(ProxyRequest(provider: "openai", path: "/v1/models"))
        XCTAssertEqual(response.statusCode, 401)
        XCTAssertEqual(transport.paths().filter { $0.hasPrefix("/p/") }.count, 1)
    }

    func testPerRequestAssertionSignsMethodPathBodyAndTimestamp() async throws {
        let attest = MockAppAttest(), transport = MockTransport(), clock = Clock()
        let client = makeClient(appAttest: attest, transport: transport, clock: clock)
        let body = Data(#"{"model":"gpt"}"#.utf8)
        _ = try await client.send(ProxyRequest(
            provider: "openai",
            path: "/v1/chat/completions",
            method: "post",
            query: [URLQueryItem(name: "stream", value: "true")],
            headers: ["Content-Type": "application/json"],
            body: body,
            requireAssertion: true
        ))
        let proxied = try XCTUnwrap(transport.requests.last)
        let timestamp = Int(clock.now.timeIntervalSince1970)
        XCTAssertEqual(proxied.httpMethod, "POST")
        XCTAssertEqual(proxied.value(forHTTPHeaderField: "X-Attestra-Timestamp"), String(timestamp))
        XCTAssertEqual(proxied.value(forHTTPHeaderField: "X-Attestra-Assertion"), Data("assertion-1".utf8).base64EncodedString())
        XCTAssertEqual(proxied.value(forHTTPHeaderField: "Content-Type"), "application/json")

        let expected = "POST\n/p/openai/v1/chat/completions?stream=true\n"
            + Base64URL.encode(Data(SHA256.hash(data: body))) + "\n\(timestamp)"
        XCTAssertEqual(attest.assertionHashes, [Data(SHA256.hash(data: Data(expected.utf8)))])
    }

    func testResetForgetsKeyAndSession() async throws {
        let store = InMemoryKeyStore(), transport = MockTransport()
        let client = makeClient(keyStore: store, transport: transport)
        _ = try await client.currentSession()
        try await client.reset()
        XCTAssertNil(try store.load())
        _ = try await client.currentSession()
        XCTAssertEqual(transport.paths().filter { $0 == "/attest/ios" }.count, 2)
    }
}

final class RequestBuilderTests: XCTestCase {
    let base = URL(string: "https://attestra.example.dev/")!

    func testEncodesPathSegmentsAndQuery() throws {
        let url = try RequestBuilder.url(
            base: base,
            provider: "gemini",
            path: "/v1beta/models/gemini pro:generateContent",
            query: [
                URLQueryItem(name: "q", value: "a&b=c+d 'e'"),
                URLQueryItem(name: "flag", value: nil),
            ]
        )
        XCTAssertEqual(
            url.absoluteString,
            "https://attestra.example.dev/p/gemini/v1beta/models/gemini%20pro:generateContent?q=a%26b%3Dc%2Bd%20%27e%27&flag"
        )
        XCTAssertEqual(
            RequestBuilder.pathAndQuery(of: url),
            "/p/gemini/v1beta/models/gemini%20pro:generateContent?q=a%26b%3Dc%2Bd%20%27e%27&flag"
        )
        let bare = try RequestBuilder.url(base: base, provider: "x", path: "/", query: [])
        XCTAssertEqual(RequestBuilder.pathAndQuery(of: bare), "/p/x/")
    }

    func testRejectsInvalidInput() {
        for (provider, path) in [("OpenAI", "/x"), ("", "/x"), ("a/b", "/x"), ("x", "x"), ("x", "/a/../b"), ("x", "/a//b"), ("x", "/./a")] {
            XCTAssertThrowsError(try RequestBuilder.url(base: base, provider: provider, path: path, query: []), "\(provider) \(path)")
        }
    }

    func testBase64URL() {
        let data = Data([0xfb, 0xff, 0xfe, 0x00])
        XCTAssertEqual(Base64URL.encode(data), "-__-AA")
        XCTAssertEqual(Base64URL.decode("-__-AA"), data)
        XCTAssertNil(Base64URL.decode("A"))
        XCTAssertNil(Base64URL.decode("!!!!"))
    }
}
