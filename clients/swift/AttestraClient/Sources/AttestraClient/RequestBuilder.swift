import CryptoKit
import Foundation

/// Builds proxy URLs and the per-request assertion `clientData`.
///
/// Paths and queries are percent-encoded conservatively, so that the URL the worker sees
/// (after the runtime's WHATWG URL parsing) is byte-for-byte what was signed.
enum RequestBuilder {
    private static let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    /// RFC 3986 `pchar` minus `%`: none of these are touched by WHATWG path normalization.
    private static let pathAllowed = CharacterSet(charactersIn: unreserved + "!$&'()*+,;=:@")
    /// Query characters left alone by WHATWG parsing, minus the `&`, `=` and `+` delimiters.
    private static let queryAllowed = CharacterSet(charactersIn: unreserved + "!$()*,;:@/?")

    static func url(base: URL, provider: String, path: String, query: [URLQueryItem]) throws -> URL {
        let providerAllowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-_")
        guard !provider.isEmpty, provider.unicodeScalars.allSatisfy(providerAllowed.contains) else {
            throw AttestraError.invalidRequest("invalid provider name")
        }
        guard path.hasPrefix("/") else {
            throw AttestraError.invalidRequest("path must start with /")
        }
        let segments = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        var encodedPath = ""
        for (index, segment) in segments.enumerated() {
            if segment == "." || segment == ".." || (segment.isEmpty && index != segments.count - 1) {
                throw AttestraError.invalidRequest("invalid path segment")
            }
            guard let encoded = String(segment).addingPercentEncoding(withAllowedCharacters: pathAllowed) else {
                throw AttestraError.invalidRequest("unencodable path")
            }
            encodedPath += "/" + encoded
        }
        if segments.isEmpty { encodedPath = "/" }

        var string = base.absoluteString
        while string.hasSuffix("/") { string.removeLast() }
        string += "/p/\(provider)\(encodedPath)"
        if !query.isEmpty {
            let pairs = try query.map { item -> String in
                guard let name = item.name.addingPercentEncoding(withAllowedCharacters: queryAllowed),
                      let value = (item.value ?? "").addingPercentEncoding(withAllowedCharacters: queryAllowed)
                else { throw AttestraError.invalidRequest("unencodable query") }
                return item.value == nil ? name : "\(name)=\(value)"
            }
            string += "?" + pairs.joined(separator: "&")
        }
        guard let url = URL(string: string) else {
            throw AttestraError.invalidRequest("invalid URL")
        }
        return url
    }

    /// `PATH` as the worker sees it: percent-encoded path plus `?query` when non-empty.
    static func pathAndQuery(of url: URL) -> String {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let path = components?.percentEncodedPath ?? url.path
        if let query = components?.percentEncodedQuery, !query.isEmpty {
            return "\(path)?\(query)"
        }
        return path
    }

    /// `METHOD\nPATH\nb64url(SHA256(body))\nunix_seconds`
    static func clientData(method: String, pathAndQuery: String, body: Data, timestamp: Int) -> Data {
        let bodyHash = Base64URL.encode(Data(SHA256.hash(data: body)))
        return Data("\(method)\n\(pathAndQuery)\n\(bodyHash)\n\(timestamp)".utf8)
    }
}
