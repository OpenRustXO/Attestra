import Foundation
import Security

/// The persisted App Attest key: its id and whether the server accepted its attestation.
public struct StoredKey: Codable, Sendable, Equatable {
    public var keyId: String
    public var attested: Bool

    public init(keyId: String, attested: Bool) {
        self.keyId = keyId
        self.attested = attested
    }
}

/// Where the App Attest key id is kept; injectable for tests.
public protocol KeyStore: Sendable {
    func load() throws -> StoredKey?
    func save(_ key: StoredKey) throws
    func delete() throws
}

/// Keychain-backed store (`kSecClassGenericPassword`, this device only, available after
/// first unlock). The key id is not secret, but the Keychain survives app updates and is
/// excluded from backups restored to other devices, matching the App Attest key lifetime.
public struct KeychainKeyStore: KeyStore {
    public let service: String
    public let account: String

    public init(service: String = "attestra", account: String = "app-attest-key") {
        self.service = service
        self.account = account
    }

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public func load() throws -> StoredKey? {
        var query = self.query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return nil }
            return try? JSONDecoder().decode(StoredKey.self, from: data)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError(status: status)
        }
    }

    public func save(_ key: StoredKey) throws {
        let data = try JSONEncoder().encode(key)
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError(status: addStatus) }
        } else if status != errSecSuccess {
            throw KeychainError(status: status)
        }
    }

    public func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }
}

public struct KeychainError: Error, Sendable, Equatable {
    public let status: OSStatus
}

/// Non-persistent store, for tests and previews.
public final class InMemoryKeyStore: KeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var key: StoredKey?

    public init(_ key: StoredKey? = nil) {
        self.key = key
    }

    public func load() throws -> StoredKey? {
        lock.withLock { key }
    }

    public func save(_ key: StoredKey) throws {
        lock.withLock { self.key = key }
    }

    public func delete() throws {
        lock.withLock { key = nil }
    }
}
