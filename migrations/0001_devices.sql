-- Registered devices. One row per App Attest key (iOS) or per install (Android).
CREATE TABLE IF NOT EXISTS devices (
    -- iOS: hex(key_id); Android: hex(SHA256(package_name || install_id)).
    id           TEXT    PRIMARY KEY,
    platform     TEXT    NOT NULL CHECK (platform IN ('ios', 'android')),
    -- iOS only: standard base64 of the 32-byte App Attest key id.
    key_id       TEXT    UNIQUE,
    -- iOS only: uncompressed SEC1 P-256 public key (65 bytes).
    public_key   BLOB,
    environment  TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    -- Set to 1 to revoke: sessions stop working within 60 s and re-attestation is refused.
    revoked      INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
);

CREATE INDEX IF NOT EXISTS devices_revoked ON devices (revoked) WHERE revoked = 1;
