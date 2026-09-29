package dev.attestra.client

import java.security.MessageDigest

/** Unpadded base64url (RFC 4648 §5), without `java.util.Base64` so minSdk 23 works. */
internal object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xff
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xff else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xff else 0
            out.append(ALPHABET[b0 ushr 2])
            out.append(ALPHABET[((b0 and 0x03) shl 4) or (b1 ushr 4)])
            if (i + 1 < bytes.size) out.append(ALPHABET[((b1 and 0x0f) shl 2) or (b2 ushr 6)])
            if (i + 2 < bytes.size) out.append(ALPHABET[b2 and 0x3f])
            i += 3
        }
        return out.toString()
    }

    fun decode(text: String): ByteArray? {
        if (text.length % 4 == 1) return null
        val out = java.io.ByteArrayOutputStream(text.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (c in text) {
            val value = ALPHABET.indexOf(c)
            if (value < 0) return null
            buffer = (buffer shl 6) or value
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer ushr bits) and 0xff)
            }
        }
        return out.toByteArray()
    }
}

internal fun sha256(vararg parts: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    parts.forEach(digest::update)
    return digest.digest()
}

/** `requestHash = base64url(SHA256(challenge || install_id))`, as the worker recomputes it. */
internal fun requestHash(challenge: ByteArray, installId: String): String =
    Base64Url.encode(sha256(challenge, installId.toByteArray(Charsets.UTF_8)))

/** Percent-encodes UTF-8 bytes of [text], leaving only [allowed] ASCII characters as-is. */
internal fun percentEncode(text: String, allowed: String): String {
    val out = StringBuilder()
    for (byte in text.toByteArray(Charsets.UTF_8)) {
        val c = (byte.toInt() and 0xff).toChar()
        if (c.code < 0x80 && c in allowed) out.append(c) else out.append("%%%02X".format(byte.toInt() and 0xff))
    }
    return out.toString()
}
