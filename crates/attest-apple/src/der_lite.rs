//! A minimal, strict DER TLV reader.
//!
//! Used where `x509-cert` does not expose what we need: the raw `tbsCertificate` bytes (the
//! signature covers the exact encoding, so re-encoding the parsed structure is not safe) and
//! the contents of Apple's nonce extension.

/// One DER element split off the front of an input.
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The complete element: tag, length and content.
    pub raw: &'a [u8],
    pub rest: &'a [u8],
}

/// Reads one TLV with a single-byte tag. Rejects indefinite and non-minimal lengths.
pub(crate) fn read_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tag numbers are not used by anything we parse
    }
    let (&first, mut after_len) = after_tag.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 {
            return None;
        }
        let (len_bytes, rest) = after_len.split_at_checked(count)?;
        after_len = rest;
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        // Minimal encoding: long form only for >= 128, no leading zero byte.
        if len < 0x80 || len_bytes.first() == Some(&0) {
            return None;
        }
        len
    };
    let (content, rest) = after_len.split_at_checked(len)?;
    let header_len = input.len() - after_len.len();
    Some(Tlv {
        tag,
        content,
        raw: input.get(..header_len + len)?,
        rest,
    })
}

/// Reads exactly one TLV with the expected tag and no trailing bytes.
pub(crate) fn read_only(input: &[u8], tag: u8) -> Option<&[u8]> {
    let tlv = read_tlv(input)?;
    (tlv.tag == tag && tlv.rest.is_empty()).then_some(tlv.content)
}

/// Returns the raw `tbsCertificate` element of a DER certificate.
pub(crate) fn tbs_certificate(cert_der: &[u8]) -> Option<&[u8]> {
    let outer = read_only(cert_der, 0x30)?;
    let tbs = read_tlv(outer)?;
    (tbs.tag == 0x30).then_some(tbs.raw)
}

/// Decodes the value of extension 1.2.840.113635.100.8.2:
/// `SEQUENCE { [1] EXPLICIT OCTET STRING nonce }`.
pub(crate) fn apple_nonce(extn_value: &[u8]) -> Option<&[u8]> {
    let mut items = read_only(extn_value, 0x30)?;
    while !items.is_empty() {
        let item = read_tlv(items)?;
        if item.tag == 0xa1 {
            return read_only(item.content, 0x04);
        }
        items = item.rest;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_lengths() {
        let short = [0x04, 0x02, 0xaa, 0xbb, 0xff];
        let tlv = read_tlv(&short).unwrap();
        assert_eq!(
            (tlv.tag, tlv.content, tlv.raw, tlv.rest),
            (0x04, &[0xaa, 0xbb][..], &short[..4], &[0xff][..])
        );

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7u8; 0x80]);
        let tlv = read_tlv(&long).unwrap();
        assert_eq!(tlv.content.len(), 0x80);
        assert!(tlv.rest.is_empty());
    }

    #[test]
    fn rejects_bad_encodings() {
        for bad in [
            &[][..],
            &[0x04],
            &[0x04, 0x03, 0x00],          // truncated
            &[0x04, 0x80],                // indefinite length
            &[0x04, 0x81, 0x01, 0x00],    // non-minimal long form
            &[0x04, 0x82, 0x00, 0x80],    // leading zero
            &[0x04, 0x84, 0, 0, 0, 1, 0], // too many length bytes
            &[0x1f, 0x01, 0x00],          // multi-byte tag
        ] {
            assert!(read_tlv(bad).is_none(), "{bad:?}");
        }
        assert!(read_only(&[0x04, 0x00, 0x00], 0x04).is_none()); // trailing data
        assert!(read_only(&[0x04, 0x00], 0x30).is_none()); // wrong tag
    }

    #[test]
    fn extracts_apple_nonce() {
        let nonce = [9u8; 32];
        let mut value = vec![0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];
        value.extend(nonce);
        assert_eq!(apple_nonce(&value), Some(&nonce[..]));

        // Other members before [1] are skipped.
        let mut value = vec![0x30, 0x27, 0x02, 0x01, 0x05, 0xa1, 0x22, 0x04, 0x20];
        value.extend(nonce);
        assert_eq!(apple_nonce(&value), Some(&nonce[..]));

        assert_eq!(apple_nonce(&[0x30, 0x00]), None);
        assert_eq!(apple_nonce(&[0x04, 0x00]), None);
    }
}
