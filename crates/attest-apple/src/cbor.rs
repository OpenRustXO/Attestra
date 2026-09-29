//! Helpers for reading the small CBOR maps App Attest produces.

use ciborium::Value;

use crate::AppleError;

/// Decodes `bytes` as exactly one CBOR map.
pub(crate) fn decode_map(bytes: &[u8]) -> Result<Vec<(Value, Value)>, AppleError> {
    let mut reader = bytes;
    let value: Value =
        ciborium::from_reader(&mut reader).map_err(|_| AppleError::Malformed("invalid CBOR"))?;
    if !reader.is_empty() {
        return Err(AppleError::Malformed("trailing data after CBOR"));
    }
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(AppleError::Malformed("expected a CBOR map")),
    }
}

pub(crate) fn get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

pub(crate) fn get_bytes<'a>(
    map: &'a [(Value, Value)],
    key: &str,
    what: &'static str,
) -> Result<&'a [u8], AppleError> {
    get(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or(AppleError::Malformed(what))
}
