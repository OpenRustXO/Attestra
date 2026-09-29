//! Synthetic App Attest PKI for unit tests.
//!
//! Certificates are DER-encoded by hand so tests can produce exactly the defects they need
//! (wrong signer, missing extensions, expired validity, ...). Keys are fixed, so every run
//! is deterministic.

use ciborium::Value;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use sha2::{Digest, Sha256, Sha384};

use crate::sha256;

/// 2025-06-15T15:06:40Z
pub(crate) const NOW: u64 = 1_750_000_000;
pub(crate) const APP_ID: &str = "ABCDE12345.com.example.app";

const DAY: u64 = 86_400;
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_APPLE_NONCE: &str = "1.2.840.113635.100.8.2";

// --- DER encoding -------------------------------------------------------------------------

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        body.extend(chunk.iter().rev());
    }
    tlv(0x06, &body)
}

fn integer(value: u8) -> Vec<u8> {
    tlv(0x02, &[value])
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    tlv(0x03, &content)
}

fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

fn explicit(tag_number: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | tag_number, inner)
}

fn name(common_name: &str) -> Vec<u8> {
    let attribute = seq(&[oid("2.5.4.3"), tlv(0x0c, common_name.as_bytes())]);
    seq(&[tlv(0x31, &attribute)])
}

/// UTCTime before 2050, GeneralizedTime from 2050 on (RFC 5280).
fn time(unix: u64) -> Vec<u8> {
    let (y, m, d) = civil_from_days((unix / DAY) as i64);
    let secs = unix % DAY;
    let (hh, mm, ss) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if y < 2050 {
        tlv(
            0x17,
            format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100).as_bytes(),
        )
    } else {
        tlv(
            0x18,
            format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z").as_bytes(),
        )
    }
}

/// Howard Hinnant's days-since-epoch to civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn spki_der(curve: &str, point: &[u8]) -> Vec<u8> {
    seq(&[
        seq(&[oid(OID_EC_PUBLIC_KEY), oid(curve)]),
        bit_string(point),
    ])
}

fn basic_constraints(ca: bool) -> Vec<u8> {
    let value = if ca {
        seq(&[tlv(0x01, &[0xff])])
    } else {
        seq(&[])
    };
    seq(&[
        oid(OID_BASIC_CONSTRAINTS),
        tlv(0x01, &[0xff]),
        octet_string(&value),
    ])
}

fn apple_nonce_extension(nonce: &[u8]) -> Vec<u8> {
    let value = seq(&[explicit(1, &octet_string(nonce))]);
    seq(&[oid(OID_APPLE_NONCE), octet_string(&value)])
}

enum Signer<'a> {
    P384Sha384(&'a p384::ecdsa::SigningKey),
    P384Sha256(&'a p384::ecdsa::SigningKey),
}

struct CertSpec<'a> {
    subject: &'a str,
    issuer: &'a str,
    validity: (u64, u64),
    spki: Vec<u8>,
    extensions: Vec<Vec<u8>>,
}

fn certificate(spec: CertSpec<'_>, signer: Signer<'_>) -> Vec<u8> {
    let algorithm = seq(&[oid(match signer {
        Signer::P384Sha384(_) => OID_ECDSA_SHA384,
        Signer::P384Sha256(_) => OID_ECDSA_SHA256,
    })]);
    let mut tbs_items = vec![
        explicit(0, &integer(2)),
        integer(1),
        algorithm.clone(),
        name(spec.issuer),
        seq(&[time(spec.validity.0), time(spec.validity.1)]),
        name(spec.subject),
        spec.spki,
    ];
    if !spec.extensions.is_empty() {
        tbs_items.push(explicit(3, &seq(&spec.extensions)));
    }
    let tbs = seq(&tbs_items);
    let signature: p384::ecdsa::DerSignature = match signer {
        Signer::P384Sha384(key) => key.sign_prehash(&Sha384::digest(&tbs)).unwrap(),
        Signer::P384Sha256(key) => key.sign_prehash(&Sha256::digest(&tbs)).unwrap(),
    };
    seq(&[tbs, algorithm, bit_string(signature.as_bytes())])
}

// --- attestation / assertion objects ------------------------------------------------------

pub(crate) fn auth_data(
    app_id: &str,
    counter: u32,
    attested: Option<([u8; 16], &[u8])>,
) -> Vec<u8> {
    let mut out = sha256(&[app_id.as_bytes()]).to_vec();
    // Like real devices, set the attested-credential-data flag even on assertions.
    out.push(0x40);
    out.extend(counter.to_be_bytes());
    if let Some((aaguid, credential_id)) = attested {
        out.extend(aaguid);
        out.extend((credential_id.len() as u16).to_be_bytes());
        out.extend(credential_id);
        // Minimal COSE_Key; its contents are not used by the verifier.
        let cose = Value::Map(vec![(Value::Integer(1.into()), Value::Integer(2.into()))]);
        ciborium::into_writer(&cose, &mut out).unwrap();
    }
    out
}

pub(crate) fn encode_assertion(signature_der: &[u8], auth_data: &[u8]) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("signature".into()),
            Value::Bytes(signature_der.to_vec()),
        ),
        (
            Value::Text("authenticatorData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

/// Signs like the Secure Enclave: ECDSA-P256-SHA256 with `nonce` as the message.
pub(crate) fn assertion(
    key: &p256::ecdsa::SigningKey,
    auth_data: &[u8],
    client_data: &[u8],
) -> Vec<u8> {
    let nonce = sha256(&[auth_data, &sha256(&[client_data])]);
    let signature: p256::ecdsa::Signature = key.sign(&nonce);
    encode_assertion(&signature.to_der().to_bytes(), auth_data)
}

#[derive(Clone, Copy)]
pub(crate) enum LeafIssuer {
    Intermediate,
    /// Named as issued by the intermediate but signed with the root key.
    RootKey,
    /// Named as issued by the intermediate but signed with an unrelated key.
    Stranger,
}

pub(crate) struct AttestationSpec {
    pub app_id: String,
    pub counter: u32,
    pub aaguid: [u8; 16],
    pub nonce_override: Option<[u8; 32]>,
    pub credential_id_override: Option<Vec<u8>>,
    pub include_nonce_extension: bool,
    pub leaf_validity: (u64, u64),
    pub leaf_issuer: LeafIssuer,
    pub intermediate_is_ca: bool,
    pub fmt: &'static str,
    pub chain_len: usize,
}

impl Default for AttestationSpec {
    fn default() -> Self {
        Self {
            app_id: APP_ID.into(),
            counter: 0,
            aaguid: *b"appattest\0\0\0\0\0\0\0",
            nonce_override: None,
            credential_id_override: None,
            include_nonce_extension: true,
            leaf_validity: (NOW - DAY, NOW + 3 * DAY),
            leaf_issuer: LeafIssuer::Intermediate,
            intermediate_is_ca: true,
            fmt: "apple-appattest",
            chain_len: 2,
        }
    }
}

pub(crate) struct Built {
    pub attestation: Vec<u8>,
    pub key_id: [u8; 32],
    pub client_data: Vec<u8>,
    pub device_key: p256::ecdsa::SigningKey,
    pub public_key: Vec<u8>,
}

pub(crate) struct Pki {
    pub root_der: Vec<u8>,
    root_key: p384::ecdsa::SigningKey,
    intermediate_key: p384::ecdsa::SigningKey,
}

impl Pki {
    pub fn new() -> Self {
        Self::with_seed(0x01)
    }

    pub fn with_seed(seed: u8) -> Self {
        let root_key = p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap();
        let intermediate_key =
            p384::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(1); 48]).unwrap();
        let root_der = certificate(
            CertSpec {
                subject: "Test App Attestation Root CA",
                issuer: "Test App Attestation Root CA",
                validity: (NOW - 1000 * DAY, 2_500_000_000), // exercises GeneralizedTime
                spki: spki_of_p384(&root_key),
                extensions: vec![basic_constraints(true)],
            },
            Signer::P384Sha384(&root_key),
        );
        Self {
            root_der,
            root_key,
            intermediate_key,
        }
    }

    pub fn attestation(&self, spec: &AttestationSpec) -> Built {
        let intermediate_der = certificate(
            CertSpec {
                subject: "Test App Attestation CA 1",
                issuer: "Test App Attestation Root CA",
                validity: (NOW - 500 * DAY, NOW + 500 * DAY),
                spki: spki_of_p384(&self.intermediate_key),
                extensions: vec![basic_constraints(spec.intermediate_is_ca)],
            },
            Signer::P384Sha384(&self.root_key),
        );

        let device_key = p256::ecdsa::SigningKey::from_slice(&[0x11; 32]).unwrap();
        let public_key = device_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let key_id = sha256(&[&public_key]);
        let client_data = b"0123456789abcdef0123456789abcdef".to_vec();

        let credential_id = spec
            .credential_id_override
            .clone()
            .unwrap_or(key_id.to_vec());
        let auth_data = auth_data(
            &spec.app_id,
            spec.counter,
            Some((spec.aaguid, &credential_id)),
        );
        let nonce = spec
            .nonce_override
            .unwrap_or_else(|| sha256(&[&auth_data, &sha256(&[&client_data])]));

        let stranger = p384::ecdsa::SigningKey::from_slice(&[0x99; 48]).unwrap();
        let leaf_signer = match spec.leaf_issuer {
            LeafIssuer::Intermediate => &self.intermediate_key,
            LeafIssuer::RootKey => &self.root_key,
            LeafIssuer::Stranger => &stranger,
        };
        let mut extensions = vec![];
        if spec.include_nonce_extension {
            extensions.push(apple_nonce_extension(&nonce));
        }
        let leaf_der = certificate(
            CertSpec {
                subject: "device key",
                issuer: "Test App Attestation CA 1",
                validity: spec.leaf_validity,
                spki: spki_der(OID_P256, &public_key),
                extensions,
            },
            // Apple signs leaves with ecdsa-with-SHA256 under the P-384 intermediate key.
            Signer::P384Sha256(leaf_signer),
        );

        let chain: Vec<Value> = [leaf_der, intermediate_der.clone(), intermediate_der]
            .into_iter()
            .take(spec.chain_len)
            .map(Value::Bytes)
            .collect();
        let object = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(spec.fmt.into())),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![
                    (Value::Text("x5c".into()), Value::Array(chain)),
                    (
                        Value::Text("receipt".into()),
                        Value::Bytes(b"receipt".to_vec()),
                    ),
                ]),
            ),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut attestation = Vec::new();
        ciborium::into_writer(&object, &mut attestation).unwrap();

        Built {
            attestation,
            key_id,
            client_data,
            device_key,
            public_key,
        }
    }
}

fn spki_of_p384(key: &p384::ecdsa::SigningKey) -> Vec<u8> {
    spki_der(
        OID_P384,
        key.verifying_key().to_sec1_point(false).as_bytes(),
    )
}

#[test]
fn civil_dates() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(civil_from_days(19_000), (2022, 1, 8));
    assert_eq!(time(NOW), tlv(0x17, b"250615150640Z"));
    assert_eq!(time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
}
