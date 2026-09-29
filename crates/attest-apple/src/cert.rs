//! X.509 parsing and ECDSA chain verification for the App Attest certificate chain.

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::{Digest, Sha256, Sha384};
use spki::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::der::Decode as _;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::Name;

use crate::{AppleError, der_lite};

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// A certificate together with the exact `tbsCertificate` bytes its signature covers.
pub(crate) struct ParsedCert<'a> {
    pub cert: Certificate,
    tbs: &'a [u8],
}

pub(crate) fn parse(der: &[u8]) -> Result<ParsedCert<'_>, AppleError> {
    let cert =
        Certificate::from_der(der).map_err(|_| AppleError::Chain("unparseable certificate"))?;
    let tbs = der_lite::tbs_certificate(der).ok_or(AppleError::Chain("unparseable certificate"))?;
    Ok(ParsedCert { cert, tbs })
}

impl ParsedCert<'_> {
    pub fn subject(&self) -> &Name {
        self.cert.tbs_certificate().subject()
    }

    pub fn check_validity(&self, now_unix: u64) -> Result<(), AppleError> {
        let validity = self.cert.tbs_certificate().validity();
        check_window(
            validity.not_before.to_unix_duration().as_secs(),
            validity.not_after.to_unix_duration().as_secs(),
            now_unix,
        )
    }

    pub fn public_key(&self) -> Result<EcKey, AppleError> {
        EcKey::from_spki(self.cert.tbs_certificate().subject_public_key_info())
    }

    /// Whether the certificate carries `basicConstraints` with `cA = TRUE`.
    pub fn is_ca(&self) -> bool {
        matches!(
            self.cert
                .tbs_certificate()
                .get_extension::<BasicConstraints>(),
            Ok(Some((_, BasicConstraints { ca: true, .. })))
        )
    }

    /// The raw value of the extension identified by `oid`, if present.
    pub fn extension_value(&self, oid: ObjectIdentifier) -> Option<&[u8]> {
        self.cert
            .tbs_certificate()
            .extensions()?
            .iter()
            .find(|ext| ext.extn_id == oid)
            .map(|ext| ext.extn_value.as_bytes())
    }

    /// The uncompressed SEC1 point of a P-256 subject public key.
    pub fn p256_point(&self) -> Result<&[u8], AppleError> {
        let spki = self.cert.tbs_certificate().subject_public_key_info();
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY || curve(spki)? != SECP256R1 {
            return Err(AppleError::Chain("credential key is not P-256"));
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(AppleError::Chain("malformed public key"))?;
        if point.len() != 65 || point.first() != Some(&0x04) {
            return Err(AppleError::Chain(
                "credential key is not an uncompressed point",
            ));
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map_err(|_| AppleError::Chain("credential key is not on the curve"))?;
        Ok(point)
    }

    /// Verifies that this certificate was issued (named and signed) by `issuer`.
    pub fn verify_issued_by(
        &self,
        issuer_subject: &Name,
        issuer_key: &EcKey,
    ) -> Result<(), AppleError> {
        let tbs = self.cert.tbs_certificate();
        if tbs.issuer() != issuer_subject {
            return Err(AppleError::Chain("issuer name mismatch"));
        }
        let algorithm = self.cert.signature_algorithm();
        if tbs.signature() != algorithm || algorithm.parameters.is_some() {
            return Err(AppleError::Chain("inconsistent signature algorithm"));
        }
        let digest: Vec<u8> = if algorithm.oid == ECDSA_WITH_SHA256 {
            Sha256::digest(self.tbs).to_vec()
        } else if algorithm.oid == ECDSA_WITH_SHA384 {
            Sha384::digest(self.tbs).to_vec()
        } else {
            return Err(AppleError::Chain("unsupported signature algorithm"));
        };
        let signature = self
            .cert
            .signature()
            .as_bytes()
            .ok_or(AppleError::Chain("malformed signature"))?;
        issuer_key.verify_prehash(&digest, signature)
    }
}

fn check_window(not_before: u64, not_after: u64, now_unix: u64) -> Result<(), AppleError> {
    if not_before <= now_unix && now_unix <= not_after {
        Ok(())
    } else {
        Err(AppleError::CertificateValidity)
    }
}

fn curve(spki: &spki::SubjectPublicKeyInfoOwned) -> Result<ObjectIdentifier, AppleError> {
    spki.algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.decode_as::<ObjectIdentifier>().ok())
        .ok_or(AppleError::Chain("missing curve parameters"))
}

/// An issuer public key.
#[derive(Debug, Clone)]
pub(crate) enum EcKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl EcKey {
    fn from_spki(spki: &spki::SubjectPublicKeyInfoOwned) -> Result<Self, AppleError> {
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(AppleError::Chain("unsupported key algorithm"));
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(AppleError::Chain("malformed public key"))?;
        let curve = curve(spki)?;
        let invalid = |_| AppleError::Chain("invalid public key");
        if curve == SECP256R1 {
            Ok(Self::P256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(invalid)?,
            ))
        } else if curve == SECP384R1 {
            Ok(Self::P384(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(invalid)?,
            ))
        } else {
            Err(AppleError::Chain("unsupported curve"))
        }
    }

    /// Verifies a DER-encoded ECDSA signature over an already computed digest.
    fn verify_prehash(&self, digest: &[u8], der_signature: &[u8]) -> Result<(), AppleError> {
        let verified = match self {
            Self::P256(key) => p256::ecdsa::Signature::from_der(der_signature)
                .and_then(|sig| key.verify_prehash(digest, &sig.normalize_s())),
            Self::P384(key) => p384::ecdsa::Signature::from_der(der_signature)
                .and_then(|sig| key.verify_prehash(digest, &sig.normalize_s())),
        };
        verified.map_err(|_| AppleError::Chain("bad certificate signature"))
    }
}

/// The trusted root: its subject, key and validity window.
#[derive(Debug, Clone)]
pub(crate) struct TrustAnchor {
    subject: Name,
    key: EcKey,
    not_before: u64,
    not_after: u64,
}

impl TrustAnchor {
    pub fn from_pem(pem: &str) -> Result<Self, AppleError> {
        let (label, der) = x509_cert::der::pem::decode_vec(pem.as_bytes())
            .map_err(|_| AppleError::Config("root certificate is not valid PEM".into()))?;
        if label != "CERTIFICATE" {
            return Err(AppleError::Config("root PEM is not a certificate".into()));
        }
        Self::from_der(&der)
    }

    /// Parses a root certificate and checks that it is self-signed.
    pub fn from_der(der: &[u8]) -> Result<Self, AppleError> {
        let root = parse(der)?;
        let key = root.public_key()?;
        root.verify_issued_by(root.subject(), &key)?;
        let validity = root.cert.tbs_certificate().validity();
        Ok(Self {
            subject: root.subject().clone(),
            key,
            not_before: validity.not_before.to_unix_duration().as_secs(),
            not_after: validity.not_after.to_unix_duration().as_secs(),
        })
    }

    pub fn check_validity(&self, now_unix: u64) -> Result<(), AppleError> {
        check_window(self.not_before, self.not_after, now_unix)
    }

    pub fn subject(&self) -> &Name {
        &self.subject
    }

    pub fn key(&self) -> &EcKey {
        &self.key
    }
}
