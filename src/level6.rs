//! Layer 6 (presentation): how the bytes are *encoded*, as opposed to what they
//! mean. In HTTPS, that covers three things:
//!
//! 1. **TLS record protection** (RFC 8446 §5.2, §7): the AEAD encryption that
//!    turns application bytes into ciphertext. This module runs the key
//!    schedule from a traffic secret to a key and IV, builds each record's
//!    nonce, and decrypts. The ciphers themselves come from the `aes-gcm` and
//!    `chacha20poly1305` crates, and HKDF/HMAC/SHA-2 from `hkdf`, `hmac` and
//!    `sha2`. Only the TLS logic around them is written here.
//! 2. **ASN.1 DER and X.509** (ITU-T X.690, RFC 5280): the encoding of the
//!    server's certificates. A hand-written DER reader on top of `Cursor`, and a
//!    certificate decoder on top of that.
//! 3. **HTTP content-coding** (RFC 9110 §8.4): gzip and deflate bodies,
//!    decompressed with the `flate2` crate.
//!
//! The *session* side of TLS (which messages, in what order, which keys are
//! live, resumption) is layer 5: see [`crate::level5`].

use std::fmt;
use std::fmt::Write as _;
use std::io::Read as _;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crate::base_level::Operate;
use crate::cursor::{Cursor, HexDump};

// ===========================================================================
// 1. TLS 1.3 record protection
// ===========================================================================

/// The three TLS 1.3 cipher suites osiview decrypts (RFC 8446 §B.4). Each names
/// an AEAD and the hash used by the key schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    /// 0x1301: AES-128-GCM with SHA-256. The most common.
    Aes128GcmSha256,
    /// 0x1302: AES-256-GCM with SHA-384.
    Aes256GcmSha384,
    /// 0x1303: ChaCha20-Poly1305 with SHA-256. Fast without AES hardware.
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(CipherSuite::Aes128GcmSha256),
            0x1302 => Some(CipherSuite::Aes256GcmSha384),
            0x1303 => Some(CipherSuite::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            CipherSuite::Aes256GcmSha384 | CipherSuite::Chacha20Poly1305Sha256 => 32,
        }
    }

    /// Hash output length: also the length of every secret in the key schedule.
    pub fn hash_len(self) -> usize {
        match self {
            CipherSuite::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }

    /// Hashes `data` with this suite's hash. Used for the handshake transcript.
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            CipherSuite::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }

    /// HMAC with this suite's hash. Used for the Finished check.
    fn hmac(self, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        match self {
            CipherSuite::Aes256GcmSha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).ok()?;
                m.update(data);
                Some(m.finalize().into_bytes().to_vec())
            }
            _ => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).ok()?;
                m.update(data);
                Some(m.finalize().into_bytes().to_vec())
            }
        }
    }
}

/// IANA name, as in the RFC.
impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CipherSuite::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        })
    }
}

/// `HKDF-Expand-Label` (RFC 8446 §7.1), the one function the whole TLS 1.3 key
/// schedule is built from:
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// Putting the output length and a purpose label into `info` means every
/// derived value is independent: a "key" can never equal an "iv" from the same
/// secret. The `hkdf` crate does HKDF-Expand (RFC 5869); this builds the label.
/// Returns `None` if the secret is shorter than the hash, which HKDF rejects.
pub fn hkdf_expand_label(
    suite: CipherSuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
    info.push(u8::try_from(full_label.len()).ok()?);
    info.extend_from_slice(full_label.as_bytes());
    info.push(u8::try_from(context.len()).ok()?);
    info.extend_from_slice(context);

    let mut out = vec![0u8; len];
    match suite {
        CipherSuite::Aes256GcmSha384 => Hkdf::<Sha384>::from_prk(secret)
            .ok()?
            .expand(&info, &mut out)
            .ok()?,
        _ => Hkdf::<Sha256>::from_prk(secret)
            .ok()?
            .expand(&info, &mut out)
            .ok()?,
    }
    Some(out)
}

/// The key and IV for one direction, derived from a traffic secret
/// (RFC 8446 §7.3):
///
/// ```text
/// key = HKDF-Expand-Label(secret, "key", "", key_length)
/// iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

impl TrafficKeys {
    pub fn derive(suite: CipherSuite, secret: &[u8]) -> Option<Self> {
        Some(TrafficKeys {
            key: hkdf_expand_label(suite, secret, "key", &[], suite.key_len())?,
            iv: hkdf_expand_label(suite, secret, "iv", &[], 12)?,
        })
    }
}

/// Decrypts the records of one direction of a TLS 1.3 connection with one
/// traffic secret.
///
/// Per record (RFC 8446 §5.2–5.3):
///
/// ```text
/// nonce      = iv XOR (64-bit record sequence number, left-padded with zeros to 12 bytes)
/// AAD        = the 5-byte record header (type 23, version 0x0303, length)
/// plaintext  = AEAD-Decrypt(key, nonce, AAD, ciphertext‖tag)
/// plaintext  = content ‖ real content type (1 byte) ‖ zero padding
/// ```
///
/// The sequence number starts at 0 for each new key and is never sent: both
/// sides count records. Missing one record therefore breaks every record after
/// it, which is why decryption needs the fully reassembled stream.
pub struct RecordProtection {
    pub suite: CipherSuite,
    secret: Vec<u8>,
    keys: TrafficKeys,
    /// Records decrypted with the current key.
    pub seq: u64,
}

impl RecordProtection {
    pub fn new(suite: CipherSuite, secret: &[u8]) -> Option<Self> {
        Some(RecordProtection {
            suite,
            secret: secret.to_vec(),
            keys: TrafficKeys::derive(suite, secret)?,
            seq: 0,
        })
    }

    /// The nonce for the current record: the IV with the sequence number XORed
    /// into its last 8 bytes.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        for (n, iv) in nonce.iter_mut().zip(&self.keys.iv) {
            *n = *iv;
        }
        for (n, s) in nonce.iter_mut().skip(4).zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        nonce
    }

    /// Decrypts one record. `header` is its 5-byte header and `ciphertext` the
    /// rest. Returns the real content type and the content, or `None` if the AEAD
    /// tag doesn't verify (wrong key, wrong sequence number, or corrupted data).
    pub fn decrypt(&mut self, header: &[u8], ciphertext: &[u8]) -> Option<(u8, Vec<u8>)> {
        let nonce = self.nonce();
        let payload = Payload {
            msg: ciphertext,
            aad: header,
        };
        let key = self.keys.key.as_slice();
        let mut inner = match self.suite {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .ok()?
                .decrypt(Nonce::from_slice(&nonce), payload)
                .ok()?,
            CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .ok()?
                .decrypt(Nonce::from_slice(&nonce), payload)
                .ok()?,
            CipherSuite::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .ok()?
                .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
                .ok()?,
        };
        self.seq += 1;

        // TLSInnerPlaintext (§5.2): strip the zero padding from the end; the
        // last non-zero byte is the real content type.
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let content_type = inner.pop()?;
        Some((content_type, inner))
    }

    /// KeyUpdate (RFC 8446 §7.2): move to the next secret and restart the
    /// sequence number.
    ///
    /// `next = HKDF-Expand-Label(current, "traffic upd", "", Hash.length)`.
    pub fn update(&mut self) -> Option<()> {
        let next = hkdf_expand_label(
            self.suite,
            &self.secret,
            "traffic upd",
            &[],
            self.suite.hash_len(),
        )?;
        *self = RecordProtection::new(self.suite, &next)?;
        Some(())
    }
}

/// Checks a Finished message (RFC 8446 §4.4.4):
///
/// ```text
/// finished_key = HKDF-Expand-Label(handshake_traffic_secret, "finished", "", Hash.length)
/// verify_data  = HMAC(finished_key, Transcript-Hash(messages so far))
/// ```
///
/// A correct Finished proves that both sides saw the same handshake and hold the
/// same keys. For osiview it's also proof that the transcript it rebuilt is
/// byte-for-byte right.
pub fn finished_ok(
    suite: CipherSuite,
    hs_secret: &[u8],
    transcript: &[u8],
    verify_data: &[u8],
) -> bool {
    let Some(key) = hkdf_expand_label(suite, hs_secret, "finished", &[], suite.hash_len()) else {
        return false;
    };
    suite.hmac(&key, &suite.hash(transcript)).as_deref() == Some(verify_data)
}

// ===========================================================================
// 2. ASN.1 DER (ITU-T X.690)
// ===========================================================================

/// Why a DER value was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerError {
    /// The input ended inside a tag, length or value.
    Truncated,
    /// A length in long form that could have been shorter (X.690 §10.1: DER
    /// requires the minimal encoding, so there's exactly one way to encode each
    /// value; that's what makes signatures over DER well-defined).
    NonMinimalLength,
    /// Length 0x80: BER's "indefinite length", which DER forbids.
    IndefiniteLength,
    /// A tag number of 31 or more (multi-byte tags). X.509 never uses them.
    HighTagNumber,
    /// The value didn't have the expected tag.
    UnexpectedTag { expected: u8, found: u8 },
    /// A value that's malformed for its type (e.g. a bad OID or time).
    Invalid(&'static str),
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerError::Truncated => f.write_str("truncated"),
            DerError::NonMinimalLength => f.write_str("non-minimal length"),
            DerError::IndefiniteLength => f.write_str("indefinite length (BER, not DER)"),
            DerError::HighTagNumber => f.write_str("multi-byte tag"),
            DerError::UnexpectedTag { expected, found } => {
                write!(f, "expected tag 0x{expected:02x}, found 0x{found:02x}")
            }
            DerError::Invalid(what) => write!(f, "invalid {what}"),
        }
    }
}

// Universal tags. The byte is: class (2 bits) | constructed (1 bit) | number (5 bits).

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
/// SEQUENCE: tag 16 with the constructed bit (0x20) set.
pub const TAG_SEQUENCE: u8 = 0x30;
/// SET: tag 17, constructed.
pub const TAG_SET: u8 = 0x31;

/// Context-specific constructed tag `[n]` (class bits 10, constructed): 0xa0 + n.
/// X.509 uses these for optional fields, e.g. `[0]` version and `[3]` extensions.
pub fn context_constructed(n: u8) -> u8 {
    0xa0 | n
}

/// One DER value: tag, length, value (TLV).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// A reader over this value's contents, for constructed types.
    pub fn reader(&self) -> Der<'a> {
        Der::new(self.value)
    }

    fn expect(self, tag: u8) -> Result<Self, DerError> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(DerError::UnexpectedTag {
                expected: tag,
                found: self.tag,
            })
        }
    }
}

/// A DER reader: reads TLVs one after another from a slice. Every read goes
/// through `Cursor`, so lengths that run past the end are errors, not panics.
/// A nested value is read with its own `Der` over just its contents, so a child
/// can never claim more bytes than its parent has.
pub struct Der<'a> {
    c: Cursor<'a>,
}

impl<'a> Der<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Der {
            c: Cursor::new(data),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.c.remaining() == 0
    }

    /// Reads the next TLV.
    ///
    /// Length encoding (X.690 §8.1.3):
    /// - **Short form:** one byte, 0–127.
    /// - **Long form:** `0x80 | n`, then `n` bytes of big-endian length. DER only
    ///   allows it for lengths of 128 or more, with no leading zero byte.
    pub fn read(&mut self) -> Result<Tlv<'a>, DerError> {
        let tag = self.c.read_u8().ok_or(DerError::Truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(DerError::HighTagNumber);
        }
        let first = self.c.read_u8().ok_or(DerError::Truncated)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else if first == 0x80 {
            return Err(DerError::IndefiniteLength);
        } else {
            let n = usize::from(first & 0x7f);
            if n > 4 {
                return Err(DerError::Invalid("length (over 4 bytes)"));
            }
            let bytes = self.c.read_bytes(n).ok_or(DerError::Truncated)?;
            if bytes.first() == Some(&0) {
                return Err(DerError::NonMinimalLength);
            }
            let len = bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            if len < 0x80 {
                return Err(DerError::NonMinimalLength);
            }
            len
        };
        let value = self.c.read_bytes(len).ok_or(DerError::Truncated)?;
        Ok(Tlv { tag, value })
    }

    /// Reads a TLV that must have `tag`.
    pub fn read_tag(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
        self.read()?.expect(tag)
    }

    /// Reads a TLV only if its tag is `tag`; otherwise leaves the reader where it
    /// was. For OPTIONAL and DEFAULT fields.
    pub fn read_optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, DerError> {
        let rest = self.c.read_bytes(self.c.remaining()).unwrap_or(&[]);
        if rest.first() != Some(&tag) {
            self.c = Cursor::new(rest);
            return Ok(None);
        }
        let mut probe = Der::new(rest);
        let tlv = probe.read()?;
        self.c = probe.c;
        Ok(Some(tlv))
    }
}

/// Decodes an OBJECT IDENTIFIER into dotted form (X.690 §8.19). The first
/// byte packs the first two arcs as `40 × X + Y`; each later arc is base-128,
/// with the top bit meaning "more bytes follow".
pub fn decode_oid(value: &[u8]) -> Result<String, DerError> {
    let mut arcs: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    let mut in_arc = false;
    for &b in value {
        if !in_arc && b == 0x80 {
            return Err(DerError::Invalid("OID (non-minimal arc)"));
        }
        if acc > (u64::MAX >> 7) {
            return Err(DerError::Invalid("OID (arc too large)"));
        }
        acc = (acc << 7) | u64::from(b & 0x7f);
        in_arc = b & 0x80 != 0;
        if !in_arc {
            arcs.push(acc);
            acc = 0;
        }
    }
    if in_arc || arcs.is_empty() {
        return Err(DerError::Invalid("OID"));
    }
    let first = arcs.remove(0);
    let (x, y) = match first {
        0..=39 => (0, first),
        40..=79 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut s = format!("{x}.{y}");
    for a in arcs {
        let _ = write!(s, ".{a}");
    }
    Ok(s)
}

/// Names for the OIDs that show up in web certificates. Anything else prints
/// in dotted form.
pub fn oid_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        // Attribute types in names (RFC 5280 §4.1.2.4).
        "2.5.4.3" => "CN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        // Public key and signature algorithms.
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.10045.2.1" => "ecPublicKey",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.101.112" => "Ed25519",
        // Extensions (RFC 5280 §4.2).
        "2.5.29.14" => "subjectKeyIdentifier",
        "2.5.29.15" => "keyUsage",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.19" => "basicConstraints",
        "2.5.29.31" => "cRLDistributionPoints",
        "2.5.29.32" => "certificatePolicies",
        "2.5.29.35" => "authorityKeyIdentifier",
        "2.5.29.37" => "extKeyUsage",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        "1.3.6.1.4.1.11129.2.4.2" => "signedCertificateTimestamps",
        // Extended key usages.
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        _ => return None,
    })
}

/// An OID by name if known, else dotted.
fn oid_text(oid: &str) -> String {
    oid_name(oid).map_or_else(|| oid.to_string(), str::to_string)
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) as
/// `2026-01-31 23:59:59 UTC`. RFC 5280 §4.1.2.5: two-digit years below 50 are
/// 20xx, 50 and up are 19xx; dates from 2050 on must use GeneralizedTime.
fn decode_time(tlv: Tlv<'_>) -> Result<String, DerError> {
    let s = std::str::from_utf8(tlv.value).map_err(|_| DerError::Invalid("time"))?;
    let digits = s
        .strip_suffix('Z')
        .ok_or(DerError::Invalid("time (not UTC)"))?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DerError::Invalid("time"));
    }
    let (year, rest) = match (tlv.tag, digits.len()) {
        (TAG_UTC_TIME, 12) => {
            let yy: u32 = digits
                .get(..2)
                .and_then(|y| y.parse().ok())
                .ok_or(DerError::Invalid("time"))?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, digits.get(2..))
        }
        (TAG_GENERALIZED_TIME, 14) => (
            digits
                .get(..4)
                .and_then(|y| y.parse().ok())
                .ok_or(DerError::Invalid("time"))?,
            digits.get(4..),
        ),
        _ => return Err(DerError::Invalid("time")),
    };
    let r = rest.ok_or(DerError::Invalid("time"))?;
    let part = |i: usize| r.get(i..i + 2).unwrap_or("??");
    Ok(format!(
        "{year}-{}-{} {}:{}:{} UTC",
        part(0),
        part(2),
        part(4),
        part(6),
        part(8)
    ))
}

/// The string types used in names (UTF8String 0x0c, PrintableString 0x13,
/// IA5String 0x16, …), as text. All are byte strings with
/// different allowed character sets; UTF-8 decoding with replacement covers them
/// well enough for display.
fn decode_string(tlv: Tlv<'_>) -> String {
    String::from_utf8_lossy(tlv.value).into_owned()
}

// ===========================================================================
// X.509 (RFC 5280)
// ===========================================================================

/// The parts of an X.509 v3 certificate that matter for reading a TLS chain.
///
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,      -- what the issuer signs
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING }
///
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT INTEGER DEFAULT v1,
///     serialNumber        INTEGER,
///     signature           AlgorithmIdentifier,
///     issuer              Name,
///     validity            SEQUENCE { notBefore Time, notAfter Time },
///     subject             Name,
///     subjectPublicKeyInfo SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING },
///     issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL,
///     subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL,
///     extensions      [3] EXPLICIT SEQUENCE OF Extension OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// 1, 2 or 3. Anything with extensions is v3.
    pub version: u8,
    /// Hex. Unique per issuer; CAs use 16+ random bytes.
    pub serial: String,
    /// Who signed it, e.g. `C=US, O=Let's Encrypt, CN=R11`.
    pub issuer: String,
    /// Who it's for. In web certificates the real names are in the SAN.
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    /// e.g. `ecPublicKey P-256` or `rsaEncryption 2048 bits`.
    pub public_key: String,
    /// Subject Alternative Names: `DNS:example.com`, `IP:1.2.3.4`. Browsers
    /// match the host name against these, not the subject CN.
    pub san: Vec<String>,
    /// Basic Constraints: `Some(true)` for a CA certificate.
    pub is_ca: Option<bool>,
    /// Key Usage bits by name, e.g. `digitalSignature`.
    pub key_usage: Vec<String>,
    /// Every extension present, by name, with "(critical)" if marked critical.
    pub extensions: Vec<String>,
}

impl Certificate {
    /// Decodes a DER certificate. Every field is checked as it's read; anything
    /// unexpected is an error rather than a guess.
    pub fn parse(der: &[u8]) -> Result<Self, DerError> {
        let mut top = Der::new(der);
        let cert = top.read_tag(TAG_SEQUENCE)?;
        if !top.is_empty() {
            return Err(DerError::Invalid("trailing data after certificate"));
        }
        let mut c = cert.reader();
        let tbs = c.read_tag(TAG_SEQUENCE)?;
        let sig_alg = algorithm(c.read_tag(TAG_SEQUENCE)?)?;
        c.read_tag(TAG_BIT_STRING)?;

        let mut t = tbs.reader();
        let version = match t.read_optional(context_constructed(0))? {
            Some(v) => {
                let int = v.reader().read_tag(TAG_INTEGER)?;
                int.value.last().copied().unwrap_or(0) + 1
            }
            None => 1,
        };
        let serial = hex_string(t.read_tag(TAG_INTEGER)?.value);
        t.read_tag(TAG_SEQUENCE)?; // signature algorithm again (must match the outer one)
        let issuer = name(t.read_tag(TAG_SEQUENCE)?)?;
        let mut validity = t.read_tag(TAG_SEQUENCE)?.reader();
        let not_before = decode_time(validity.read()?)?;
        let not_after = decode_time(validity.read()?)?;
        let subject = name(t.read_tag(TAG_SEQUENCE)?)?;
        let public_key = public_key_info(t.read_tag(TAG_SEQUENCE)?)?;
        // Unique IDs [1] and [2] are obsolete; skip them if present.
        t.read_optional(0x81)?;
        t.read_optional(0x82)?;

        let mut cert = Certificate {
            version,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            signature_algorithm: sig_alg,
            public_key,
            san: Vec::new(),
            is_ca: None,
            key_usage: Vec::new(),
            extensions: Vec::new(),
        };
        if let Some(exts) = t.read_optional(context_constructed(3))? {
            let mut list = exts.reader().read_tag(TAG_SEQUENCE)?.reader();
            while !list.is_empty() {
                cert.extension(list.read_tag(TAG_SEQUENCE)?)?;
            }
        }
        Ok(cert)
    }

    /// One Extension: `SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    /// extnValue OCTET STRING }`. The OCTET STRING wraps the extension's own DER.
    fn extension(&mut self, ext: Tlv<'_>) -> Result<(), DerError> {
        let mut e = ext.reader();
        let oid = decode_oid(e.read_tag(TAG_OID)?.value)?;
        let critical = e
            .read_optional(TAG_BOOLEAN)?
            .is_some_and(|b| b.value.first().is_some_and(|&v| v != 0));
        let value = e.read_tag(TAG_OCTET_STRING)?.value;

        self.extensions.push(format!(
            "{}{}",
            oid_text(&oid),
            if critical { " (critical)" } else { "" }
        ));
        match oid.as_str() {
            // SubjectAltName ::= SEQUENCE OF GeneralName
            "2.5.29.17" => {
                let mut names = Der::new(value).read_tag(TAG_SEQUENCE)?.reader();
                while !names.is_empty() {
                    let gn = names.read()?;
                    match gn.tag {
                        0x82 => self.san.push(format!("DNS:{}", decode_string(gn))),
                        0x87 => self.san.push(match gn.value.len() {
                            4 => format!(
                                "IP:{}",
                                std::net::Ipv4Addr::from(
                                    <[u8; 4]>::try_from(gn.value)
                                        .map_err(|_| DerError::Invalid("IP"))?
                                )
                            ),
                            16 => format!(
                                "IP:{}",
                                std::net::Ipv6Addr::from(
                                    <[u8; 16]>::try_from(gn.value)
                                        .map_err(|_| DerError::Invalid("IP"))?
                                )
                            ),
                            _ => "IP:?".to_string(),
                        }),
                        0x81 => self.san.push(format!("email:{}", decode_string(gn))),
                        0x86 => self.san.push(format!("URI:{}", decode_string(gn))),
                        _ => {}
                    }
                }
            }
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
            "2.5.29.19" => {
                let mut bc = Der::new(value).read_tag(TAG_SEQUENCE)?.reader();
                let ca = bc
                    .read_optional(TAG_BOOLEAN)?
                    .is_some_and(|b| b.value.first().is_some_and(|&v| v != 0));
                self.is_ca = Some(ca);
            }
            // KeyUsage ::= BIT STRING. The first byte of a BIT STRING is the number
            // of unused bits at the end; bit 0 is the top bit of the next byte.
            "2.5.29.15" => {
                let bits = Der::new(value).read_tag(TAG_BIT_STRING)?.value;
                const NAMES: [&str; 9] = [
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly",
                ];
                for (i, name) in NAMES.iter().enumerate() {
                    let byte = bits.get(1 + i / 8).copied().unwrap_or(0);
                    if byte & (0x80 >> (i % 8)) != 0 {
                        self.key_usage.push((*name).to_string());
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
/// → the algorithm's name.
fn algorithm(seq: Tlv<'_>) -> Result<String, DerError> {
    let oid = decode_oid(seq.reader().read_tag(TAG_OID)?.value)?;
    Ok(oid_text(&oid))
}

/// `SubjectPublicKeyInfo`: the algorithm, plus the curve for EC keys or the
/// modulus size for RSA keys.
fn public_key_info(spki: Tlv<'_>) -> Result<String, DerError> {
    let mut s = spki.reader();
    let mut alg = s.read_tag(TAG_SEQUENCE)?.reader();
    let oid = decode_oid(alg.read_tag(TAG_OID)?.value)?;
    let key = s.read_tag(TAG_BIT_STRING)?.value;
    match oid.as_str() {
        "1.2.840.10045.2.1" => {
            let curve = alg.read_tag(TAG_OID).and_then(|c| decode_oid(c.value));
            Ok(format!(
                "ecPublicKey {}",
                curve.map(|c| oid_text(&c)).unwrap_or_default()
            ))
        }
        "1.2.840.113549.1.1.1" => {
            // The BIT STRING (after its unused-bits byte) holds
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
            let bits = (|| {
                let mut rsa = Der::new(key.get(1..)?)
                    .read_tag(TAG_SEQUENCE)
                    .ok()?
                    .reader();
                let modulus = rsa.read_tag(TAG_INTEGER).ok()?.value;
                // INTEGERs are signed, so a leading 0x00 keeps a big modulus positive.
                let m = modulus.strip_prefix(&[0]).unwrap_or(modulus);
                let top = m.first()?;
                Some(m.len() * 8 - top.leading_zeros() as usize)
            })();
            Ok(match bits {
                Some(b) => format!("rsaEncryption {b} bits"),
                None => "rsaEncryption".to_string(),
            })
        }
        other => Ok(oid_text(other)),
    }
}

/// A Name, as `C=US, O=Example, CN=example.com`.
///
/// `Name ::= SEQUENCE OF RelativeDistinguishedName`,
/// `RelativeDistinguishedName ::= SET OF SEQUENCE { type OID, value ANY }`.
fn name(seq: Tlv<'_>) -> Result<String, DerError> {
    let mut parts = Vec::new();
    let mut rdns = seq.reader();
    while !rdns.is_empty() {
        let mut set = rdns.read_tag(TAG_SET)?.reader();
        while !set.is_empty() {
            let mut atv = set.read_tag(TAG_SEQUENCE)?.reader();
            let oid = decode_oid(atv.read_tag(TAG_OID)?.value)?;
            let value = decode_string(atv.read()?);
            parts.push(format!("{}={value}", oid_text(&oid)));
        }
    }
    Ok(parts.join(", "))
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "subject   {}", self.subject)?;
        writeln!(f, "issuer    {}", self.issuer)?;
        writeln!(f, "validity  {} → {}", self.not_before, self.not_after)?;
        if !self.san.is_empty() {
            writeln!(f, "san       {}", self.san.join(", "))?;
        }
        writeln!(f, "key       {}", self.public_key)?;
        writeln!(f, "signature {}", self.signature_algorithm)?;
        writeln!(f, "version   v{}, serial {}", self.version, self.serial)?;
        if let Some(ca) = self.is_ca {
            writeln!(f, "ca        {ca}")?;
        }
        if !self.key_usage.is_empty() {
            writeln!(f, "usage     {}", self.key_usage.join(", "))?;
        }
        write!(f, "ext       {}", self.extensions.join(", "))
    }
}

// ===========================================================================
// 3. HTTP content-coding (RFC 9110 §8.4)
// ===========================================================================

/// Decompressed bodies are capped at this size, so a "zip bomb" (a tiny body
/// that inflates to gigabytes) can't exhaust memory.
const MAX_INFLATED: u64 = 64 * 1024 * 1024;

/// Undoes a `Content-Encoding`. Supports `gzip` (RFC 1952: DEFLATE with a header
/// and CRC-32 trailer, which `flate2` checks), `deflate` (which in HTTP means
/// the zlib wrapper, RFC 1950, not raw DEFLATE) and `identity`.
pub fn decode_content(encoding: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let result = match encoding.trim().to_ascii_lowercase().as_str() {
        "identity" | "" => return Ok(body.to_vec()),
        "gzip" | "x-gzip" => flate2::read::GzDecoder::new(body)
            .take(MAX_INFLATED)
            .read_to_end(&mut out),
        "deflate" => flate2::read::ZlibDecoder::new(body)
            .take(MAX_INFLATED)
            .read_to_end(&mut out),
        other => return Err(format!("content-encoding {other} not supported")),
    };
    result.map_err(|e| format!("{encoding} decode failed: {e}"))?;
    Ok(out)
}

// ===========================================================================
// Layer
// ===========================================================================

/// The presentation layer as an [`Operate`] layer: given DER bytes, decodes them
/// as a certificate.
pub struct Level6;

impl Operate for Level6 {
    fn render(&self, data: &[u8]) -> String {
        let mut out = match Certificate::parse(data) {
            Ok(cert) => format!("{cert}\n"),
            Err(e) => format!("not a DER certificate: {e}\n"),
        };
        let _ = write!(out, "{}", HexDump(data));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_vectors::*;

    const SUITE: CipherSuite = CipherSuite::Aes128GcmSha256;

    #[test]
    fn key_schedule_matches_rfc8448() {
        for (secret, key, iv) in [
            (SERVER_HS_SECRET, SERVER_HS_KEY, SERVER_HS_IV),
            (CLIENT_HS_SECRET, CLIENT_HS_KEY, CLIENT_HS_IV),
            (SERVER_AP_SECRET, SERVER_AP_KEY, SERVER_AP_IV),
            (CLIENT_AP_SECRET, CLIENT_AP_KEY, CLIENT_AP_IV),
        ] {
            let keys = TrafficKeys::derive(SUITE, &hex(secret)).unwrap();
            assert_eq!(keys.key, hex(key));
            assert_eq!(keys.iv, hex(iv));
        }
    }

    /// Decrypts a whole RFC 8448 record and checks it against the plaintext
    /// the RFC gives.
    fn decrypt_vector(secret: &str, record: &str, seq: u64) -> (u8, Vec<u8>) {
        let mut rp = RecordProtection::new(SUITE, &hex(secret)).unwrap();
        rp.seq = seq;
        let record = hex(record);
        rp.decrypt(&record[..5], &record[5..]).unwrap()
    }

    #[test]
    fn decrypts_rfc8448_records() {
        let (t, pt) = decrypt_vector(SERVER_HS_SECRET, SERVER_HS_RECORD, 0);
        assert_eq!((t, pt), (22, hex(SERVER_HS_PAYLOAD)));
        let (t, pt) = decrypt_vector(CLIENT_HS_SECRET, CLIENT_FINISHED_RECORD, 0);
        assert_eq!((t, pt), (22, hex(CLIENT_FINISHED_PAYLOAD)));
        let (t, pt) = decrypt_vector(SERVER_AP_SECRET, SERVER_TICKET_RECORD, 0);
        assert_eq!((t, pt), (22, hex(SERVER_TICKET_PAYLOAD)));
        let (t, pt) = decrypt_vector(CLIENT_AP_SECRET, CLIENT_APP_RECORD, 0);
        assert_eq!((t, pt), (23, hex(APP_PAYLOAD)));
        let (t, pt) = decrypt_vector(SERVER_AP_SECRET, SERVER_APP_RECORD, 1);
        assert_eq!((t, pt), (23, hex(APP_PAYLOAD)));
        let (t, pt) = decrypt_vector(CLIENT_AP_SECRET, CLIENT_ALERT_RECORD, 1);
        assert_eq!((t, pt), (21, vec![1, 0])); // close_notify
    }

    #[test]
    fn wrong_sequence_number_or_tampering_fails() {
        let mut rp = RecordProtection::new(SUITE, &hex(SERVER_AP_SECRET)).unwrap();
        let record = hex(SERVER_APP_RECORD);
        assert!(rp.decrypt(&record[..5], &record[5..]).is_none()); // needs seq 1, not 0
        let mut bad = hex(CLIENT_APP_RECORD);
        bad[20] ^= 1;
        let mut rp = RecordProtection::new(SUITE, &hex(CLIENT_AP_SECRET)).unwrap();
        assert!(rp.decrypt(&bad[..5], &bad[5..]).is_none());
    }

    #[test]
    fn key_update_changes_keys_and_resets_sequence() {
        let mut rp = RecordProtection::new(SUITE, &hex(CLIENT_AP_SECRET)).unwrap();
        rp.seq = 7;
        let before = rp.keys.clone();
        rp.update().unwrap();
        assert_ne!(rp.keys, before);
        assert_eq!(rp.seq, 0);
    }

    // -- DER ---------------------------------------------------------------

    #[test]
    fn der_lengths() {
        assert_eq!(Der::new(&[0x04, 0x02, 1, 2]).read().unwrap().value, &[1, 2]);
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend_from_slice(&[0; 128]);
        assert_eq!(Der::new(&long).read().unwrap().value.len(), 128);
        // Non-minimal: long form for a length under 128, or a leading zero byte.
        assert_eq!(
            Der::new(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0]).read(),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            Der::new(&[0x04, 0x82, 0x00, 0x80]).read(),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            Der::new(&[0x30, 0x80]).read(),
            Err(DerError::IndefiniteLength)
        );
        // Runs past the end, and past its parent.
        assert_eq!(
            Der::new(&[0x04, 0x05, 1, 2]).read(),
            Err(DerError::Truncated)
        );
        let parent = [0x30, 0x03, 0x04, 0x05, 1, 2, 3, 4, 5];
        let seq = Der::new(&parent).read().unwrap();
        assert_eq!(seq.reader().read(), Err(DerError::Truncated));
    }

    #[test]
    fn oids() {
        assert_eq!(decode_oid(&[0x55, 0x04, 0x03]).unwrap(), "2.5.4.3");
        assert_eq!(
            decode_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]).unwrap(),
            "1.2.840.113549.1.1.11"
        );
        assert!(decode_oid(&[0x2a, 0x86]).is_err()); // ends mid-arc
        assert!(decode_oid(&[0x2a, 0x80, 0x01]).is_err()); // non-minimal arc
    }

    #[test]
    fn times() {
        let utc = Tlv {
            tag: TAG_UTC_TIME,
            value: b"260131235959Z",
        };
        assert_eq!(decode_time(utc).unwrap(), "2026-01-31 23:59:59 UTC");
        let old = Tlv {
            tag: TAG_UTC_TIME,
            value: b"990101000000Z",
        };
        assert_eq!(decode_time(old).unwrap(), "1999-01-01 00:00:00 UTC");
        let gen_time = Tlv {
            tag: TAG_GENERALIZED_TIME,
            value: b"20500101000000Z",
        };
        assert_eq!(decode_time(gen_time).unwrap(), "2050-01-01 00:00:00 UTC");
        assert!(
            decode_time(Tlv {
                tag: TAG_UTC_TIME,
                value: b"2601"
            })
            .is_err()
        );
    }

    /// The certificate inside the RFC 8448 Certificate message.
    pub(crate) fn rfc8448_cert() -> Vec<u8> {
        // Certificate message: type(1) len(3) context_len(1)=0 list_len(3)
        // cert_len(3) cert...
        let p = hex(SERVER_HS_PAYLOAD);
        let start = p
            .windows(4)
            .position(|w| w == [0x0b, 0x00, 0x01, 0xb9])
            .unwrap();
        let cert_len = usize::from(p[start + 8]) << 16
            | usize::from(p[start + 9]) << 8
            | usize::from(p[start + 10]);
        p[start + 11..start + 11 + cert_len].to_vec()
    }

    #[test]
    fn parses_rfc8448_certificate() {
        let cert = Certificate::parse(&rfc8448_cert()).unwrap();
        assert_eq!(cert.version, 3);
        assert_eq!(cert.subject, "CN=rsa");
        assert_eq!(cert.issuer, "CN=rsa");
        assert!(cert.public_key.starts_with("rsaEncryption"));
        assert_eq!(cert.signature_algorithm, "sha256WithRSAEncryption");
        assert!(cert.not_before.ends_with("UTC"));
    }

    #[test]
    fn truncated_certificate_is_an_error() {
        let der = rfc8448_cert();
        for cut in [1, 10, der.len() / 2, der.len() - 1] {
            assert!(Certificate::parse(&der[..cut]).is_err(), "cut at {cut}");
        }
    }

    /// Fuzz-style check: thousands of truncated and bit-flipped certificates must
    /// give errors, never panics.
    #[test]
    fn mangled_certificates_never_panic() {
        let der = rfc8448_cert();
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..5000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut m = der.clone();
            let i = (state as usize) % m.len();
            m[i] ^= (state >> 32) as u8 | 1;
            let cut = ((state >> 16) as usize) % (m.len() + 1);
            let _ = Certificate::parse(&m[..cut]);
            let _ = Certificate::parse(&m);
        }
    }

    // -- content coding ------------------------------------------------------

    #[test]
    fn gzip_and_deflate_bodies() {
        use flate2::Compression;
        use std::io::Write as _;
        let text = b"hello hello hello hello, layer six".repeat(20);

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(&text).unwrap();
        let gz = gz.finish().unwrap();
        assert!(gz.len() < text.len());
        assert_eq!(decode_content("gzip", &gz).unwrap(), text);

        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&text).unwrap();
        assert_eq!(
            decode_content("deflate", &z.finish().unwrap()).unwrap(),
            text
        );

        assert!(decode_content("gzip", b"not gzip").is_err());
        assert!(decode_content("br", b"").is_err());
    }
}
