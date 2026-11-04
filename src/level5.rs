//! Layer 5 (session): TLS 1.3 (RFC 8446) as a *conversation*: records, the
//! handshake messages inside them, which keys are live at each point, and
//! whether a connection resumes an earlier session.
//!
//! The internet stack doesn't map neatly onto OSI layers 5 and 6, and TLS does
//! both jobs. The split in osiview:
//!
//! - **Layer 5, this module:** record framing, handshake messages and their
//!   extensions, the per-connection state machine (plaintext → handshake keys →
//!   application keys → KeyUpdate), Finished checks, keylog lookup, session
//!   tickets and PSK resumption.
//! - **Layer 6, [`crate::level6`]:** the encoding itself: key derivation, AEAD
//!   decryption, X.509 certificates, compressed bodies.
//!
//! # How a TLS 1.3 connection looks on the wire
//!
//! ```text
//! client                                             server
//! ClientHello (random, SNI, ALPN, key_share)  ──►                       plaintext
//!                                             ◄──  ServerHello (suite, key_share)
//!                                             ◄──  [ChangeCipherSpec]   ignored
//!                                             ◄──  {EncryptedExtensions} handshake keys
//!                                             ◄──  {Certificate}
//!                                             ◄──  {CertificateVerify}
//!                                             ◄──  {Finished}
//! [ChangeCipherSpec]                          ──►
//! {Finished}                                  ──►                       handshake keys
//! [application data]                          ◄─►                       application keys
//!                                             ◄──  [NewSessionTicket]   (for resumption)
//! ```
//!
//! `{}` is encrypted with handshake keys, `[]` with application keys. Everything
//! encrypted is sent as record type 23 ("application data"); the real type is
//! inside the encryption. So without keys an observer sees the hellos and then
//! only opaque records.
//!
//! # Decrypting with a keylog
//!
//! Browsers and curl write per-connection secrets to the file named by the
//! `SSLKEYLOGFILE` environment variable (draft-ietf-tls-keylogfile). Each line is
//! `LABEL <client random> <secret>`. osiview finds a connection's lines by the
//! ClientHello's random, then derives keys from the secrets in layer 6.
//!
//! # Specs
//!
//! - Records: RFC 8446 §5. Handshake messages: §4. Extensions: §4.2, plus
//!   RFC 6066 §3 (SNI) and RFC 7301 §3 (ALPN).
//! - Key changes: §7.1 and §7.2 (KeyUpdate). State machines: Appendix A.
//! - Resumption: §2.2, §4.6.1 (NewSessionTicket), §4.2.11 (pre_shared_key).
//! - Keylog format: draft-ietf-tls-keylogfile.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::base_level::Operate;
use crate::cursor::{Cursor, HexDump};
use crate::display::LayerLine;
use crate::level2::field;
use crate::level6::{CipherSuite, RecordProtection, finished_ok};

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

/// Record content type names.
pub fn content_type_name(t: u8) -> &'static str {
    match t {
        CT_CHANGE_CIPHER_SPEC => "change_cipher_spec",
        CT_ALERT => "alert",
        CT_HANDSHAKE => "handshake",
        CT_APPLICATION_DATA => "application_data",
        _ => "unknown",
    }
}

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_END_OF_EARLY_DATA: u8 = 5;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_REQUEST: u8 = 13;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;
pub const HS_KEY_UPDATE: u8 = 24;

/// Handshake message type names (RFC 8446 §4).
pub fn handshake_type_name(t: u8) -> &'static str {
    match t {
        HS_CLIENT_HELLO => "ClientHello",
        HS_SERVER_HELLO => "ServerHello",
        HS_NEW_SESSION_TICKET => "NewSessionTicket",
        HS_END_OF_EARLY_DATA => "EndOfEarlyData",
        HS_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
        HS_CERTIFICATE => "Certificate",
        HS_CERTIFICATE_REQUEST => "CertificateRequest",
        HS_CERTIFICATE_VERIFY => "CertificateVerify",
        HS_FINISHED => "Finished",
        HS_KEY_UPDATE => "KeyUpdate",
        _ => "unknown handshake message",
    }
}

/// GREASE (RFC 8701): clients put random reserved values like 0x0a0a or 0x1a1a
/// into lists, so servers that choke on unknown values get found and fixed.
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// Protocol version names. In TLS 1.3 the record and hello "legacy_version"
/// fields are frozen at TLS 1.2 (0x0303) for compatibility; the real version is
/// in the supported_versions extension.
pub fn version_name(v: u16) -> String {
    match v {
        0x0304 => "TLS 1.3".into(),
        0x0303 => "TLS 1.2".into(),
        0x0302 => "TLS 1.1".into(),
        0x0301 => "TLS 1.0".into(),
        v if is_grease(v) => "GREASE".into(),
        v => format!("0x{v:04x}"),
    }
}

/// Cipher suite names: the TLS 1.3 ones, and the TLS 1.2 suites clients still
/// offer.
pub fn cipher_suite_name(id: u16) -> String {
    if let Some(s) = CipherSuite::from_id(id) {
        return s.to_string();
    }
    match id {
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256".into(),
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384".into(),
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256".into(),
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384".into(),
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305".into(),
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305".into(),
        0x00ff => "EMPTY_RENEGOTIATION_INFO_SCSV".into(),
        v if is_grease(v) => "GREASE".into(),
        v => format!("0x{v:04x}"),
    }
}

/// Key exchange group names (supported_groups, key_share).
pub fn group_name(g: u16) -> String {
    match g {
        0x001d => "x25519".into(),
        0x001e => "x448".into(),
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        0x0019 => "secp521r1".into(),
        0x0100 => "ffdhe2048".into(),
        0x0101 => "ffdhe3072".into(),
        0x0102 => "ffdhe4096".into(),
        0x11ec => "X25519MLKEM768".into(),
        0x6399 => "X25519Kyber768Draft00".into(),
        v if is_grease(v) => "GREASE".into(),
        v => format!("0x{v:04x}"),
    }
}

/// Signature scheme names (signature_algorithms, CertificateVerify).
pub fn signature_scheme_name(s: u16) -> String {
    match s {
        0x0401 => "rsa_pkcs1_sha256".into(),
        0x0501 => "rsa_pkcs1_sha384".into(),
        0x0601 => "rsa_pkcs1_sha512".into(),
        0x0403 => "ecdsa_secp256r1_sha256".into(),
        0x0503 => "ecdsa_secp384r1_sha384".into(),
        0x0603 => "ecdsa_secp521r1_sha512".into(),
        0x0804 => "rsa_pss_rsae_sha256".into(),
        0x0805 => "rsa_pss_rsae_sha384".into(),
        0x0806 => "rsa_pss_rsae_sha512".into(),
        0x0807 => "ed25519".into(),
        0x0808 => "ed448".into(),
        0x0809 => "rsa_pss_pss_sha256".into(),
        v if is_grease(v) => "GREASE".into(),
        v => format!("0x{v:04x}"),
    }
}

/// Extension names (IANA "TLS ExtensionType Values").
pub fn extension_name(t: u16) -> String {
    match t {
        0 => "server_name".into(),
        5 => "status_request".into(),
        10 => "supported_groups".into(),
        11 => "ec_point_formats".into(),
        13 => "signature_algorithms".into(),
        16 => "application_layer_protocol_negotiation".into(),
        18 => "signed_certificate_timestamp".into(),
        21 => "padding".into(),
        22 => "encrypt_then_mac".into(),
        23 => "extended_master_secret".into(),
        27 => "compress_certificate".into(),
        28 => "record_size_limit".into(),
        35 => "session_ticket".into(),
        41 => "pre_shared_key".into(),
        42 => "early_data".into(),
        43 => "supported_versions".into(),
        44 => "cookie".into(),
        45 => "psk_key_exchange_modes".into(),
        49 => "post_handshake_auth".into(),
        51 => "key_share".into(),
        57 => "quic_transport_parameters".into(),
        0x4469 | 0x44cd => "application_settings".into(),
        0xfe0d => "encrypted_client_hello".into(),
        0xff01 => "renegotiation_info".into(),
        v if is_grease(v) => "GREASE".into(),
        v => format!("extension 0x{v:04x}"),
    }
}

/// Alert names (RFC 8446 §6).
fn alert_text(level: u8, desc: u8) -> String {
    let name = match desc {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        80 => "internal_error",
        90 => "user_canceled",
        109 => "missing_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    };
    let level = match level {
        1 => "warning",
        2 => "fatal",
        _ => "?",
    };
    format!("Alert {level} {name} ({desc})")
}

// ---------------------------------------------------------------------------
// Vector helpers
// ---------------------------------------------------------------------------

// TLS's presentation language prefixes variable-length vectors with their
// length in 1, 2 or 3 bytes: `opaque x<0..255>` has a 1-byte length, and so on.

fn vec8<'a>(c: &mut Cursor<'a>) -> Option<&'a [u8]> {
    let n = c.read_u8()?;
    c.read_bytes(usize::from(n))
}

fn vec16<'a>(c: &mut Cursor<'a>) -> Option<&'a [u8]> {
    let n = c.read_u16_be()?;
    c.read_bytes(usize::from(n))
}

fn read_u24(c: &mut Cursor<'_>) -> Option<usize> {
    let b = c.read_bytes(3)?;
    Some(b.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x)))
}

fn vec24<'a>(c: &mut Cursor<'a>) -> Option<&'a [u8]> {
    let n = read_u24(c)?;
    c.read_bytes(n)
}

/// A list of u16s (cipher suites, groups, versions, …).
fn u16_list(data: &[u8]) -> Vec<u16> {
    let mut c = Cursor::new(data);
    let mut out = Vec::new();
    while let Some(v) = c.read_u16_be() {
        out.push(v);
    }
    out
}

fn names(list: &[u16], f: fn(u16) -> String) -> String {
    list.iter().map(|v| f(*v)).collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------
// Records (RFC 8446 §5.1)
// ---------------------------------------------------------------------------

/// The largest record TLS 1.3 allows on the wire: 2^14 bytes of plaintext plus
/// 256 bytes of AEAD expansion (§5.2).
const MAX_RECORD: usize = 16384 + 256;

/// One TLS record.
///
/// ```text
/// struct {
///     ContentType type;                  // 1 byte: 20, 21, 22 or 23
///     ProtocolVersion legacy_record_version;  // 2 bytes: 0x0301 or 0x0303
///     uint16 length;
///     opaque fragment[length];
/// } TLSPlaintext;
/// ```
///
/// Records are TLS's own framing on top of the TCP byte stream. They have
/// nothing to do with TCP segments: one segment can carry several records, and
/// one record can span many segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsRecord<'a> {
    pub content_type: u8,
    pub version: u16,
    pub fragment: &'a [u8],
    /// The 5-byte header. For encrypted records this is the AEAD's AAD.
    pub header: &'a [u8],
}

impl<'a> TlsRecord<'a> {
    /// Reads one record from the start of `data`, returning it and the bytes
    /// after it. `None` if the record isn't complete or its header is invalid.
    pub fn parse(data: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let mut c = Cursor::new(data);
        let header = Cursor::new(data).read_bytes(5)?;
        let content_type = c.read_u8()?;
        let version = c.read_u16_be()?;
        let len = usize::from(c.read_u16_be()?);
        if !(CT_CHANGE_CIPHER_SPEC..=CT_APPLICATION_DATA).contains(&content_type)
            || len > MAX_RECORD
        {
            return None;
        }
        let fragment = c.read_bytes(len)?;
        let rest = c.read_bytes(c.remaining())?;
        Some((
            TlsRecord {
                content_type,
                version,
                fragment,
                header,
            },
            rest,
        ))
    }

    /// Splits a stream into records. Returns the records and any bytes left
    /// over (an incomplete last record, or data that isn't TLS).
    pub fn split(mut data: &'a [u8]) -> (Vec<Self>, &'a [u8]) {
        let mut out = Vec::new();
        while let Some((rec, rest)) = TlsRecord::parse(data) {
            out.push(rec);
            data = rest;
        }
        (out, data)
    }
}

/// True if `data` starts with something that looks like a TLS record header:
/// a known content type, major version 3, and a plausible length. Used to
/// decide whether a TCP payload is TLS, whatever the port.
pub fn looks_like_tls(data: &[u8]) -> bool {
    let mut c = Cursor::new(data);
    let (Some(t), Some(major), Some(minor), Some(len)) =
        (c.read_u8(), c.read_u8(), c.read_u8(), c.read_u16_be())
    else {
        return false;
    };
    (CT_CHANGE_CIPHER_SPEC..=CT_APPLICATION_DATA).contains(&t)
        && major == 3
        && minor <= 4
        && usize::from(len) <= MAX_RECORD
}

// ---------------------------------------------------------------------------
// Handshake messages (RFC 8446 §4)
// ---------------------------------------------------------------------------

/// One handshake message.
///
/// ```text
/// struct {
///     HandshakeType msg_type;   // 1 byte
///     uint24 length;
///     opaque body[length];
/// } Handshake;
/// ```
///
/// Handshake messages are a *second* layer of framing inside records: a large
/// Certificate message spans several records, and one record can hold several
/// small messages. So they're parsed from a buffer of record contents, not
/// from single records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    pub msg_type: u8,
    pub body: &'a [u8],
    /// Header + body, as hashed into the transcript.
    pub raw: &'a [u8],
}

impl<'a> HandshakeMessage<'a> {
    /// Reads every complete message from `buf`. Returns them and how many bytes
    /// they used, so the caller can keep any incomplete tail for later.
    pub fn split(buf: &'a [u8]) -> (Vec<Self>, usize) {
        let mut out = Vec::new();
        let mut used = 0;
        loop {
            let mut c = Cursor::new(buf);
            if c.read_bytes(used).is_none() {
                break;
            }
            let Some(msg_type) = c.read_u8() else { break };
            let Some(len) = read_u24(&mut c) else { break };
            let Some(body) = c.read_bytes(len) else { break };
            let Some(raw) = Cursor::new(buf)
                .read_bytes(used + 4 + len)
                .and_then(|all| all.get(used..))
            else {
                break;
            };
            out.push(HandshakeMessage {
                msg_type,
                body,
                raw,
            });
            used += 4 + len;
        }
        (out, used)
    }
}

/// One extension: a 2-byte type and a length-prefixed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    pub ext_type: u16,
    pub data: &'a [u8],
}

fn parse_extensions(data: &[u8]) -> Option<Vec<Extension<'_>>> {
    let mut c = Cursor::new(data);
    let mut out = Vec::new();
    while c.remaining() > 0 {
        let ext_type = c.read_u16_be()?;
        let data = vec16(&mut c)?;
        out.push(Extension { ext_type, data });
    }
    Some(out)
}

/// Which message an extension is in. Several extensions have a different
/// format in the ClientHello than in the ServerHello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Where {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    Other,
}

/// An extension's contents as text.
fn describe_extension(ext: &Extension<'_>, place: Where) -> String {
    let mut c = Cursor::new(ext.data);
    let text = (|| -> Option<String> {
        Some(match ext.ext_type {
            // SNI (RFC 6066 §3): the host name the client wants. Sent in clear
            // in the ClientHello, which is why ECH exists.
            0 if place == Where::ClientHello => {
                let mut list = Cursor::new(vec16(&mut c)?);
                let mut hosts = Vec::new();
                while list.remaining() > 0 {
                    let kind = list.read_u8()?;
                    let name = vec16(&mut list)?;
                    if kind == 0 {
                        hosts.push(String::from_utf8_lossy(name).into_owned());
                    }
                }
                hosts.join(", ")
            }
            0 => "acknowledged".into(),
            // ALPN (RFC 7301): protocols offered (client) or chosen (server).
            16 => alpn_list(ext.data)?.join(", "),
            // supported_versions: a list in the ClientHello, one value in the
            // ServerHello. This is how TLS 1.3 is actually negotiated.
            43 if place == Where::ClientHello => names(&u16_list(vec8(&mut c)?), version_name),
            43 => version_name(c.read_u16_be()?),
            10 => names(&u16_list(vec16(&mut c)?), group_name),
            13 => names(&u16_list(vec16(&mut c)?), signature_scheme_name),
            // key_share: the client's ephemeral public keys, one per group it
            // guesses; the server answers with one. A HelloRetryRequest names
            // only the group it wants instead.
            51 if place == Where::ClientHello => {
                let mut list = Cursor::new(vec16(&mut c)?);
                let mut shares = Vec::new();
                while list.remaining() > 0 {
                    let group = list.read_u16_be()?;
                    let key = vec16(&mut list)?;
                    shares.push(format!("{} ({} bytes)", group_name(group), key.len()));
                }
                shares.join(", ")
            }
            51 if place == Where::HelloRetryRequest => {
                format!("retry with {}", group_name(c.read_u16_be()?))
            }
            51 => {
                let group = c.read_u16_be()?;
                format!("{} ({} bytes)", group_name(group), vec16(&mut c)?.len())
            }
            45 => vec8(&mut c)?
                .iter()
                .map(|m| match m {
                    0 => "psk_ke",
                    1 => "psk_dhe_ke",
                    _ => "?",
                })
                .collect::<Vec<_>>()
                .join(", "),
            // pre_shared_key: the client offers tickets; the server picks one.
            41 if place == Where::ClientHello => {
                let ids = psk_identities(ext.data)?;
                format!(
                    "{} identit{} offered",
                    ids.len(),
                    if ids.len() == 1 { "y" } else { "ies" }
                )
            }
            41 => format!("accepted identity {}", c.read_u16_be()?),
            42 if ext.data.is_empty() => "requested".into(),
            42 => format!("max early data {} bytes", c.read_u32_be()?),
            21 => format!("{} bytes", ext.data.len()),
            28 => format!("{} bytes", c.read_u16_be()?),
            _ => format!("{} bytes", ext.data.len()),
        })
    })();
    format!(
        "{}: {}",
        extension_name(ext.ext_type),
        text.unwrap_or_else(|| "(malformed)".into())
    )
}

fn alpn_list(data: &[u8]) -> Option<Vec<String>> {
    let mut c = Cursor::new(data);
    let mut list = Cursor::new(vec16(&mut c)?);
    let mut out = Vec::new();
    while list.remaining() > 0 {
        out.push(String::from_utf8_lossy(vec8(&mut list)?).into_owned());
    }
    Some(out)
}

/// The ticket identities in a ClientHello pre_shared_key extension:
/// `identities<7..2^16-1>` of `{ opaque identity<1..2^16-1>; uint32 obfuscated_ticket_age; }`.
fn psk_identities(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut c = Cursor::new(data);
    let mut list = Cursor::new(vec16(&mut c)?);
    let mut out = Vec::new();
    while list.remaining() > 0 {
        out.push(vec16(&mut list)?);
        list.read_u32_be()?;
    }
    Some(out)
}

/// The ClientHello: the client's opening offer (RFC 8446 §4.1.2).
///
/// ```text
/// struct {
///     ProtocolVersion legacy_version = 0x0303;
///     Random random;                          // 32 bytes
///     opaque legacy_session_id<0..32>;        // random in TLS 1.3 (middlebox compat)
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// } ClientHello;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub legacy_version: u16,
    /// 32 random bytes. Keylogs are indexed by this.
    pub random: [u8; 32],
    pub session_id: &'a [u8],
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<Extension<'a>>,
}

impl<'a> ClientHello<'a> {
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(body);
        let legacy_version = c.read_u16_be()?;
        let random = c.read_bytes(32)?.try_into().ok()?;
        let session_id = vec8(&mut c)?;
        let cipher_suites = u16_list(vec16(&mut c)?);
        vec8(&mut c)?; // compression methods: always just "null" in TLS 1.3
        let extensions = if c.remaining() > 0 {
            parse_extensions(vec16(&mut c)?)?
        } else {
            Vec::new()
        };
        Some(ClientHello {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            extensions,
        })
    }

    fn ext(&self, t: u16) -> Option<&Extension<'a>> {
        self.extensions.iter().find(|e| e.ext_type == t)
    }

    /// The server name from SNI.
    pub fn sni(&self) -> Option<String> {
        let d = describe_extension(self.ext(0)?, Where::ClientHello);
        d.strip_prefix("server_name: ").map(str::to_string)
    }

    pub fn alpn(&self) -> Vec<String> {
        self.ext(16)
            .and_then(|e| alpn_list(e.data))
            .unwrap_or_default()
    }

    /// Ticket identities offered for resumption.
    pub fn psk_identities(&self) -> Vec<&'a [u8]> {
        self.ext(41)
            .and_then(|e| psk_identities(e.data))
            .unwrap_or_default()
    }
}

/// `ClientHello sni example.com, alpn h2, http/1.1, 17 suites, TLS 1.3 offered`.
impl fmt::Display for ClientHello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientHello")?;
        let mut parts = Vec::new();
        if let Some(sni) = self.sni() {
            parts.push(format!("sni {sni}"));
        }
        let alpn = self.alpn();
        if !alpn.is_empty() {
            parts.push(format!("alpn {}", alpn.join(", ")));
        }
        parts.push(format!("{} cipher suites", self.cipher_suites.len()));
        if !self.psk_identities().is_empty() {
            parts.push("offers resumption".into());
        }
        write!(f, " {}", parts.join(", "))
    }
}

/// The ServerHello: the server's choices (RFC 8446 §4.1.3). Same layout as the
/// ClientHello but with one cipher suite and one compression method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello<'a> {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: &'a [u8],
    pub cipher_suite: u16,
    pub extensions: Vec<Extension<'a>>,
}

impl<'a> ServerHello<'a> {
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(body);
        let legacy_version = c.read_u16_be()?;
        let random = c.read_bytes(32)?.try_into().ok()?;
        let session_id = vec8(&mut c)?;
        let cipher_suite = c.read_u16_be()?;
        c.read_u8()?;
        let extensions = if c.remaining() > 0 {
            parse_extensions(vec16(&mut c)?)?
        } else {
            Vec::new()
        };
        Some(ServerHello {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            extensions,
        })
    }

    /// A HelloRetryRequest is a ServerHello whose random is the fixed value
    /// SHA-256("HelloRetryRequest") (§4.1.3). The server sends it when none of
    /// the client's key shares suit it; the client then sends a second ClientHello.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random[..] == Sha256::digest(b"HelloRetryRequest")[..]
    }

    /// The negotiated version: supported_versions if present, otherwise the
    /// legacy field (which means TLS 1.2 or older).
    pub fn version(&self) -> u16 {
        self.extensions
            .iter()
            .find(|e| e.ext_type == 43)
            .and_then(|e| Cursor::new(e.data).read_u16_be())
            .unwrap_or(self.legacy_version)
    }

    /// True if the server accepted a pre-shared key, i.e. this connection
    /// resumes an earlier session.
    pub fn accepted_psk(&self) -> bool {
        self.extensions.iter().any(|e| e.ext_type == 41)
    }

    fn place(&self) -> Where {
        if self.is_hello_retry_request() {
            Where::HelloRetryRequest
        } else {
            Where::ServerHello
        }
    }
}

/// `ServerHello TLS 1.3, TLS_AES_128_GCM_SHA256` or `HelloRetryRequest …`.
impl fmt::Display for ServerHello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.is_hello_retry_request() {
            "HelloRetryRequest"
        } else {
            "ServerHello"
        };
        write!(
            f,
            "{name} {}, {}",
            version_name(self.version()),
            cipher_suite_name(self.cipher_suite)
        )?;
        if self.accepted_psk() {
            f.write_str(", resumes a session (PSK accepted)")?;
        }
        Ok(())
    }
}

/// A NewSessionTicket (§4.6.1): sent by the server after the handshake, under
/// application keys. The client stores it and can offer it in a later
/// ClientHello's pre_shared_key to skip the certificate exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSessionTicket<'a> {
    /// Seconds the ticket may be used for (at most 7 days).
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: &'a [u8],
    /// Opaque to the client: usually the session state encrypted with a key
    /// only the server knows.
    pub ticket: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

impl<'a> NewSessionTicket<'a> {
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(body);
        Some(NewSessionTicket {
            lifetime: c.read_u32_be()?,
            age_add: c.read_u32_be()?,
            nonce: vec8(&mut c)?,
            ticket: vec16(&mut c)?,
            extensions: parse_extensions(vec16(&mut c)?)?,
        })
    }
}

/// The DER certificates in a Certificate message (§4.4.2):
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct { opaque cert_data<1..2^24-1>; Extension extensions<0..2^16-1>; } CertificateEntry;
/// ```
///
/// The first is the server's own certificate; the rest are the intermediates
/// that link it to a root the client trusts.
pub fn certificate_entries(body: &[u8]) -> Option<Vec<&[u8]>> {
    let mut c = Cursor::new(body);
    vec8(&mut c)?;
    let mut list = Cursor::new(vec24(&mut c)?);
    let mut out = Vec::new();
    while list.remaining() > 0 {
        out.push(vec24(&mut list)?);
        vec16(&mut list)?;
    }
    Some(out)
}

/// A one-line description of a handshake message, plus detail lines (one per
/// extension for the hellos).
fn describe_message(msg: &HandshakeMessage<'_>) -> (String, Vec<String>) {
    let name = handshake_type_name(msg.msg_type);
    let mut c = Cursor::new(msg.body);
    match msg.msg_type {
        HS_CLIENT_HELLO => match ClientHello::parse(msg.body) {
            Some(ch) => {
                let mut lines = vec![format!(
                    "cipher suites: {}",
                    names(&ch.cipher_suites, cipher_suite_name)
                )];
                lines.extend(
                    ch.extensions
                        .iter()
                        .map(|e| describe_extension(e, Where::ClientHello)),
                );
                (ch.to_string(), lines)
            }
            None => (format!("{name} (malformed)"), vec![]),
        },
        HS_SERVER_HELLO => match ServerHello::parse(msg.body) {
            Some(sh) => {
                let place = sh.place();
                let lines = sh
                    .extensions
                    .iter()
                    .map(|e| describe_extension(e, place))
                    .collect();
                (sh.to_string(), lines)
            }
            None => (format!("{name} (malformed)"), vec![]),
        },
        HS_ENCRYPTED_EXTENSIONS => {
            let exts = vec16(&mut c).and_then(parse_extensions).unwrap_or_default();
            let lines: Vec<String> = exts
                .iter()
                .map(|e| describe_extension(e, Where::Other))
                .collect();
            (format!("{name} ({} extensions)", exts.len()), lines)
        }
        HS_CERTIFICATE => match certificate_entries(msg.body) {
            Some(certs) => (format!("{name}: {} certificate(s)", certs.len()), vec![]),
            None => (format!("{name} (malformed)"), vec![]),
        },
        HS_CERTIFICATE_VERIFY => {
            let scheme = c
                .read_u16_be()
                .map(signature_scheme_name)
                .unwrap_or_default();
            let sig = vec16(&mut c).map_or(0, <[u8]>::len);
            (format!("{name} {scheme}, {sig}-byte signature"), vec![])
        }
        HS_FINISHED => (
            format!("{name} (verify_data {} bytes)", msg.body.len()),
            vec![],
        ),
        HS_NEW_SESSION_TICKET => match NewSessionTicket::parse(msg.body) {
            Some(t) => {
                let lines = t
                    .extensions
                    .iter()
                    .map(|e| describe_extension(e, Where::Other))
                    .collect();
                (
                    format!(
                        "{name} lifetime {} s, ticket {} bytes",
                        t.lifetime,
                        t.ticket.len()
                    ),
                    lines,
                )
            }
            None => (format!("{name} (malformed)"), vec![]),
        },
        HS_KEY_UPDATE => {
            let req = match c.read_u8() {
                Some(1) => "update_requested",
                Some(0) => "update_not_requested",
                _ => "?",
            };
            (format!("{name} ({req})"), vec![])
        }
        _ => (format!("{name} ({} bytes)", msg.body.len()), vec![]),
    }
}

// ---------------------------------------------------------------------------
// Keylog (draft-ietf-tls-keylogfile)
// ---------------------------------------------------------------------------

/// Secrets from an `SSLKEYLOGFILE`, indexed by ClientHello random.
///
/// TLS 1.3 lines look like:
///
/// ```text
/// CLIENT_HANDSHAKE_TRAFFIC_SECRET <64 hex: client random> <hex secret>
/// SERVER_HANDSHAKE_TRAFFIC_SECRET …
/// CLIENT_TRAFFIC_SECRET_0 …
/// SERVER_TRAFFIC_SECRET_0 …
/// EXPORTER_SECRET …
/// ```
///
/// TLS 1.2 connections log a single `CLIENT_RANDOM` line (the master secret)
/// instead; osiview reads it but only decrypts TLS 1.3.
#[derive(Debug, Default)]
pub struct KeyLog {
    entries: HashMap<[u8; 32], HashMap<String, Vec<u8>>>,
}

impl KeyLog {
    /// Parses keylog text. Comments (`#`) and lines that don't fit the format are
    /// skipped, since keylog files often collect lines from many programs.
    pub fn parse(text: &str) -> Self {
        let mut log = KeyLog::default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (Some(label), Some(random), Some(secret)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if label.starts_with('#') {
                continue;
            }
            let (Some(random), Some(secret)) = (unhex(random), unhex(secret)) else {
                continue;
            };
            let Ok(random) = <[u8; 32]>::try_from(random) else {
                continue;
            };
            log.entries
                .entry(random)
                .or_default()
                .insert(label.to_string(), secret);
        }
        log
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn secret(&self, client_random: &[u8; 32], label: &str) -> Option<&[u8]> {
        self.entries
            .get(client_random)?
            .get(label)
            .map(Vec::as_slice)
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

// ---------------------------------------------------------------------------
// The session: one connection, both directions
// ---------------------------------------------------------------------------

/// Which keys a direction is using: the session state machine of RFC 8446
/// Appendix A, reduced to what changes the decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Before the hellos are done: records are plaintext.
    Plaintext,
    /// After the ServerHello: handshake traffic keys.
    Handshake,
    /// After this side's Finished: application traffic keys.
    Application,
}

/// A connection's traffic secrets from the keylog. Index 0 is the client's,
/// 1 the server's: each side encrypts with its own secret.
struct SessionKeys {
    suite: CipherSuite,
    /// `CLIENT_/SERVER_HANDSHAKE_TRAFFIC_SECRET`: used from the ServerHello to
    /// that side's Finished.
    handshake: [Vec<u8>; 2],
    /// `CLIENT_/SERVER_TRAFFIC_SECRET_0`: used after that side's Finished.
    application: [Vec<u8>; 2],
}

/// Everything decoded from one TLS connection.
#[derive(Debug, Default)]
pub struct TlsConnection {
    pub client_random: Option<[u8; 32]>,
    pub sni: Option<String>,
    pub alpn_offered: Vec<String>,
    /// From EncryptedExtensions, so only known after decryption.
    pub alpn: Option<String>,
    pub version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub hello_retry: bool,
    /// The ClientHello offered tickets; these are their identities.
    pub psk_identities: Vec<Vec<u8>>,
    /// The ServerHello accepted one: this is a resumed session.
    pub resumed: bool,
    /// Tickets issued in this connection (NewSessionTicket), for linking later
    /// connections that resume from them.
    pub tickets: Vec<Vec<u8>>,
    /// DER certificates from the Certificate message.
    pub certificates: Vec<Vec<u8>>,
    /// What happened in each direction, in order. Index 0: client → server.
    pub events: [Vec<String>; 2],
    /// Decrypted application data per direction (HTTP, usually).
    pub app_data: [Vec<u8>; 2],
    /// `Some(true)` if this side's Finished verified.
    pub finished_ok: [Option<bool>; 2],
    /// True if any records were decrypted.
    pub decrypted: bool,
    /// Why nothing was decrypted, if so.
    pub note: Option<String>,
}

/// Collects consecutive application-data records into one event line, so a
/// 2 MB download is "application data: 140 records, 2,000,000 bytes" rather
/// than 140 lines.
#[derive(Default)]
struct AppDataRun {
    records: usize,
    bytes: usize,
    encrypted: bool,
}

impl AppDataRun {
    fn flush(&mut self, events: &mut Vec<String>) {
        if self.records > 0 {
            let what = if self.encrypted {
                "encrypted application_data"
            } else {
                "application data"
            };
            events.push(format!(
                "{what}: {} record{}, {} bytes",
                self.records,
                if self.records == 1 { "" } else { "s" },
                self.bytes
            ));
        }
        *self = AppDataRun::default();
    }
}

/// Decodes a whole TLS connection from its two reassembled TCP streams.
///
/// It works on complete streams rather than packet by packet, because a
/// record's sequence number (part of its nonce) is its position in the stream:
/// decryption needs every earlier record in that direction.
///
/// Steps:
/// 1. Split both streams into records, and read the plaintext hellos to learn
///    the client random and the cipher suite.
/// 2. Look the client random up in the keylog.
/// 3. Walk the server direction, then the client direction, switching keys as
///    RFC 8446 says: handshake keys after the ServerHello, application keys
///    after that side's Finished, new keys after a KeyUpdate. The server goes
///    first because the client's Finished covers the server's messages.
pub fn analyse(client: &[u8], server: &[u8], keylog: Option<&KeyLog>) -> TlsConnection {
    let mut conn = TlsConnection::default();
    let (client_records, _) = TlsRecord::split(client);
    let (server_records, _) = TlsRecord::split(server);

    // Step 1: the plaintext handshake messages (all type 22 records in TLS 1.3).
    let plain = |records: &[TlsRecord<'_>]| -> Vec<u8> {
        records
            .iter()
            .filter(|r| r.content_type == CT_HANDSHAKE)
            .flat_map(|r| r.fragment.iter().copied())
            .collect()
    };
    let client_plain = plain(&client_records);
    let server_plain = plain(&server_records);
    let (client_msgs, _) = HandshakeMessage::split(&client_plain);
    let (server_msgs, _) = HandshakeMessage::split(&server_plain);

    let client_hello = client_msgs
        .iter()
        .rev()
        .find(|m| m.msg_type == HS_CLIENT_HELLO)
        .and_then(|m| ClientHello::parse(m.body).map(|ch| (*m, ch)));
    let server_hello = server_msgs
        .iter()
        .filter(|m| m.msg_type == HS_SERVER_HELLO)
        .filter_map(|m| ServerHello::parse(m.body).map(|sh| (*m, sh)))
        .inspect(|(_, sh)| conn.hello_retry |= sh.is_hello_retry_request())
        .rfind(|(_, sh)| !sh.is_hello_retry_request());

    if let Some((_, ch)) = &client_hello {
        conn.client_random = Some(ch.random);
        conn.sni = ch.sni();
        conn.alpn_offered = ch.alpn();
        conn.psk_identities = ch.psk_identities().iter().map(|i| i.to_vec()).collect();
    }
    if let Some((_, sh)) = &server_hello {
        conn.version = Some(sh.version());
        conn.cipher_suite = Some(sh.cipher_suite);
        conn.resumed = sh.accepted_psk();
    }

    // Step 2: keys.
    let suite = conn.cipher_suite.and_then(CipherSuite::from_id);
    let tls13 = conn.version == Some(0x0304);
    let secrets = |label: &str| -> Option<Vec<u8>> {
        let log = keylog?;
        log.secret(conn.client_random.as_ref()?, label)
            .map(<[u8]>::to_vec)
    };
    let keys = match (keylog, tls13, suite) {
        (None, _, _) => {
            conn.note = Some("no keylog given (use --keylog)".into());
            None
        }
        (Some(_), false, _) if server_hello.is_some() => {
            conn.note = Some(format!(
                "{} is not TLS 1.3; osiview only decrypts TLS 1.3",
                conn.version.map(version_name).unwrap_or_default()
            ));
            None
        }
        (Some(_), true, Some(suite)) => {
            let found = (
                secrets("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                secrets("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
                secrets("CLIENT_TRAFFIC_SECRET_0"),
                secrets("SERVER_TRAFFIC_SECRET_0"),
            );
            match found {
                (Some(ch), Some(sh), Some(ca), Some(sa)) => Some(SessionKeys {
                    suite,
                    handshake: [ch, sh],
                    application: [ca, sa],
                }),
                _ => {
                    conn.note = Some("this connection's client random is not in the keylog".into());
                    None
                }
            }
        }
        (Some(_), true, None) => {
            conn.note = Some("unknown TLS 1.3 cipher suite".into());
            None
        }
        _ => {
            conn.note = Some("no ServerHello seen".into());
            None
        }
    };

    // The transcript so far (for Finished checks): ClientHello + ServerHello.
    // After a HelloRetryRequest the transcript starts with a synthetic
    // message_hash instead; osiview doesn't rebuild that, so it skips the check.
    let mut transcript: Vec<u8> = Vec::new();
    if let (Some((chm, _)), Some((shm, _))) = (&client_hello, &server_hello) {
        transcript.extend_from_slice(chm.raw);
        transcript.extend_from_slice(shm.raw);
    }
    let check_finished = !conn.hello_retry && !transcript.is_empty();

    // Step 3: server direction, then client.
    for dir in [1usize, 0] {
        let records = if dir == 0 {
            &client_records
        } else {
            &server_records
        };
        walk_direction(
            dir,
            records,
            keys.as_ref(),
            &mut transcript,
            check_finished,
            &mut conn,
        );
    }
    conn
}

/// Walks one direction's records. `dir` is 0 for client → server, 1 for server
/// → client. `transcript` is shared, so the server's messages are in it when
/// the client's Finished is checked.
fn walk_direction(
    dir: usize,
    records: &[TlsRecord<'_>],
    keys: Option<&SessionKeys>,
    transcript: &mut Vec<u8>,
    check_finished: bool,
    conn: &mut TlsConnection,
) {
    let mut events: Vec<String> = Vec::new();
    let mut run = AppDataRun::default();
    let mut phase = Phase::Plaintext;
    let mut protection: Option<RecordProtection> = None;
    let mut failed = false;
    let mut plain_hs = Vec::new();
    let mut enc_hs = Vec::new();

    for rec in records {
        match rec.content_type {
            CT_HANDSHAKE => {
                run.flush(&mut events);
                plain_hs.extend_from_slice(rec.fragment);
                let (msgs, used) = HandshakeMessage::split(&plain_hs);
                for m in &msgs {
                    push_message(&mut events, m);
                }
                let saw_server_hello = msgs.iter().any(|m| {
                    m.msg_type == HS_SERVER_HELLO
                        && ServerHello::parse(m.body).is_some_and(|s| !s.is_hello_retry_request())
                });
                let any = !msgs.is_empty();
                plain_hs.drain(..used);
                // The client moves to handshake keys after its (last) ClientHello;
                // in practice its next encrypted record is its Finished.
                if saw_server_hello || (dir == 0 && any) {
                    phase = Phase::Handshake;
                    protection =
                        keys.and_then(|k| RecordProtection::new(k.suite, &k.handshake[dir]));
                }
            }
            CT_CHANGE_CIPHER_SPEC => {
                run.flush(&mut events);
                events
                    .push("ChangeCipherSpec (middlebox compatibility; ignored in TLS 1.3)".into());
            }
            CT_ALERT => {
                run.flush(&mut events);
                let mut c = Cursor::new(rec.fragment);
                let (Some(level), Some(desc)) = (c.read_u8(), c.read_u8()) else {
                    events.push("Alert (malformed)".into());
                    continue;
                };
                events.push(alert_text(level, desc));
            }
            CT_APPLICATION_DATA => {
                let decrypted = match protection.as_mut() {
                    Some(p) if !failed => p.decrypt(rec.header, rec.fragment),
                    _ => None,
                };
                let Some((inner_type, plaintext)) = decrypted else {
                    if protection.is_some() && !failed {
                        run.flush(&mut events);
                        events.push(format!(
                            "could not decrypt record (phase {phase:?}): wrong key, missing records, or 0-RTT data"
                        ));
                        failed = true;
                    }
                    run.encrypted = true;
                    run.records += 1;
                    run.bytes += rec.fragment.len();
                    continue;
                };
                conn.decrypted = true;
                match inner_type {
                    CT_APPLICATION_DATA => {
                        run.encrypted = false;
                        run.records += 1;
                        run.bytes += plaintext.len();
                        conn.app_data[dir].extend_from_slice(&plaintext);
                    }
                    CT_ALERT => {
                        run.flush(&mut events);
                        let mut c = Cursor::new(&plaintext);
                        if let (Some(l), Some(d)) = (c.read_u8(), c.read_u8()) {
                            events.push(format!("{{{}}}", alert_text(l, d)));
                        }
                    }
                    CT_HANDSHAKE => {
                        run.flush(&mut events);
                        enc_hs.extend_from_slice(&plaintext);
                        let (msgs, used) = HandshakeMessage::split(&enc_hs);
                        let mut switch_to_app = false;
                        let mut key_update = false;
                        for m in &msgs {
                            let mut line = String::new();
                            if m.msg_type == HS_FINISHED && phase == Phase::Handshake {
                                if let (true, Some(k)) = (check_finished, keys) {
                                    let ok =
                                        finished_ok(k.suite, &k.handshake[dir], transcript, m.body);
                                    conn.finished_ok[dir] = Some(ok);
                                    line = if ok {
                                        " - verified".into()
                                    } else {
                                        " - DOES NOT VERIFY".into()
                                    };
                                }
                                switch_to_app = true;
                            }
                            if phase == Phase::Handshake {
                                transcript.extend_from_slice(m.raw);
                            }
                            match m.msg_type {
                                HS_CERTIFICATE => {
                                    if let Some(certs) = certificate_entries(m.body) {
                                        conn.certificates.extend(certs.iter().map(|c| c.to_vec()));
                                    }
                                }
                                HS_ENCRYPTED_EXTENSIONS => {
                                    let mut c = Cursor::new(m.body);
                                    if let Some(exts) = vec16(&mut c).and_then(parse_extensions) {
                                        conn.alpn = exts
                                            .iter()
                                            .find(|e| e.ext_type == 16)
                                            .and_then(|e| alpn_list(e.data))
                                            .and_then(|l| l.into_iter().next());
                                    }
                                }
                                HS_NEW_SESSION_TICKET => {
                                    if let Some(t) = NewSessionTicket::parse(m.body) {
                                        conn.tickets.push(t.ticket.to_vec());
                                    }
                                }
                                HS_KEY_UPDATE => key_update = true,
                                _ => {}
                            }
                            push_message(&mut events, m);
                            if !line.is_empty()
                                && let Some(last) =
                                    events.iter_mut().rev().find(|e| e.starts_with('{'))
                            {
                                last.push_str(&line);
                            }
                        }
                        enc_hs.drain(..used);
                        if switch_to_app {
                            phase = Phase::Application;
                            protection = keys
                                .and_then(|k| RecordProtection::new(k.suite, &k.application[dir]));
                        }
                        if key_update && let Some(p) = protection.as_mut() {
                            p.update();
                        }
                    }
                    other => {
                        run.flush(&mut events);
                        events.push(format!("{{record with content type {other}}}"));
                    }
                }
            }
            _ => {}
        }
    }
    run.flush(&mut events);
    conn.events[dir] = events;
}

/// Adds a handshake message (and its detail lines, indented) to the events.
/// Messages after the hellos are only visible decrypted, so they're shown in
/// `{}` as in RFC 8446's diagrams.
fn push_message(events: &mut Vec<String>, m: &HandshakeMessage<'_>) {
    let (line, details) = describe_message(m);
    if matches!(m.msg_type, HS_CLIENT_HELLO | HS_SERVER_HELLO) {
        events.push(line);
    } else {
        events.push(format!("{{{line}}}"));
    }
    for d in details {
        events.push(format!("    {d}"));
    }
}

impl TlsConnection {
    /// One line: version, suite, SNI, ALPN, and full or resumed.
    pub fn headline(&self) -> String {
        let mut parts = Vec::new();
        if let Some(v) = self.version {
            parts.push(version_name(v));
        }
        if let Some(s) = self.cipher_suite {
            parts.push(cipher_suite_name(s));
        }
        if let Some(sni) = &self.sni {
            parts.push(format!("sni {sni}"));
        }
        match &self.alpn {
            Some(a) => parts.push(format!("alpn {a}")),
            None if !self.alpn_offered.is_empty() => {
                parts.push(format!("alpn offered {}", self.alpn_offered.join(", ")))
            }
            None => {}
        }
        if self.hello_retry {
            parts.push("after HelloRetryRequest".into());
        }
        parts.push(if self.resumed {
            "resumed session".into()
        } else {
            "full handshake".into()
        });
        parts.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Per-segment view
// ---------------------------------------------------------------------------

/// The session layer as an [`Operate`] layer. Per segment it can only show the
/// records that *start* in that segment; complete decoding (and decryption)
/// needs the reassembled stream, via [`analyse`].
pub struct Level5;

impl Level5 {
    /// Records in a TCP payload that starts with a record header: field rows for
    /// each record header, and the hello messages decoded.
    pub(crate) fn render_fields(&self, payload: &[u8]) -> String {
        let mut out = String::new();
        let mut rest = payload;
        loop {
            let mut c = Cursor::new(rest);
            let (Some(t), Some(v), Some(len)) = (c.read_u8(), c.read_u16_be(), c.read_u16_be())
            else {
                break;
            };
            let available = c.remaining();
            let _ = writeln!(
                out,
                "tls record {} ({t}), {}, {len} bytes{}",
                content_type_name(t),
                version_name(v),
                if available < usize::from(len) {
                    " (continues in later segments)"
                } else {
                    ""
                }
            );
            let mut h = Cursor::new(rest);
            if let (Some(a), Some(b), Some(d)) = (h.read_bytes(1), h.read_bytes(2), h.read_bytes(2))
            {
                field(&mut out, "  ", "type", a, content_type_name(t));
                field(&mut out, "  ", "version", b, version_name(v));
                field(&mut out, "  ", "length", d, len);
            }
            match TlsRecord::parse(rest) {
                Some((rec, after)) => {
                    if rec.content_type == CT_HANDSHAKE {
                        let (msgs, _) = HandshakeMessage::split(rec.fragment);
                        for m in &msgs {
                            let (line, details) = describe_message(m);
                            let _ = writeln!(out, "  {line}");
                            for d in details {
                                let _ = writeln!(out, "    {d}");
                            }
                        }
                    } else if rec.content_type == CT_APPLICATION_DATA {
                        let _ =
                            writeln!(out, "  (encrypted; decrypt with `osiview follow --keylog`)");
                    }
                    rest = after;
                    if !looks_like_tls(rest) {
                        break;
                    }
                }
                None => break,
            }
        }
        out
    }

    /// The stacked-view line for a TCP payload that starts with TLS records.
    pub(crate) fn layer(&self, payload: &[u8]) -> LayerLine {
        let s = self.summary(payload);
        LayerLine::new(5, "tls", s.strip_prefix("tls ").unwrap_or(&s))
    }

    /// One line for the records that start in this payload.
    pub(crate) fn summary(&self, payload: &[u8]) -> String {
        let mut parts = Vec::new();
        let mut rest = payload;
        while looks_like_tls(rest) {
            match TlsRecord::parse(rest) {
                Some((rec, after)) => {
                    let mut desc = content_type_name(rec.content_type).to_string();
                    if rec.content_type == CT_HANDSHAKE {
                        let (msgs, _) = HandshakeMessage::split(rec.fragment);
                        let names: Vec<String> =
                            msgs.iter().map(|m| describe_message(m).0).collect();
                        if !names.is_empty() {
                            desc = names.join(", ");
                        }
                    }
                    parts.push(format!("{desc} ({} B)", rec.fragment.len()));
                    rest = after;
                }
                None => {
                    let mut c = Cursor::new(rest);
                    let t = c.read_u8().unwrap_or(0);
                    c.read_u16_be();
                    let len = c.read_u16_be().unwrap_or(0);
                    parts.push(format!("{} ({len} B, continues)", content_type_name(t)));
                    break;
                }
            }
        }
        format!("tls {}", parts.join(", "))
    }
}

impl Operate for Level5 {
    fn render(&self, data: &[u8]) -> String {
        let mut out = self.render_fields(data);
        let _ = write!(out, "{}", HexDump(data));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_vectors::*;

    fn rfc8448_streams() -> (Vec<u8>, Vec<u8>) {
        let client = [
            CLIENT_HELLO_RECORD,
            CLIENT_FINISHED_RECORD,
            CLIENT_APP_RECORD,
            CLIENT_ALERT_RECORD,
        ]
        .iter()
        .flat_map(|r| hex(r))
        .collect();
        let server = [
            SERVER_HELLO_RECORD,
            SERVER_HS_RECORD,
            SERVER_TICKET_RECORD,
            SERVER_APP_RECORD,
            SERVER_ALERT_RECORD,
        ]
        .iter()
        .flat_map(|r| hex(r))
        .collect();
        (client, server)
    }

    fn rfc8448_keylog() -> KeyLog {
        let ch = hex(CLIENT_HELLO_RECORD);
        let random: String = ch[11..43].iter().map(|b| format!("{b:02x}")).collect();
        KeyLog::parse(&format!(
            "# a comment\n\
             CLIENT_HANDSHAKE_TRAFFIC_SECRET {random} {CLIENT_HS_SECRET}\n\
             SERVER_HANDSHAKE_TRAFFIC_SECRET {random} {SERVER_HS_SECRET}\n\
             CLIENT_TRAFFIC_SECRET_0 {random} {CLIENT_AP_SECRET}\n\
             SERVER_TRAFFIC_SECRET_0 {random} {SERVER_AP_SECRET}\n\
             garbage line\n"
        ))
    }

    #[test]
    fn parses_rfc8448_hellos() {
        let ch_rec = hex(CLIENT_HELLO_RECORD);
        let (rec, rest) = TlsRecord::parse(&ch_rec).unwrap();
        assert!(rest.is_empty());
        assert_eq!(rec.content_type, CT_HANDSHAKE);
        let (msgs, _) = HandshakeMessage::split(rec.fragment);
        let ch = ClientHello::parse(msgs[0].body).unwrap();
        assert_eq!(ch.sni().as_deref(), Some("server"));
        assert!(ch.cipher_suites.contains(&0x1301));

        let sh_rec = hex(SERVER_HELLO_RECORD);
        let (rec, _) = TlsRecord::parse(&sh_rec).unwrap();
        let (msgs, _) = HandshakeMessage::split(rec.fragment);
        let sh = ServerHello::parse(msgs[0].body).unwrap();
        assert_eq!(sh.version(), 0x0304);
        assert_eq!(sh.cipher_suite, 0x1301);
        assert!(!sh.is_hello_retry_request());
        assert_eq!(
            sh.to_string(),
            "ServerHello TLS 1.3, TLS_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn decrypts_the_whole_rfc8448_connection() {
        let (client, server) = rfc8448_streams();
        let keylog = rfc8448_keylog();
        assert_eq!(keylog.len(), 1);
        let conn = analyse(&client, &server, Some(&keylog));

        assert!(conn.decrypted, "{:?}", conn.note);
        assert_eq!(conn.cipher_suite, Some(0x1301));
        assert_eq!(conn.sni.as_deref(), Some("server"));
        assert_eq!(
            conn.finished_ok,
            [Some(true), Some(true)],
            "{:#?}",
            conn.events
        );
        assert_eq!(conn.certificates.len(), 1);
        assert_eq!(conn.tickets.len(), 1);
        assert_eq!(conn.app_data[0], hex(APP_PAYLOAD));
        assert_eq!(conn.app_data[1], hex(APP_PAYLOAD));
        assert!(!conn.resumed);

        let server_events = conn.events[1].join("\n");
        for expected in [
            "ServerHello TLS 1.3",
            "{EncryptedExtensions",
            "{Certificate: 1 certificate(s)}",
            "{CertificateVerify rsa_pss_rsae_sha256, 128-byte signature}",
            "{Finished (verify_data 32 bytes)} - verified",
            "{NewSessionTicket lifetime 30 s",
            "application data: 1 record, 50 bytes",
            "{Alert warning close_notify (0)}",
        ] {
            assert!(
                server_events.contains(expected),
                "missing {expected:?} in\n{server_events}"
            );
        }
        assert!(
            conn.events[0]
                .iter()
                .any(|e| e == "{Finished (verify_data 32 bytes)} - verified")
        );
    }

    #[test]
    fn without_keys_only_the_hellos_are_visible() {
        let (client, server) = rfc8448_streams();
        let conn = analyse(&client, &server, None);
        assert!(!conn.decrypted);
        assert_eq!(conn.note.as_deref(), Some("no keylog given (use --keylog)"));
        assert!(
            conn.events[1]
                .iter()
                .any(|e| e.starts_with("encrypted application_data: 4 records"))
        );

        let other = KeyLog::parse(
            "CLIENT_TRAFFIC_SECRET_0 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 00",
        );
        let conn = analyse(&client, &server, Some(&other));
        assert!(conn.note.unwrap().contains("not in the keylog"));
    }

    #[test]
    fn hello_retry_request_detection() {
        let sh_rec = hex(SERVER_HELLO_RECORD);
        let (rec, _) = TlsRecord::parse(&sh_rec).unwrap();
        let mut body = HandshakeMessage::split(rec.fragment).0[0].body.to_vec();
        body[2..34].copy_from_slice(&Sha256::digest(b"HelloRetryRequest"));
        assert!(ServerHello::parse(&body).unwrap().is_hello_retry_request());
    }

    #[test]
    fn records_split_and_tls_detection() {
        let ch = hex(CLIENT_HELLO_RECORD);
        assert!(looks_like_tls(&ch));
        assert!(!looks_like_tls(b"GET / HTTP/1.1"));
        let (recs, rest) = TlsRecord::split(&ch[..100]);
        assert!(recs.is_empty());
        assert_eq!(rest.len(), 100);
        assert!(Level5.summary(&ch[..100]).contains("continues"));
        assert!(
            Level5
                .summary(&ch)
                .starts_with("tls ClientHello sni server")
        );
    }

    #[test]
    fn grease_values() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0a1a));
        assert!(!is_grease(0x1301));
    }
}
