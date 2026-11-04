//! Layer 7 (application): DNS (RFC 1035) and HTTP/1.1 (RFC 9112).
//!
//! These are the two plaintext protocols, and they're built very differently:
//!
//! - **DNS** is binary. A message is a fixed 12-byte header and four sections
//!   of records, and names are compressed with pointers back into the message.
//!   It usually travels in one UDP datagram, so it can be decoded per packet.
//! - **HTTP/1.1** is text: a start line, header lines, a blank line, then a
//!   body. One message can span many TCP segments, and one segment can hold the
//!   end of one message and the start of the next. So there are two views:
//!   - per segment ([`HttpSegment`]): if a segment *starts* a message, show its
//!     start line and whatever headers it carries;
//!   - per stream ([`parse_http_stream`]): from the reassembled TCP stream
//!     ([`crate::flow`]), split out every message and decode its body framing.
//!     `osiview follow` uses this.
//!
//! For HTTPS, layers 5 and 6 (TLS) sit between layer 4 and this module.
//!
//! # Specs
//!
//! - DNS message format: RFC 1035 §4.1, name compression §4.1.4, record types
//!   §3.2. AAAA: RFC 3596. EDNS(0) OPT: RFC 6891 §6. DNS over TCP: RFC 7766
//!   (each message gets a 2-byte length prefix).
//! - HTTP/1.1 message syntax: RFC 9112 §2–5. Body length: RFC 9112 §6.3.
//!   Chunked encoding: RFC 9112 §7.1.

use std::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::base_level::Operate;
use crate::cursor::{Cursor, HexDump};
use crate::display::LayerLine;
use crate::level2::field;

// ---------------------------------------------------------------------------
// Which application protocol
// ---------------------------------------------------------------------------

/// Which decoder to use for a transport payload. Ports pick it for DNS; HTTP is
/// recognised by its first bytes instead, so it works on any port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppProtocol {
    /// DNS over UDP (port 53) or multicast DNS (port 5353, RFC 6762).
    Dns,
    /// DNS over TCP (port 53): each message has a 2-byte length prefix.
    DnsOverTcp,
    /// Any other TCP payload: decoded as HTTP/1.1 if it starts like HTTP.
    MaybeHttp,
    /// Nothing osiview decodes.
    Unknown,
}

/// The application layer.
pub struct Level7 {
    pub app: AppProtocol,
}

impl Level7 {
    /// The decoder for a UDP datagram between these ports.
    pub fn for_udp(src_port: u16, dst_port: u16) -> Self {
        let dns = [53, 5353].iter().any(|p| *p == src_port || *p == dst_port);
        Level7 {
            app: if dns {
                AppProtocol::Dns
            } else {
                AppProtocol::Unknown
            },
        }
    }

    /// The decoder for a TCP segment between these ports.
    pub fn for_tcp(src_port: u16, dst_port: u16) -> Self {
        let app = if src_port == 53 || dst_port == 53 {
            AppProtocol::DnsOverTcp
        } else {
            AppProtocol::MaybeHttp
        };
        Level7 { app }
    }

    /// The DNS message in a payload, with the TCP length prefix removed if
    /// needed. Over TCP, a segment that doesn't hold a whole message gives `None`.
    fn dns<'a>(&self, payload: &'a [u8]) -> Option<DnsMessage<'a>> {
        match self.app {
            AppProtocol::Dns => DnsMessage::parse(payload),
            AppProtocol::DnsOverTcp => {
                let mut c = Cursor::new(payload);
                let len = usize::from(c.read_u16_be()?);
                DnsMessage::parse(c.read_bytes(len)?)
            }
            _ => None,
        }
    }

    /// Summary and field table, or `None` if this payload isn't something
    /// osiview decodes (layer 4 then just prints its size).
    pub(crate) fn render_fields(&self, payload: &[u8]) -> Option<String> {
        let mut out = String::new();
        if let Some(dns) = self.dns(payload) {
            let _ = writeln!(out, "{dns}");
            dns.write_fields(&mut out, "  ");
            return Some(out);
        }
        if self.app == AppProtocol::MaybeHttp
            && let Some(http) = HttpSegment::parse(payload)
        {
            let _ = writeln!(out, "{http}");
            http.write_lines(&mut out, "  ");
            return Some(out);
        }
        None
    }

    /// The stacked-view line for this payload, if it's DNS or the start of an
    /// HTTP message.
    pub(crate) fn layer(&self, payload: &[u8]) -> Option<LayerLine> {
        if let Some(dns) = self.dns(payload) {
            let s = dns.to_string();
            return Some(LayerLine::new(
                7,
                "dns",
                s.strip_prefix("dns ").unwrap_or(&s),
            ));
        }
        if self.app == AppProtocol::MaybeHttp {
            let h = HttpSegment::parse(payload)?;
            let s = h.to_string();
            return Some(LayerLine::new(
                7,
                "http",
                s.strip_prefix("http ").unwrap_or(&s),
            ));
        }
        None
    }

    /// One-line summary, or `None` if this payload isn't decoded.
    pub(crate) fn summary(&self, payload: &[u8]) -> Option<String> {
        if let Some(dns) = self.dns(payload) {
            return Some(dns.to_string());
        }
        if self.app == AppProtocol::MaybeHttp {
            return HttpSegment::parse(payload).map(|h| h.to_string());
        }
        None
    }
}

impl Operate for Level7 {
    /// Decodes an application payload, or just hexdumps it if it isn't recognised.
    fn render(&self, data: &[u8]) -> String {
        let mut out = self
            .render_fields(data)
            .unwrap_or_else(|| format!("{} bytes, not decoded\n", data.len()));
        let _ = write!(out, "{}", HexDump(data));
        out
    }
}

// ---------------------------------------------------------------------------
// DNS (RFC 1035)
// ---------------------------------------------------------------------------

/// Record type: A, IPv4 address.
pub const DNS_A: u16 = 1;
/// Record type: NS, name server.
pub const DNS_NS: u16 = 2;
/// Record type: CNAME, "this name is an alias for that one".
pub const DNS_CNAME: u16 = 5;
/// Record type: SOA, start of authority (zone metadata; seen in negative answers).
pub const DNS_SOA: u16 = 6;
/// Record type: PTR, reverse lookup (address → name).
pub const DNS_PTR: u16 = 12;
/// Record type: MX, mail exchanger.
pub const DNS_MX: u16 = 15;
/// Record type: TXT, free-form strings.
pub const DNS_TXT: u16 = 16;
/// Record type: AAAA, IPv6 address (RFC 3596).
pub const DNS_AAAA: u16 = 28;
/// Record type: SRV, service location (RFC 2782).
pub const DNS_SRV: u16 = 33;
/// Pseudo-record type: OPT, EDNS(0) (RFC 6891). Only in the additional section;
/// it carries the sender's UDP size limit and extra flags, not data.
pub const DNS_OPT: u16 = 41;
/// Record type: HTTPS (RFC 9460), service parameters such as ALPN for a web host.
pub const DNS_HTTPS: u16 = 65;

/// A record type's name, for printing.
pub fn dns_type_name(t: u16) -> String {
    match t {
        DNS_A => "A".into(),
        DNS_NS => "NS".into(),
        DNS_CNAME => "CNAME".into(),
        DNS_SOA => "SOA".into(),
        DNS_PTR => "PTR".into(),
        DNS_MX => "MX".into(),
        DNS_TXT => "TXT".into(),
        DNS_AAAA => "AAAA".into(),
        DNS_SRV => "SRV".into(),
        DNS_OPT => "OPT".into(),
        64 => "SVCB".into(),
        DNS_HTTPS => "HTTPS".into(),
        255 => "ANY".into(),
        // RFC 3597's notation for types without a name.
        _ => format!("TYPE{t}"),
    }
}

/// A response code's name (the low 4 bits of the flags).
pub fn dns_rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "rcode?",
    }
}

/// The most compression pointers a name may follow. A real name has at most
/// 127 labels, so this is generous; it stops pointer loops such as a pointer
/// to itself.
const MAX_NAME_JUMPS: usize = 64;

/// Reads a (possibly compressed) domain name starting at byte `start` of the
/// whole message `msg`. Returns the name in dotted form and the offset just past
/// it *where it started* (a pointer is 2 bytes there, however long the name
/// it points to).
///
/// A name is a run of labels, each a length byte (1–63) and that many bytes,
/// ending with a zero length (the root). A length byte with the top two bits
/// set (`0b11xxxxxx`) is instead a 14-bit pointer to an earlier offset in the
/// message where the rest of the name is (RFC 1035 §4.1.4):
///
/// ```text
/// offset 12:  07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00    example.com
/// offset 40:  03 'w' 'w' 'w' c0 0c                                www + pointer to 12
/// ```
///
/// Loop guard: every pointer must point *backwards* (to before the label it's
/// in), and at most [`MAX_NAME_JUMPS`] are followed. Either rule alone stops a
/// hostile message from looping forever.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_after_first: Option<usize> = None;
    let mut jumps = 0;
    let mut total_len = 0usize;

    loop {
        let mut c = Cursor::new(msg);
        c.read_bytes(pos)?;
        let len = c.read_u8()?;
        match len >> 6 {
            0b00 => {
                if len == 0 {
                    let end = end_after_first.unwrap_or(pos + 1);
                    let name = if labels.is_empty() {
                        ".".to_string()
                    } else {
                        labels.join(".")
                    };
                    return Some((name, end));
                }
                let label = c.read_bytes(usize::from(len))?;
                total_len += label.len() + 1;
                if total_len > 255 {
                    return None; // RFC 1035 §2.3.4: names are at most 255 bytes
                }
                labels.push(escape_label(label));
                pos += 1 + label.len();
            }
            0b11 => {
                let low = c.read_u8()?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if target >= pos || jumps >= MAX_NAME_JUMPS {
                    return None;
                }
                jumps += 1;
                end_after_first.get_or_insert(pos + 2);
                pos = target;
            }
            // 0b01 and 0b10 are reserved (EDNS once proposed extended labels).
            _ => return None,
        }
    }
}

/// A label as text. Labels are bytes, not text: printable ASCII is shown as is,
/// and anything else (and `.` itself, which would be ambiguous) as `\DDD`, the
/// zone-file escape.
fn escape_label(label: &[u8]) -> String {
    let mut s = String::new();
    for &b in label {
        if b.is_ascii_graphic() && b != b'.' && b != b'\\' {
            s.push(b as char);
        } else {
            let _ = write!(s, "\\{b:03}");
        }
    }
    s
}

/// One question: "what are the records of this type for this name?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    /// Almost always 1 (IN, Internet). mDNS uses the top bit as "unicast reply wanted".
    pub qclass: u16,
}

/// A record's data, decoded for the common types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, NS and PTR all hold one name.
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        minimum: u32,
    },
    /// EDNS(0). For OPT, the record's class field is the UDP payload size and
    /// its TTL holds the extended rcode, version and flags (bit 15 = DO, "I want
    /// DNSSEC records").
    Opt {
        udp_size: u16,
        dnssec_ok: bool,
    },
    /// Anything else: shown as a length.
    Other,
}

/// One resource record from the answer, authority or additional section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    /// Seconds the answer may be cached for.
    pub ttl: u32,
    /// Length of the raw record data.
    pub rdlength: u16,
    pub data: RData,
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let RData::Opt {
            udp_size,
            dnssec_ok,
        } = &self.data
        {
            write!(f, "OPT (EDNS) udp size {udp_size}")?;
            if *dnssec_ok {
                f.write_str(", DO")?;
            }
            return Ok(());
        }
        write!(
            f,
            "{} {} ttl {}s ",
            self.name,
            dns_type_name(self.rtype),
            self.ttl
        )?;
        match &self.data {
            RData::A(a) => write!(f, "{a}"),
            RData::Aaaa(a) => write!(f, "{a}"),
            RData::Name(n) => write!(f, "{n}"),
            RData::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            RData::Txt(parts) => {
                let quoted: Vec<String> = parts.iter().map(|p| format!("{p:?}")).collect();
                write!(f, "{}", quoted.join(" "))
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {target}"),
            RData::Soa {
                mname,
                rname,
                serial,
                minimum,
            } => write!(f, "{mname} {rname} serial {serial} min {minimum}s"),
            RData::Opt { .. } => Ok(()),
            RData::Other => write!(f, "({} bytes)", self.rdlength),
        }
    }
}

/// A DNS message: query or response.
///
/// ```text
/// +---------------------+
/// | header (12 bytes)   |  id, flags, and the four section counts
/// +---------------------+
/// | question            |  what's being asked
/// +---------------------+
/// | answer              |  records answering it
/// +---------------------+
/// | authority           |  name servers (or an SOA for "no such name")
/// +---------------------+
/// | additional          |  extra records, including EDNS OPT
/// +---------------------+
/// ```
///
/// Header flags (RFC 1035 §4.1.1):
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+-----------+--+--+--+--+--------+-----------+
/// |QR|  Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+-----------+--+--+--+--+--------+-----------+
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct DnsMessage<'a> {
    /// Chosen by the client; the response copies it so the client can match
    /// them. A resolver should pick it at random, or spoofed answers are easy.
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
    /// The whole message, for the header rows of the field table.
    pub raw: &'a [u8],
}

impl<'a> DnsMessage<'a> {
    /// Parses a message. Returns `None` if anything is malformed: a section count
    /// that runs past the end, a bad name, or record data that's too short.
    pub fn parse(msg: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(msg);
        let id = c.read_u16_be()?;
        let flags = c.read_u16_be()?;
        let counts = [
            c.read_u16_be()?,
            c.read_u16_be()?,
            c.read_u16_be()?,
            c.read_u16_be()?,
        ];
        let mut pos = 12;

        let mut questions = Vec::new();
        for _ in 0..counts[0] {
            let (name, end) = read_name(msg, pos)?;
            let mut q = Cursor::new(msg);
            q.read_bytes(end)?;
            questions.push(DnsQuestion {
                name,
                qtype: q.read_u16_be()?,
                qclass: q.read_u16_be()?,
            });
            pos = end + 4;
        }

        let mut sections: [Vec<DnsRecord>; 3] = Default::default();
        for (i, section) in sections.iter_mut().enumerate() {
            for _ in 0..counts[i + 1] {
                let (record, end) = parse_record(msg, pos)?;
                section.push(record);
                pos = end;
            }
        }
        let [answers, authority, additional] = sections;
        Some(DnsMessage {
            id,
            flags,
            questions,
            answers,
            authority,
            additional,
            raw: msg,
        })
    }

    /// QR bit: false for a query, true for a response.
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// 0 = standard query. 4 = NOTIFY and 5 = UPDATE also exist.
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    /// The flags as text: `response, recursion desired, recursion available, NOERROR`.
    fn flags_text(&self) -> String {
        let mut parts = vec![
            if self.is_response() {
                "response"
            } else {
                "query"
            }
            .to_string(),
        ];
        if self.opcode() != 0 {
            parts.push(format!("opcode {}", self.opcode()));
        }
        for (bit, name) in [
            (0x0400, "authoritative"),
            (0x0200, "truncated"),
            (0x0100, "recursion desired"),
            (0x0080, "recursion available"),
            (0x0020, "authentic data"),
            (0x0010, "checking disabled"),
        ] {
            if self.flags & bit != 0 {
                parts.push(name.to_string());
            }
        }
        if self.is_response() {
            parts.push(dns_rcode_name(self.rcode()).to_string());
        }
        parts.join(", ")
    }

    /// The 12-byte header as field rows, then one line per question and record.
    /// Records get a line each rather than a hex row, because their bytes are
    /// often mostly compression pointers and say little on their own.
    fn write_fields(&self, out: &mut String, ind: &str) -> Option<()> {
        let mut c = Cursor::new(self.raw);
        field(
            out,
            ind,
            "id",
            c.read_bytes(2)?,
            format_args!("0x{:04x}", self.id),
        );
        field(out, ind, "flags", c.read_bytes(2)?, self.flags_text());
        field(out, ind, "qdcount", c.read_bytes(2)?, self.questions.len());
        field(out, ind, "ancount", c.read_bytes(2)?, self.answers.len());
        field(out, ind, "nscount", c.read_bytes(2)?, self.authority.len());
        field(out, ind, "arcount", c.read_bytes(2)?, self.additional.len());
        for q in &self.questions {
            let _ = writeln!(
                out,
                "{ind}{:<8} {} {}",
                "question",
                q.name,
                dns_type_name(q.qtype)
            );
        }
        for (label, records) in [
            ("answer", &self.answers),
            ("auth", &self.authority),
            ("extra", &self.additional),
        ] {
            for r in records {
                let _ = writeln!(out, "{ind}{label:<8} {r}");
            }
        }
        Some(())
    }
}

/// Parses one resource record at `pos`. Returns it and the offset after it.
///
/// ```text
/// name | type (2) | class (2) | ttl (4) | rdlength (2) | rdata (rdlength)
/// ```
fn parse_record(msg: &[u8], pos: usize) -> Option<(DnsRecord, usize)> {
    let (name, name_end) = read_name(msg, pos)?;
    let mut c = Cursor::new(msg);
    c.read_bytes(name_end)?;
    let rtype = c.read_u16_be()?;
    let class = c.read_u16_be()?;
    let ttl = c.read_u32_be()?;
    let rdlength = c.read_u16_be()?;
    let rdata_start = name_end + 10;
    let rdata = c.read_bytes(usize::from(rdlength))?;
    let end = rdata_start + rdata.len();

    // Names inside rdata can point anywhere earlier in the message, so they're
    // read from `msg` at the rdata's offset, not from `rdata` alone.
    let mut r = Cursor::new(rdata);
    let data = match rtype {
        DNS_A => RData::A(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?)),
        DNS_AAAA => RData::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?)),
        DNS_CNAME | DNS_NS | DNS_PTR => RData::Name(read_name(msg, rdata_start)?.0),
        DNS_MX => RData::Mx {
            preference: r.read_u16_be()?,
            exchange: read_name(msg, rdata_start + 2)?.0,
        },
        DNS_TXT => {
            // One or more <length byte><text> strings.
            let mut parts = Vec::new();
            while r.remaining() > 0 {
                let len = usize::from(r.read_u8()?);
                parts.push(String::from_utf8_lossy(r.read_bytes(len)?).into_owned());
            }
            RData::Txt(parts)
        }
        DNS_SRV => RData::Srv {
            priority: r.read_u16_be()?,
            weight: r.read_u16_be()?,
            port: r.read_u16_be()?,
            target: read_name(msg, rdata_start + 6)?.0,
        },
        DNS_SOA => {
            let (mname, m_end) = read_name(msg, rdata_start)?;
            let (rname, r_end) = read_name(msg, m_end)?;
            let mut s = Cursor::new(msg);
            s.read_bytes(r_end)?;
            let serial = s.read_u32_be()?;
            s.read_bytes(12)?; // refresh, retry, expire
            RData::Soa {
                mname,
                rname,
                serial,
                minimum: s.read_u32_be()?,
            }
        }
        DNS_OPT => RData::Opt {
            udp_size: class,
            dnssec_ok: ttl & 0x0000_8000 != 0,
        },
        _ => RData::Other,
    };
    Some((
        DnsRecord {
            name,
            rtype,
            class,
            ttl,
            rdlength,
            data,
        },
        end,
    ))
}

/// tcpdump-style: `dns query 0x1a2b A example.com` or
/// `dns response 0x1a2b NOERROR A example.com: 93.184.216.34`.
impl fmt::Display for DnsMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_response() {
            "response"
        } else {
            "query"
        };
        write!(f, "dns {kind} 0x{:04x}", self.id)?;
        if self.is_response() {
            write!(f, " {}", dns_rcode_name(self.rcode()))?;
        }
        if let Some(q) = self.questions.first() {
            write!(f, " {} {}", dns_type_name(q.qtype), q.name)?;
        }
        if self.is_response() && !self.answers.is_empty() {
            let answers: Vec<String> = self
                .answers
                .iter()
                .map(|r| match &r.data {
                    RData::A(a) => a.to_string(),
                    RData::Aaaa(a) => a.to_string(),
                    RData::Name(n) => format!("{} {n}", dns_type_name(r.rtype)),
                    _ => dns_type_name(r.rtype),
                })
                .collect();
            write!(f, ": {}", answers.join(", "))?;
        }
        Ok(())
    }
}

/// Builds a DNS query for `name` (RFC 1035 §4.1): a 12-byte header with one
/// question and "recursion desired" set, so the resolver does the full lookup.
/// No compression is needed with a single name. Returns `None` for names that
/// can't be encoded (an empty label, a label over 63 bytes, or over 253 total).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question, no records
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| (1..=63).contains(l))?;
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    Some(q)
}

// ---------------------------------------------------------------------------
// HTTP/1.1 (RFC 9112): one segment
// ---------------------------------------------------------------------------

/// Methods recognised at the start of a request (RFC 9110 §9, plus PATCH).
const HTTP_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// True if `data` starts like an HTTP/1.x request or status line.
pub fn looks_like_http(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP/1.") {
        return true;
    }
    HTTP_METHODS
        .iter()
        .any(|m| data.starts_with(m.as_bytes()) && data.get(m.len()) == Some(&b' '))
}

/// The start of an HTTP message, as seen in one TCP segment: the start line and
/// the header lines that fit. The body, and headers that spill into later
/// segments, need the reassembled stream; see [`parse_http_stream`].
#[derive(Debug, PartialEq, Eq)]
pub struct HttpSegment {
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    /// True if the blank line ending the headers is in this segment.
    pub headers_complete: bool,
    /// Bytes after the headers in this segment (the start of the body).
    pub body_bytes: usize,
}

impl HttpSegment {
    /// Returns `None` unless the segment starts with an HTTP start line.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !looks_like_http(data) {
            return None;
        }
        let mut r = LineReader::new(data);
        let start_line = text(r.line()?);
        let mut headers = Vec::new();
        let mut headers_complete = false;
        while let Some(line) = r.line() {
            if line.is_empty() {
                headers_complete = true;
                break;
            }
            if let Some(h) = parse_header(line) {
                headers.push(h);
            }
        }
        Some(HttpSegment {
            start_line,
            headers,
            headers_complete,
            body_bytes: if headers_complete { r.rest().len() } else { 0 },
        })
    }

    fn write_lines(&self, out: &mut String, ind: &str) {
        let _ = writeln!(out, "{ind}{:<8} {}", "start", self.start_line);
        for (name, value) in &self.headers {
            let _ = writeln!(out, "{ind}{:<8} {name}: {value}", "header");
        }
        if !self.headers_complete {
            let _ = writeln!(out, "{ind}(headers continue in the next segment)");
        } else if self.body_bytes > 0 {
            let _ = writeln!(
                out,
                "{ind}{:<8} ({} bytes in this segment)",
                "body", self.body_bytes
            );
        }
    }
}

/// `http GET /index.html HTTP/1.1, host example.com` or
/// `http HTTP/1.1 200 OK, 1256 bytes`.
impl fmt::Display for HttpSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http {}", self.start_line)?;
        if let Some(host) = header_value(&self.headers, "host") {
            write!(f, ", host {host}")?;
        }
        if let Some(len) = header_value(&self.headers, "content-length") {
            write!(f, ", {len} bytes")?;
        } else if header_value(&self.headers, "transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            f.write_str(", chunked")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 (RFC 9112): whole stream
// ---------------------------------------------------------------------------

/// How the end of a message body is found (RFC 9112 §6.3). Getting this right is
/// the whole difficulty of HTTP/1.1 framing: there's no length prefix on a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body: a request without Content-Length or Transfer-Encoding, or a
    /// 1xx, 204 or 304 response.
    None,
    /// `Content-Length: n`.
    Length(usize),
    /// `Transfer-Encoding: chunked`: a series of `<hex size>\r\n<data>\r\n` chunks
    /// ending with a zero-size chunk. Used when the sender doesn't know the
    /// length in advance.
    Chunked,
    /// A response with neither: the body runs until the server closes the
    /// connection.
    UntilClose,
}

/// One HTTP message from a reassembled stream.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpMessage {
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    pub framing: BodyFraming,
    /// The body with chunked encoding removed. Content-Encoding (gzip) is not
    /// undone here; that's layer 6.
    pub body: Vec<u8>,
    /// False if the stream ended before the message did.
    pub complete: bool,
}

impl HttpMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

/// Splits a reassembled stream into HTTP messages: several requests on one
/// keep-alive connection come out as several messages.
///
/// `responses` says which direction this is. It matters because the body rules
/// differ: a request with no length has no body, but a response with no length
/// runs until the connection closes.
///
/// One known gap: a response to a HEAD request has headers saying how long the
/// body *would* be, but no body. Telling that apart needs the request stream too.
pub fn parse_http_stream(stream: &[u8], responses: bool) -> Vec<HttpMessage> {
    let mut messages = Vec::new();
    let mut r = LineReader::new(stream);
    while !r.rest().is_empty() {
        // Stray blank lines between messages are allowed (RFC 9112 §2.2).
        if r.rest().starts_with(b"\r\n") || r.rest().starts_with(b"\n") {
            r.line();
            continue;
        }
        if !looks_like_http(r.rest()) {
            break;
        }
        let Some(start) = r.line() else { break };
        let start_line = text(start);
        let mut headers = Vec::new();
        let mut headers_done = false;
        while let Some(line) = r.line() {
            if line.is_empty() {
                headers_done = true;
                break;
            }
            if let Some(h) = parse_header(line) {
                headers.push(h);
            }
        }
        let framing = body_framing(&start_line, &headers, responses);
        if !headers_done {
            messages.push(HttpMessage {
                start_line,
                headers,
                framing,
                body: Vec::new(),
                complete: false,
            });
            break;
        }
        let (body, complete) = match framing {
            BodyFraming::None => (Vec::new(), true),
            BodyFraming::Length(n) => {
                let body = r.take(n);
                let complete = body.len() == n;
                (body.to_vec(), complete)
            }
            BodyFraming::Chunked => read_chunked(&mut r),
            BodyFraming::UntilClose => (r.take(usize::MAX).to_vec(), true),
        };
        messages.push(HttpMessage {
            start_line,
            headers,
            framing,
            body,
            complete,
        });
        if !complete {
            break;
        }
    }
    messages
}

/// RFC 9112 §6.3, in the order that matters for the common cases.
fn body_framing(start_line: &str, headers: &[(String, String)], response: bool) -> BodyFraming {
    if response {
        let status: u16 = start_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if (100..200).contains(&status) || status == 204 || status == 304 {
            return BodyFraming::None;
        }
    }
    // Transfer-Encoding wins over Content-Length; a message with both is
    // suspicious (request smuggling), but chunked is what a server would use.
    if header_value(headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().trim_end().ends_with("chunked"))
    {
        return BodyFraming::Chunked;
    }
    if let Some(n) = header_value(headers, "content-length").and_then(|v| v.trim().parse().ok()) {
        return BodyFraming::Length(n);
    }
    if response {
        BodyFraming::UntilClose
    } else {
        BodyFraming::None
    }
}

/// Decodes a chunked body (RFC 9112 §7.1):
///
/// ```text
/// 1a\r\n                      chunk size in hex (may have ";extensions")
/// abcdefghijklmnopqrstuvwxyz\r\n
/// 0\r\n                       last chunk
/// \r\n                        end of trailer fields
/// ```
fn read_chunked(r: &mut LineReader<'_>) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let Some(size_line) = r.line() else {
            return (body, false);
        };
        let size_text = text(size_line);
        let hex = size_text.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(hex, 16) else {
            return (body, false);
        };
        if size == 0 {
            // Trailer fields, then a blank line.
            while let Some(line) = r.line() {
                if line.is_empty() {
                    return (body, true);
                }
            }
            return (body, false);
        }
        let chunk = r.take(size);
        body.extend_from_slice(chunk);
        if chunk.len() < size {
            return (body, false);
        }
        r.line(); // the CRLF after the chunk data
    }
}

/// `Name: value` → (name, value) with surrounding whitespace trimmed. Lines
/// without a colon are ignored.
fn parse_header(line: &[u8]) -> Option<(String, String)> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = text(line.get(..colon)?);
    let value = text(line.get(colon + 1..)?);
    Some((name.trim().to_string(), value.trim().to_string()))
}

/// Header lookup. Header names are case-insensitive (RFC 9110 §5.1).
fn header_value<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Bytes as text. HTTP field values are meant to be ASCII; anything else is
/// replaced rather than rejected.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Reads lines and fixed-size blocks from a byte slice. Like `Cursor`, every
/// access is bounds-checked, so a hostile stream can't cause a panic.
struct LineReader<'a> {
    data: &'a [u8],
}

impl<'a> LineReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        LineReader { data }
    }

    fn rest(&self) -> &'a [u8] {
        self.data
    }

    /// The next line without its `\n` (and `\r`, if present). Returns `None` if
    /// there's no complete line left. RFC 9112 §2.2 lets a recipient accept a
    /// bare LF as a line ending, so this does.
    fn line(&mut self) -> Option<&'a [u8]> {
        let nl = self.data.iter().position(|&b| b == b'\n')?;
        let line = self.data.get(..nl)?;
        self.data = self.data.get(nl + 1..).unwrap_or(&[]);
        Some(line.strip_suffix(b"\r").unwrap_or(line))
    }

    /// Up to `n` bytes.
    fn take(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.data.len());
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        head
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A DNS response for example.com A, as a resolver would send it: the answer
    /// name is a pointer (c0 0c) back to the question.
    pub(crate) fn dns_response() -> Vec<u8> {
        let mut m = vec![
            0x1a, 0x2b, // id
            0x81, 0x80, // response, rd, ra, NOERROR
            0, 1, 0, 2, 0, 0, 0, 1, // 1 question, 2 answers, 0 authority, 1 additional
        ];
        m.extend_from_slice(b"\x07example\x03com\x00");
        m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        // answer 1: example.com (pointer to offset 12) A, ttl 3600, 93.184.216.34
        m.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34,
        ]);
        // answer 2: example.com CNAME www.example.com (www + pointer)
        m.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend_from_slice(&[3, b'w', b'w', b'w', 0xc0, 0x0c]);
        // additional: OPT, udp size 1232, DO
        m.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        m
    }

    #[test]
    fn decodes_dns_response_with_compression() {
        let data = dns_response();
        let msg = DnsMessage::parse(&data).unwrap();
        assert_eq!(msg.id, 0x1a2b);
        assert!(msg.is_response());
        assert_eq!(msg.rcode(), 0);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(
            msg.answers[0].data,
            RData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(msg.answers[0].ttl, 3600);
        assert_eq!(msg.answers[1].data, RData::Name("www.example.com".into()));
        assert_eq!(
            msg.additional[0].data,
            RData::Opt {
                udp_size: 1232,
                dnssec_ok: true
            }
        );
        assert_eq!(
            msg.to_string(),
            "dns response 0x1a2b NOERROR A example.com: 93.184.216.34, CNAME www.example.com"
        );
    }

    #[test]
    fn dns_query() {
        let mut m = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(b"\x03www\x06google\x03com\x00\x00\x1c\x00\x01");
        let msg = DnsMessage::parse(&m).unwrap();
        assert_eq!(msg.to_string(), "dns query 0xabcd AAAA www.google.com");
        let out = Level7::for_udp(40000, 53).render_fields(&m).unwrap();
        assert!(out.contains("recursion desired"));
        assert!(out.contains("question www.google.com AAAA"));
    }

    #[test]
    fn dns_pointer_loops_are_rejected() {
        // A name that is a pointer to itself.
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(DnsMessage::parse(&m), None);
        // Two names pointing at each other: the forward pointer is refused.
        assert_eq!(read_name(&[0xc0, 2, 0xc0, 0], 0), None);
        // A pointer past the end.
        assert_eq!(read_name(&[0xc0, 0xff], 0), None);
    }

    #[test]
    fn dns_truncated_or_lying_counts_are_none() {
        let data = dns_response();
        assert_eq!(DnsMessage::parse(&data[..11]), None);
        assert_eq!(DnsMessage::parse(&data[..40]), None);
        let mut more = data.clone();
        more[7] = 9; // claims 9 answers
        assert_eq!(DnsMessage::parse(&more), None);
    }

    #[test]
    fn dns_over_tcp_strips_length_prefix() {
        let msg = dns_response();
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        let summary = Level7::for_tcp(53, 40000).summary(&framed).unwrap();
        assert!(summary.starts_with("dns response 0x1a2b"));
    }

    #[test]
    fn built_query_parses_back() {
        let q = build_query(0x4242, "example.com.", DNS_A).unwrap();
        let msg = DnsMessage::parse(&q).unwrap();
        assert_eq!(msg.to_string(), "dns query 0x4242 A example.com");
        assert!(build_query(1, "a..b", DNS_A).is_none());
        assert!(build_query(1, &"x".repeat(64), DNS_A).is_none());
    }

    #[test]
    fn label_bytes_are_escaped() {
        assert_eq!(escape_label(b"a.b"), "a\\046b");
        assert_eq!(escape_label(&[0x00, b'x']), "\\000x");
    }

    #[test]
    fn http_request_segment() {
        let seg = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let h = HttpSegment::parse(seg).unwrap();
        assert_eq!(h.start_line, "GET /index.html HTTP/1.1");
        assert!(h.headers_complete);
        assert_eq!(
            h.to_string(),
            "http GET /index.html HTTP/1.1, host example.com"
        );
        assert_eq!(HttpSegment::parse(b"GETX / HTTP/1.1\r\n"), None);
        assert_eq!(HttpSegment::parse(b"\x16\x03\x01"), None); // a TLS record
    }

    #[test]
    fn http_response_split_across_segments() {
        let first = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Le";
        let h = HttpSegment::parse(first).unwrap();
        assert!(!h.headers_complete);
        assert_eq!(h.headers.len(), 1);
    }

    #[test]
    fn stream_with_keep_alive_requests() {
        let stream = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n\
                       POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello\
                       GET /c HTTP/1.1\r\nHost: x\r\n\r\n";
        let msgs = parse_http_stream(stream, false);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[1].start_line, "POST /b HTTP/1.1");
        assert_eq!(msgs[1].body, b"hello");
        assert!(msgs.iter().all(|m| m.complete));
    }

    #[test]
    fn chunked_response() {
        let stream = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                       5\r\nhello\r\n7;ext=1\r\n, world\r\n0\r\nX-Trailer: y\r\n\r\n\
                       HTTP/1.1 204 No Content\r\n\r\n";
        let msgs = parse_http_stream(stream, true);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].framing, BodyFraming::Chunked);
        assert_eq!(msgs[0].body, b"hello, world");
        assert!(msgs[0].complete);
        assert_eq!(msgs[1].framing, BodyFraming::None);
    }

    #[test]
    fn incomplete_and_until_close_bodies() {
        let msgs = parse_http_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", true);
        assert_eq!(msgs[0].body, b"abc");
        assert!(!msgs[0].complete);

        let msgs = parse_http_stream(b"HTTP/1.0 200 OK\r\n\r\nall of it", true);
        assert_eq!(msgs[0].framing, BodyFraming::UntilClose);
        assert_eq!(msgs[0].body, b"all of it");

        // Garbage chunk size stops cleanly.
        let msgs = parse_http_stream(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            true,
        );
        assert!(!msgs[0].complete);
    }
}
