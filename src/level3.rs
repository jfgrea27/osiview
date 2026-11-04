//! Layer 3 (network): IPv4 (RFC 791), IPv6 (RFC 8200) and ICMP (RFC 792 for v4,
//! RFC 4443 for v6), including IPv6 Neighbor Discovery (RFC 4861), which does
//! the job ARP does for IPv4.
//!
//! # How the pieces fit
//!
//! ```text
//! Ethernet payload (EtherType 0x0800 / 0x86dd)
//!   │
//!   ├─ version nibble 4 ─► Ipv4Header::parse ─► protocol 1 ─► Icmp (V4)
//!   │                                         └ other ──────► layer 4 (TCP, UDP, …)
//!   │
//!   └─ version nibble 6 ─► Ipv6Header::parse ─► extension headers ─► protocol 58 ─► Icmp (V6)
//!                                                                  └ other ───────► layer 4
//! ```
//!
//! The IP version comes from the first 4 bits of the packet, not from the
//! EtherType, so `Level3` can decode an IP packet from anywhere: an Ethernet
//! payload, a pcap file, or the original packet quoted inside an ICMP error.
//!
//! ICMP is a separate protocol carried inside IP, but it's part of the network
//! layer: it reports IP's errors (unreachable, TTL exceeded) and, for IPv6, does
//! address resolution. That's why it lives here and not in layer 4.
//!
//! # Specs
//!
//! - IPv4 header: RFC 791 §3.1. Fragmentation: RFC 791 §3.2.
//! - Internet checksum: RFC 1071.
//! - IPv6 header and extension headers: RFC 8200 §3–4. Upper-layer checksums
//!   with the IPv6 pseudo-header: RFC 8200 §8.1.
//! - IPv6 address text form: RFC 5952.
//! - ICMPv4: RFC 792. ICMPv6: RFC 4443. Neighbor Discovery: RFC 4861 §4.
//! - Protocol numbers: the IANA "Assigned Internet Protocol Numbers" registry.

use std::fmt;
use std::fmt::Write as _;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::base_level::Operate;
use crate::cursor::{Cursor, HexDump};
use crate::display::{LayerLine, TcpRel};
use crate::level2::{MacAddr, field};
use crate::level4::Level4;

// ---------------------------------------------------------------------------
// Protocol numbers
// ---------------------------------------------------------------------------

// The 8-bit "protocol" (IPv4) or "next header" (IPv6) field says what comes
// next. IPv4 and IPv6 share one number space, which is why IPv6 extension
// headers have numbers in it too.

/// IPv6 Hop-by-Hop Options extension header (RFC 8200 §4.3).
pub const PROTO_HOPOPT: u8 = 0;
/// ICMP for IPv4 (RFC 792).
pub const PROTO_ICMP: u8 = 1;
/// TCP (RFC 9293). Decoded at layer 4.
pub const PROTO_TCP: u8 = 6;
/// UDP (RFC 768). Decoded at layer 4.
pub const PROTO_UDP: u8 = 17;
/// IPv6 Routing extension header (RFC 8200 §4.4).
pub const PROTO_IPV6_ROUTE: u8 = 43;
/// IPv6 Fragment extension header (RFC 8200 §4.5).
pub const PROTO_IPV6_FRAG: u8 = 44;
/// IPsec Encapsulating Security Payload (RFC 4303). Everything after it is
/// encrypted, so the extension-header walk has to stop there.
pub const PROTO_ESP: u8 = 50;
/// IPsec Authentication Header (RFC 4302). Unlike the others, its length is in
/// 4-byte units.
pub const PROTO_AH: u8 = 51;
/// ICMP for IPv6 (RFC 4443).
pub const PROTO_ICMPV6: u8 = 58;
/// "No Next Header": nothing follows (RFC 8200 §4.7).
pub const PROTO_IPV6_NONXT: u8 = 59;
/// IPv6 Destination Options extension header (RFC 8200 §4.6).
pub const PROTO_IPV6_OPTS: u8 = 60;

/// Returns a short name for an IP protocol number, for printing.
pub fn protocol_name(p: u8) -> &'static str {
    match p {
        PROTO_HOPOPT => "hop-by-hop",
        PROTO_ICMP => "ICMP",
        2 => "IGMP",
        PROTO_TCP => "TCP",
        PROTO_UDP => "UDP",
        41 => "IPv6-in-IPv4",
        PROTO_IPV6_ROUTE => "routing",
        PROTO_IPV6_FRAG => "fragment",
        PROTO_ESP => "ESP",
        PROTO_AH => "AH",
        PROTO_ICMPV6 => "ICMPv6",
        PROTO_IPV6_NONXT => "no next header",
        PROTO_IPV6_OPTS => "destination options",
        132 => "SCTP",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Internet checksum (RFC 1071)
// ---------------------------------------------------------------------------

/// The Internet checksum, used by the IPv4 header, ICMP, UDP and TCP.
///
/// The data is treated as a sequence of big-endian 16-bit words. They're added
/// with *one's-complement* addition: any carry out of the top bit is added back
/// in at the bottom ("end-around carry"). The checksum is the bitwise NOT of
/// that sum.
///
/// Two properties make it handy:
/// - **Verifying is the same call.** Run it over a message *including* its
///   checksum field. A correct message gives 0.
/// - **Order doesn't matter**, so the data can come in several pieces. That's why
///   this takes a list of chunks: for ICMPv6, UDP and TCP the sum also covers a
///   "pseudo-header" (addresses, length, protocol) that isn't in the packet. The
///   bytes are paired across chunk boundaries, so a chunk with an odd length is fine.
///
/// An odd total length is padded with a zero byte at the end (RFC 1071 §1).
///
/// The sum is kept in a `u64` and only folded at the end. Each 16-bit word adds
/// less than 2^16, so it can't overflow for any input that fits in memory.
pub fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    let mut high: Option<u8> = None;
    for &b in chunks.iter().flat_map(|c| c.iter()) {
        match high.take() {
            None => high = Some(b),
            Some(h) => sum += u64::from(u16::from_be_bytes([h, b])),
        }
    }
    if let Some(h) = high {
        sum += u64::from(h) << 8;
    }
    // Fold the carries back in until the sum fits in 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Text for a checksum result, as printed everywhere in osiview.
fn ok_text(ok: bool) -> &'static str {
    if ok { "OK" } else { "BAD" }
}

/// Reads a 4-byte slice as an IPv4 address, through `Cursor` so it can't panic.
fn read_ipv4(c: &mut Cursor<'_>) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(c.read_bytes(4)?).ok()?))
}

/// Reads a 16-byte slice as an IPv6 address.
fn read_ipv6(c: &mut Cursor<'_>) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(
        <[u8; 16]>::try_from(c.read_bytes(16)?).ok()?,
    ))
}

/// Decodes a big-endian number from a field's bytes, for the field tables.
/// Returns 0 for slices longer than 4 bytes, which never happens for the fields
/// it's used on.
fn be_value(bytes: &[u8]) -> u32 {
    let mut c = Cursor::new(bytes);
    match bytes.len() {
        1 => c.read_u8().map_or(0, u32::from),
        2 => c.read_u16_be().map_or(0, u32::from),
        4 => c.read_u32_be().unwrap_or(0),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// What layer 4 needs from layer 3
// ---------------------------------------------------------------------------

/// The parts of the IP header that layer 4 needs: the addresses and protocol
/// for the TCP/UDP checksum pseudo-header, and the addresses that, together with
/// the ports, identify a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpContext {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// The upper-layer protocol (after any IPv6 extension headers).
    pub protocol: u8,
}

impl IpContext {
    pub fn is_v4(&self) -> bool {
        self.src.is_ipv4()
    }

    /// The pseudo-header that TCP and UDP checksums cover, for an upper-layer
    /// message of `upper_len` bytes.
    ///
    /// IPv4 (RFC 9293 §3.1, 12 bytes):
    /// `source (4) | destination (4) | zero (1) | protocol (1) | length (2)`.
    /// IPv6: see [`ipv6_pseudo_header`] (40 bytes).
    pub fn pseudo_header(&self, upper_len: usize) -> Vec<u8> {
        match (self.src, self.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.push(0);
                p.push(self.protocol);
                p.extend_from_slice(&(upper_len as u16).to_be_bytes());
                p
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                ipv6_pseudo_header(s, d, upper_len as u32, self.protocol).to_vec()
            }
            // Mixed families can't come from one packet.
            _ => Vec::new(),
        }
    }
}

/// The transport payload of an IP packet and its context, for code that works
/// above layer 3 (the flow table). Returns `None` for fragments, truncated
/// packets and anything that isn't IPv4 or IPv6.
pub fn transport(data: &[u8]) -> Option<(IpContext, &[u8])> {
    match Cursor::new(data).read_u8()? >> 4 {
        4 => {
            let ip = Ipv4Header::parse(data)?;
            if ip.is_fragment() || ip.truncated {
                return None;
            }
            Some((ip.context(), ip.payload))
        }
        6 => {
            let ip = Ipv6Header::parse(data)?;
            if ip.fragment().is_some() || ip.truncated {
                return None;
            }
            Some((ip.context(), ip.payload))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// IPv4 (RFC 791)
// ---------------------------------------------------------------------------

/// An IPv4 header and its payload.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |   DSCP    |ECN|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options (0–40 bytes)                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The header is 20–60 bytes: IHL counts 32-bit words, from 5 (no options) to
/// 15. The packet's end comes from Total Length, not from the buffer: an
/// Ethernet frame may add padding after a short packet, and `payload` excludes it.
///
/// Like the layer 2 types, this borrows from the input buffer instead of copying.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Header<'a> {
    /// Internet Header Length, in 32-bit words (5–15). Header bytes = `ihl * 4`.
    pub ihl: u8,
    /// Differentiated Services Code Point (RFC 2474), 6 bits: a traffic class
    /// for QoS. 0 is best effort; 46 (EF) is typical for voice. This byte used to
    /// be called Type of Service.
    pub dscp: u8,
    /// Explicit Congestion Notification (RFC 3168), 2 bits. Routers can set it
    /// to 3 instead of dropping the packet when they're congested.
    pub ecn: u8,
    /// Length of the whole packet, header included, in bytes. At most 65535.
    pub total_length: u16,
    /// Identification: the same for every fragment of one original packet, so
    /// the receiver knows which fragments to put back together.
    pub identification: u16,
    /// Reserved flag bit (bit 0). Must be 0. RFC 3514 jokingly calls it the
    /// "evil bit".
    pub reserved_flag: bool,
    /// Don't Fragment. Routers must drop the packet rather than fragment it, and
    /// send back ICMP "fragmentation needed". Path MTU discovery depends on this,
    /// so most modern traffic sets DF.
    pub dont_fragment: bool,
    /// More Fragments: set on every fragment except the last.
    pub more_fragments: bool,
    /// Where this fragment's data goes in the original packet, in 8-byte units
    /// (13 bits). 0 for unfragmented packets and the first fragment.
    pub fragment_offset: u16,
    /// Time to Live: decremented by each router. When it reaches 0 the packet is
    /// dropped and an ICMP Time Exceeded is sent back, which is how traceroute
    /// works. Starting values hint at the OS: 64 for Linux and macOS, 128 for
    /// Windows.
    pub ttl: u8,
    /// What the payload is. See [`protocol_name`].
    pub protocol: u8,
    /// Header checksum, covering the header only (not the payload). Routers
    /// recompute it at every hop because the TTL changes.
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Raw options, if IHL > 5. Rare today; Record Route and Timestamp are examples.
    pub options: &'a [u8],
    /// The whole header (`ihl * 4` bytes), kept for checksum verification and
    /// for printing the field table.
    pub header: &'a [u8],
    /// The payload, from the end of the header to Total Length, excluding any
    /// link-layer padding.
    pub payload: &'a [u8],
    /// True if the buffer ended before Total Length. A live capture shouldn't
    /// do this, but the original packet quoted inside an ICMP error always does:
    /// only its header and first 8 payload bytes are included.
    pub truncated: bool,
}

impl<'a> Ipv4Header<'a> {
    /// Parses an IPv4 packet. Returns `None` if it isn't version 4, IHL is below
    /// 5, the buffer is shorter than the header, or Total Length is smaller than
    /// the header. A short *payload* is allowed and sets `truncated`.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let first = Cursor::new(data).read_u8()?;
        if first >> 4 != 4 {
            return None;
        }
        let ihl = first & 0x0f;
        if ihl < 5 {
            return None;
        }
        let header_len = usize::from(ihl) * 4;

        let mut c = Cursor::new(data);
        let header = c.read_bytes(header_len)?;

        let mut h = Cursor::new(header);
        h.read_u8()?; // version + IHL, already decoded
        let tos = h.read_u8()?;
        let total_length = h.read_u16_be()?;
        let identification = h.read_u16_be()?;
        let flags_frag = h.read_u16_be()?;
        let ttl = h.read_u8()?;
        let protocol = h.read_u8()?;
        let checksum = h.read_u16_be()?;
        let src = read_ipv4(&mut h)?;
        let dst = read_ipv4(&mut h)?;
        let options = h.read_bytes(h.remaining())?;

        let total = usize::from(total_length);
        if total < header_len {
            return None;
        }
        let wanted = total - header_len;
        let available = c.remaining();
        let payload = c.read_bytes(wanted.min(available))?;

        Some(Ipv4Header {
            ihl,
            dscp: tos >> 2,
            ecn: tos & 0x03,
            total_length,
            identification,
            reserved_flag: flags_frag & 0x8000 != 0,
            dont_fragment: flags_frag & 0x4000 != 0,
            more_fragments: flags_frag & 0x2000 != 0,
            fragment_offset: flags_frag & 0x1fff,
            ttl,
            protocol,
            checksum,
            src,
            dst,
            options,
            header,
            payload,
            truncated: available < wanted,
        })
    }

    /// The addresses and protocol, for layer 4.
    pub fn context(&self) -> IpContext {
        IpContext {
            src: IpAddr::V4(self.src),
            dst: IpAddr::V4(self.dst),
            protocol: self.protocol,
        }
    }

    /// True if the header checksum is correct: the checksum over the whole
    /// header, checksum field included, comes out as 0.
    pub fn checksum_ok(&self) -> bool {
        internet_checksum(&[self.header]) == 0
    }

    /// True if this packet is one piece of a larger one. Its payload then isn't a
    /// complete upper-layer message (and for later fragments, it doesn't even
    /// start with the upper-layer header), so it isn't decoded further.
    /// Reassembly is optional: most traffic is never fragmented.
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }

    /// The ICMP message in the payload and whether its checksum is correct, if
    /// this is a complete ICMP packet.
    pub fn icmp(&self) -> Option<(Icmp<'a>, bool)> {
        if self.protocol != PROTO_ICMP || self.is_fragment() {
            return None;
        }
        let icmp = Icmp::parse(IcmpVersion::V4, self.payload)?;
        // ICMPv4 has no pseudo-header: the checksum covers the message only.
        let ok = !self.truncated && icmp.verify_checksum(&[]);
        Some((icmp, ok))
    }

    /// The flags and fragment offset as text, for the field table.
    fn flags_text(&self) -> String {
        let mut parts = Vec::new();
        if self.reserved_flag {
            parts.push("reserved bit set".to_string());
        }
        if self.dont_fragment {
            parts.push("DF".to_string());
        }
        if self.more_fragments {
            parts.push("MF".to_string());
        }
        parts.push(format!("offset {}", u32::from(self.fragment_offset) * 8));
        parts.join(", ")
    }

    /// Writes one row per header field, like the layer 2 tables. Walks `header`
    /// with a `Cursor`, so it can't panic. Bit-packed bytes (version/IHL, DSCP/ECN,
    /// flags/offset) get one row each, with the decoded parts as the meaning.
    fn write_fields(&self, out: &mut String, ind: &str) -> Option<()> {
        let mut c = Cursor::new(self.header);
        field(
            out,
            ind,
            "ver/ihl",
            c.read_bytes(1)?,
            format_args!("version 4, header {} bytes", usize::from(self.ihl) * 4),
        );
        field(
            out,
            ind,
            "tos",
            c.read_bytes(1)?,
            format_args!("dscp {}, ecn {}", self.dscp, self.ecn),
        );
        field(
            out,
            ind,
            "length",
            c.read_bytes(2)?,
            format_args!("{} bytes total", self.total_length),
        );
        field(
            out,
            ind,
            "id",
            c.read_bytes(2)?,
            format_args!("{}", self.identification),
        );
        field(out, ind, "flags", c.read_bytes(2)?, self.flags_text());
        field(out, ind, "ttl", c.read_bytes(1)?, self.ttl);
        field(
            out,
            ind,
            "proto",
            c.read_bytes(1)?,
            protocol_name(self.protocol),
        );
        field(
            out,
            ind,
            "checksum",
            c.read_bytes(2)?,
            ok_text(self.checksum_ok()),
        );
        field(out, ind, "src", c.read_bytes(4)?, self.src);
        field(out, ind, "dst", c.read_bytes(4)?, self.dst);
        if !self.options.is_empty() {
            let _ = writeln!(out, "{ind}{:<8} ({} bytes)", "options", self.options.len());
        }
        Some(())
    }
}

/// One-line summary:
/// `ipv4 10.0.0.1 > 10.0.0.2, ICMP (1), ttl 64, id 0x1c46, length 84, DF`.
/// The checksum result isn't included; the renderer adds it.
impl fmt::Display for Ipv4Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ipv4 {} > {}, {} ({}), ttl {}, id 0x{:04x}, length {}",
            self.src,
            self.dst,
            protocol_name(self.protocol),
            self.protocol,
            self.ttl,
            self.identification,
            self.total_length
        )?;
        if self.dont_fragment {
            f.write_str(", DF")?;
        }
        if self.is_fragment() {
            write!(
                f,
                ", fragment offset {}{}",
                u32::from(self.fragment_offset) * 8,
                if self.more_fragments { " MF" } else { "" }
            )?;
        }
        if self.truncated {
            f.write_str(", truncated")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IPv6 (RFC 8200)
// ---------------------------------------------------------------------------

/// An IPv6 Fragment extension header (RFC 8200 §4.5). Unlike IPv4, routers never
/// fragment IPv6 packets; only the sender can, and it says so with this header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    /// Where this fragment's data goes, in 8-byte units.
    pub offset: u16,
    /// More fragments follow.
    pub more: bool,
    /// Identification shared by all fragments of the original packet. 32 bits,
    /// twice IPv4's.
    pub id: u32,
}

/// One IPv6 extension header. Each one starts with a Next Header byte, so they
/// form a chain from the fixed header to the upper-layer protocol:
///
/// ```text
/// fixed header      hop-by-hop        fragment          ICMPv6
/// next = 0   ─────► next = 44  ─────► next = 58  ─────► message
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ExtHeader<'a> {
    /// Which extension header this is (its protocol number, e.g. 0, 43, 44, 60).
    pub kind: u8,
    /// What comes after it.
    pub next_header: u8,
    /// The whole extension header, Next Header byte included.
    pub raw: &'a [u8],
    /// The decoded fields, for a Fragment header.
    pub fragment: Option<Ipv6Fragment>,
}

impl<'a> ExtHeader<'a> {
    /// Parses one extension header of type `kind` at the start of `data`.
    /// Returns the header and the bytes after it, or `None` if `kind` isn't an
    /// extension header osiview can walk past, or the header is cut short.
    ///
    /// The length rules differ by type:
    /// - Hop-by-Hop, Routing, Destination Options: byte 1 is the length in 8-byte
    ///   units, *not counting the first 8*. So `(len + 1) * 8`.
    /// - Fragment: always 8 bytes.
    /// - AH: byte 1 is the length in 4-byte units, minus 2. So `(len + 2) * 4`.
    /// - ESP: the rest is encrypted, so the walk can't continue.
    fn parse(kind: u8, data: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let mut peek = Cursor::new(data);
        let next_header = peek.read_u8()?;
        let len_byte = usize::from(peek.read_u8()?);
        let len = match kind {
            PROTO_HOPOPT | PROTO_IPV6_ROUTE | PROTO_IPV6_OPTS => (len_byte + 1) * 8,
            PROTO_IPV6_FRAG => 8,
            PROTO_AH => (len_byte + 2) * 4,
            _ => return None,
        };

        let mut c = Cursor::new(data);
        let raw = c.read_bytes(len)?;
        let rest = c.read_bytes(c.remaining())?;

        let fragment = if kind == PROTO_IPV6_FRAG {
            // `peek` is past Next Header and the reserved byte. Then 13 bits of
            // offset, 2 reserved bits, the M flag, and a 32-bit identification.
            let off_flags = peek.read_u16_be()?;
            Some(Ipv6Fragment {
                offset: off_flags >> 3,
                more: off_flags & 1 != 0,
                id: peek.read_u32_be()?,
            })
        } else {
            None
        };

        Some((
            ExtHeader {
                kind,
                next_header,
                raw,
                fragment,
            },
            rest,
        ))
    }

    /// The meaning column for this header's row in the field table.
    fn describe(&self) -> String {
        let next = protocol_name(self.next_header);
        match self.fragment {
            Some(f) => format!(
                "fragment offset {}{}, id 0x{:08x}, next {next}",
                u32::from(f.offset) * 8,
                if f.more { " MF" } else { "" },
                f.id
            ),
            None => format!(
                "{}, {} bytes, next {next}",
                protocol_name(self.kind),
                self.raw.len()
            ),
        }
    }
}

/// An IPv6 header, its extension-header chain, and the upper-layer payload.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Traffic Class |              Flow Label               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Source Address (128 bits)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Destination Address (128 bits)               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Compared with IPv4, the header is a fixed 40 bytes and has no checksum
/// (layer 2 and layer 4 already check) and no fragmentation fields. Anything
/// optional moved into extension headers, which are walked to find the real
/// upper-layer protocol.
///
/// Addresses print in RFC 5952 form (`fe80::1`, lowercase, the longest run of
/// zero groups replaced by `::`), using `Ipv6Addr`'s `Display` from `std`.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv6Header<'a> {
    /// Same job as IPv4's DSCP + ECN byte.
    pub traffic_class: u8,
    /// 20 bits. Lets the sender label packets of one flow so routers can keep
    /// them on one path. Often 0, or a hash of the connection's addresses and ports.
    pub flow_label: u32,
    /// Bytes after the fixed 40-byte header, extension headers included. Unlike
    /// IPv4's Total Length, it doesn't count the header itself.
    pub payload_length: u16,
    /// The first Next Header: either an extension header or the upper layer.
    pub next_header: u8,
    /// IPv6's TTL, renamed because it always counted hops, not seconds.
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// The fixed 40-byte header, for the field table.
    pub fixed: &'a [u8],
    /// Extension headers, in order.
    pub ext: Vec<ExtHeader<'a>>,
    /// The protocol of `payload`, found at the end of the extension-header chain.
    pub upper_protocol: u8,
    /// Everything after the last extension header, up to Payload Length.
    pub payload: &'a [u8],
    /// True if the buffer ended before Payload Length. Expected for packets
    /// quoted inside ICMPv6 errors.
    pub truncated: bool,
}

impl<'a> Ipv6Header<'a> {
    /// Parses an IPv6 packet and walks its extension headers. Returns `None` if
    /// it isn't version 6 or is shorter than 40 bytes.
    ///
    /// The walk stops at the first header that isn't an extension header (the
    /// upper layer), at a truncated extension header, or at a Fragment header with
    /// a non-zero offset, because later fragments don't contain the upper-layer
    /// header. Every step consumes at least 8 bytes, so it always ends.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let fixed = c.read_bytes(40)?;

        let mut h = Cursor::new(fixed);
        let first = h.read_u32_be()?;
        if first >> 28 != 6 {
            return None;
        }
        let payload_length = h.read_u16_be()?;
        let next_header = h.read_u8()?;
        let hop_limit = h.read_u8()?;
        let src = read_ipv6(&mut h)?;
        let dst = read_ipv6(&mut h)?;

        let wanted = usize::from(payload_length);
        let available = c.remaining();
        let mut rest = c.read_bytes(wanted.min(available))?;

        let mut ext = Vec::new();
        let mut next = next_header;
        while let Some((hdr, after)) = ExtHeader::parse(next, rest) {
            next = hdr.next_header;
            rest = after;
            let later_fragment = hdr.fragment.is_some_and(|f| f.offset != 0);
            ext.push(hdr);
            if later_fragment {
                break;
            }
        }

        Some(Ipv6Header {
            traffic_class: ((first >> 20) & 0xff) as u8,
            flow_label: first & 0x000f_ffff,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
            fixed,
            ext,
            upper_protocol: next,
            payload: rest,
            truncated: available < wanted,
        })
    }

    /// The addresses and upper-layer protocol, for layer 4.
    pub fn context(&self) -> IpContext {
        IpContext {
            src: IpAddr::V6(self.src),
            dst: IpAddr::V6(self.dst),
            protocol: self.upper_protocol,
        }
    }

    /// The Fragment header's fields, if this packet is a fragment.
    pub fn fragment(&self) -> Option<Ipv6Fragment> {
        self.ext.iter().find_map(|e| e.fragment)
    }

    /// The ICMPv6 message in the payload and whether its checksum is correct, if
    /// this is a complete ICMPv6 packet.
    pub fn icmp(&self) -> Option<(Icmp<'a>, bool)> {
        if self.upper_protocol != PROTO_ICMPV6 || self.fragment().is_some() {
            return None;
        }
        let icmp = Icmp::parse(IcmpVersion::V6, self.payload)?;
        let len = u32::try_from(self.payload.len()).ok()?;
        let pseudo = ipv6_pseudo_header(self.src, self.dst, len, PROTO_ICMPV6);
        let ok = !self.truncated && icmp.verify_checksum(&pseudo);
        Some((icmp, ok))
    }

    /// Writes one row per header field, then one row per extension header.
    fn write_fields(&self, out: &mut String, ind: &str) -> Option<()> {
        let mut c = Cursor::new(self.fixed);
        field(
            out,
            ind,
            "v/tc/fl",
            c.read_bytes(4)?,
            format_args!(
                "version 6, traffic class 0x{:02x}, flow label 0x{:05x}",
                self.traffic_class, self.flow_label
            ),
        );
        field(
            out,
            ind,
            "length",
            c.read_bytes(2)?,
            format_args!("payload {} bytes", self.payload_length),
        );
        field(
            out,
            ind,
            "next",
            c.read_bytes(1)?,
            protocol_name(self.next_header),
        );
        field(out, ind, "hop lim", c.read_bytes(1)?, self.hop_limit);
        field(out, ind, "src", c.read_bytes(16)?, self.src);
        field(out, ind, "dst", c.read_bytes(16)?, self.dst);
        for e in &self.ext {
            field(out, ind, "ext", e.raw, e.describe());
        }
        Some(())
    }
}

/// One-line summary:
/// `ipv6 fe80::1 > ff02::1, ICMPv6 (58), hop limit 255, payload 32 bytes, via hop-by-hop`.
impl fmt::Display for Ipv6Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ipv6 {} > {}, {} ({}), hop limit {}, payload {} bytes",
            self.src,
            self.dst,
            protocol_name(self.upper_protocol),
            self.upper_protocol,
            self.hop_limit,
            self.payload_length
        )?;
        if !self.ext.is_empty() {
            let names: Vec<&str> = self.ext.iter().map(|e| protocol_name(e.kind)).collect();
            write!(f, ", via {}", names.join(" + "))?;
        }
        if self.truncated {
            f.write_str(", truncated")?;
        }
        Ok(())
    }
}

/// Builds the IPv6 pseudo-header that ICMPv6, UDP and TCP include in their
/// checksums (RFC 8200 §8.1):
///
/// ```text
/// source address (16) | destination address (16) | upper-layer length (4) | zero (3) | next header (1)
/// ```
///
/// It isn't sent; both ends build it from the IP header. Including it means a
/// packet delivered to the wrong address fails its checksum. (With a Routing
/// header, the destination should be the *final* one; osiview doesn't handle that.)
pub fn ipv6_pseudo_header(src: Ipv6Addr, dst: Ipv6Addr, upper_len: u32, next: u8) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[0..16].copy_from_slice(&src.octets());
    p[16..32].copy_from_slice(&dst.octets());
    p[32..36].copy_from_slice(&upper_len.to_be_bytes());
    p[39] = next;
    p
}

// ---------------------------------------------------------------------------
// ICMP (RFC 792, RFC 4443) and Neighbor Discovery (RFC 4861)
// ---------------------------------------------------------------------------

/// Which ICMP: they share a header layout but not their type numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpVersion {
    /// ICMP for IPv4, protocol 1.
    V4,
    /// ICMPv6, protocol 58.
    V6,
}

// ICMPv6 Neighbor Discovery message types (RFC 4861 §4).

/// "Are there any routers here?" Sent by hosts when they join a link.
pub const ND_ROUTER_SOLICIT: u8 = 133;
/// A router's answer (also sent periodically): prefixes, MTU, default gateway.
/// It's how SLAAC hosts give themselves addresses.
pub const ND_ROUTER_ADVERT: u8 = 134;
/// IPv6's ARP request: "who has this address?"
pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
/// IPv6's ARP reply: "that address is mine, here's my MAC".
pub const ND_NEIGHBOR_ADVERT: u8 = 136;
/// "Use a better first hop for that destination."
pub const ND_REDIRECT: u8 = 137;

/// An ICMP or ICMPv6 message.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Rest of header (by type)                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Body (by type)                         |
/// ```
///
/// There are two kinds of message:
/// - **Informational:** echo request/reply (ping), and for IPv6, Neighbor
///   Discovery. Echo's "rest of header" is an identifier and sequence number;
///   the body is arbitrary data that the reply copies back.
/// - **Errors:** destination unreachable, time exceeded, and so on. The body
///   quotes the start of the packet that caused the error, so the sender can
///   tell which connection it belongs to. traceroute relies on this.
///
/// The checksum covers the whole message. ICMPv6 also covers the IPv6
/// pseudo-header; ICMPv4 doesn't. See [`Ipv4Header::icmp`] and [`Ipv6Header::icmp`].
#[derive(Debug, PartialEq, Eq)]
pub struct Icmp<'a> {
    pub version: IcmpVersion,
    /// Message type: echo request, time exceeded, …
    pub icmp_type: u8,
    /// Detail within the type, e.g. *which* destination was unreachable.
    pub code: u8,
    pub checksum: u16,
    /// The 4 bytes after the checksum. Their meaning depends on the type: echo
    /// identifier + sequence, an MTU, Neighbor Advertisement flags, or unused.
    pub rest: &'a [u8],
    /// Everything after the first 8 bytes.
    pub body: &'a [u8],
    /// The whole message, for checksum verification and the field table.
    pub raw: &'a [u8],
}

impl<'a> Icmp<'a> {
    /// Parses an ICMP message. Every ICMP type has at least the 8-byte header,
    /// so shorter input gives `None`.
    pub fn parse(version: IcmpVersion, data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let icmp_type = c.read_u8()?;
        let code = c.read_u8()?;
        let checksum = c.read_u16_be()?;
        let rest = c.read_bytes(4)?;
        let body = c.read_bytes(c.remaining())?;
        Some(Icmp {
            version,
            icmp_type,
            code,
            checksum,
            rest,
            body,
            raw: data,
        })
    }

    /// True if the checksum over `pseudo_header` followed by the message is 0.
    /// Pass `&[]` for ICMPv4 and [`ipv6_pseudo_header`] for ICMPv6.
    pub fn verify_checksum(&self, pseudo_header: &[u8]) -> bool {
        internet_checksum(&[pseudo_header, self.raw]) == 0
    }

    fn is_v6(&self) -> bool {
        self.version == IcmpVersion::V6
    }

    /// The type as text.
    pub fn type_name(&self) -> &'static str {
        match (self.version, self.icmp_type) {
            (IcmpVersion::V4, 0) => "echo reply",
            (IcmpVersion::V4, 3) => "destination unreachable",
            (IcmpVersion::V4, 4) => "source quench",
            (IcmpVersion::V4, 5) => "redirect",
            (IcmpVersion::V4, 8) => "echo request",
            (IcmpVersion::V4, 11) => "time exceeded",
            (IcmpVersion::V4, 12) => "parameter problem",
            (IcmpVersion::V4, 13) => "timestamp",
            (IcmpVersion::V4, 14) => "timestamp reply",
            (IcmpVersion::V6, 1) => "destination unreachable",
            (IcmpVersion::V6, 2) => "packet too big",
            (IcmpVersion::V6, 3) => "time exceeded",
            (IcmpVersion::V6, 4) => "parameter problem",
            (IcmpVersion::V6, 128) => "echo request",
            (IcmpVersion::V6, 129) => "echo reply",
            (IcmpVersion::V6, ND_ROUTER_SOLICIT) => "router solicitation",
            (IcmpVersion::V6, ND_ROUTER_ADVERT) => "router advertisement",
            (IcmpVersion::V6, ND_NEIGHBOR_SOLICIT) => "neighbor solicitation",
            (IcmpVersion::V6, ND_NEIGHBOR_ADVERT) => "neighbor advertisement",
            (IcmpVersion::V6, ND_REDIRECT) => "redirect",
            (IcmpVersion::V6, 143) => "multicast listener report v2",
            _ => "unknown",
        }
    }

    /// The code as text, for the types where it matters. Empty otherwise.
    pub fn code_name(&self) -> &'static str {
        match (self.version, self.icmp_type, self.code) {
            (IcmpVersion::V4, 3, 0) => "net unreachable",
            (IcmpVersion::V4, 3, 1) => "host unreachable",
            (IcmpVersion::V4, 3, 2) => "protocol unreachable",
            (IcmpVersion::V4, 3, 3) => "port unreachable",
            (IcmpVersion::V4, 3, 4) => "fragmentation needed and DF set",
            (IcmpVersion::V4, 3, 13) => "administratively prohibited",
            (IcmpVersion::V4, 11, 0) => "TTL exceeded in transit",
            (IcmpVersion::V4, 11, 1) => "fragment reassembly time exceeded",
            (IcmpVersion::V6, 1, 0) => "no route to destination",
            (IcmpVersion::V6, 1, 1) => "administratively prohibited",
            (IcmpVersion::V6, 1, 3) => "address unreachable",
            (IcmpVersion::V6, 1, 4) => "port unreachable",
            (IcmpVersion::V6, 3, 0) => "hop limit exceeded in transit",
            (IcmpVersion::V6, 3, 1) => "fragment reassembly time exceeded",
            _ => "",
        }
    }

    /// True for echo request and reply (ping).
    pub fn is_echo(&self) -> bool {
        matches!(
            (self.version, self.icmp_type),
            (IcmpVersion::V4, 0 | 8) | (IcmpVersion::V6, 128 | 129)
        )
    }

    /// True for error messages, whose body quotes the packet that caused them.
    pub fn quotes_packet(&self) -> bool {
        matches!(
            (self.version, self.icmp_type),
            (IcmpVersion::V4, 3 | 4 | 5 | 11 | 12) | (IcmpVersion::V6, 1..=4)
        )
    }

    /// Echo identifier and sequence number. The identifier tells pings from
    /// different processes apart (Linux uses a per-socket value); the sequence
    /// counts up by 1 per request.
    pub fn echo(&self) -> Option<(u16, u16)> {
        if !self.is_echo() {
            return None;
        }
        let mut c = Cursor::new(self.rest);
        Some((c.read_u16_be()?, c.read_u16_be()?))
    }

    /// True for the five Neighbor Discovery messages.
    fn is_nd(&self) -> bool {
        self.is_v6() && (ND_ROUTER_SOLICIT..=ND_REDIRECT).contains(&self.icmp_type)
    }

    /// The Target Address of a Neighbor Solicitation, Neighbor Advertisement or
    /// Redirect: the first 16 bytes of the body.
    pub fn nd_target(&self) -> Option<Ipv6Addr> {
        if !self.is_v6()
            || !matches!(
                self.icmp_type,
                ND_NEIGHBOR_SOLICIT | ND_NEIGHBOR_ADVERT | ND_REDIRECT
            )
        {
            return None;
        }
        read_ipv6(&mut Cursor::new(self.body))
    }

    /// The Neighbor Discovery options, as `(type, raw option bytes)`. Each option
    /// is type (1 byte), length (1 byte, in 8-byte units, including these 2
    /// bytes), then data. Where they start depends on the message: after 0 body
    /// bytes for RS, 8 for RA (timers), 16 for NS/NA (target), 32 for Redirect.
    ///
    /// RFC 4861 §4.6 says a length of 0 is invalid and the packet must be
    /// discarded; here the walk just stops. That also guarantees it ends.
    pub fn nd_options(&self) -> Vec<(u8, &'a [u8])> {
        let skip = match self.icmp_type {
            ND_ROUTER_ADVERT => 8,
            ND_NEIGHBOR_SOLICIT | ND_NEIGHBOR_ADVERT => 16,
            ND_REDIRECT => 32,
            _ => 0,
        };
        let mut opts = Vec::new();
        if !self.is_nd() {
            return opts;
        }
        let mut c = Cursor::new(self.body);
        let (Some(_), Some(mut rest)) = (c.read_bytes(skip), c.read_bytes(c.remaining())) else {
            return opts;
        };
        while !rest.is_empty() {
            // Peek at type and length with one cursor, then take the whole option
            // with another, so `rest` only advances when the option is complete.
            let mut peek = Cursor::new(rest);
            let (Some(t), Some(len)) = (peek.read_u8(), peek.read_u8()) else {
                break;
            };
            if len == 0 {
                break;
            }
            let mut take = Cursor::new(rest);
            let Some(raw) = take.read_bytes(usize::from(len) * 8) else {
                break;
            };
            opts.push((t, raw));
            rest = take.read_bytes(take.remaining()).unwrap_or(&[]);
        }
        opts
    }

    /// The MAC address in a Source (type 1) or Target (type 2) Link-Layer Address
    /// option. This is the answer an NS/NA exchange is after.
    pub fn nd_link_addr(&self, option_type: u8) -> Option<MacAddr> {
        let (_, raw) = self
            .nd_options()
            .into_iter()
            .find(|(t, _)| *t == option_type)?;
        let mut c = Cursor::new(raw);
        c.read_bytes(2)?;
        Some(MacAddr(c.read_bytes(6)?.try_into().ok()?))
    }

    /// Writes one row per field. The rows after the checksum depend on the
    /// message type, since that's what decides what the bytes mean.
    fn write_fields(&self, out: &mut String, ind: &str, checksum_ok: bool) -> Option<()> {
        let mut c = Cursor::new(self.raw);
        field(
            out,
            ind,
            "type",
            c.read_bytes(1)?,
            format_args!("{} ({})", self.type_name(), self.icmp_type),
        );
        let code_name = self.code_name();
        if code_name.is_empty() {
            field(out, ind, "code", c.read_bytes(1)?, self.code);
        } else {
            field(
                out,
                ind,
                "code",
                c.read_bytes(1)?,
                format_args!("{} ({})", code_name, self.code),
            );
        }
        field(out, ind, "checksum", c.read_bytes(2)?, ok_text(checksum_ok));

        // The 4 "rest of header" bytes.
        let v6 = self.is_v6();
        if self.is_echo() {
            let id = c.read_bytes(2)?;
            field(out, ind, "id", id, format_args!("0x{:04x}", be_value(id)));
            let seq = c.read_bytes(2)?;
            field(out, ind, "seq", seq, be_value(seq));
        } else if v6 && self.icmp_type == ND_NEIGHBOR_ADVERT {
            let b = c.read_bytes(4)?;
            let v = be_value(b);
            let mut flags = Vec::new();
            if v & 0x8000_0000 != 0 {
                flags.push("router");
            }
            if v & 0x4000_0000 != 0 {
                flags.push("solicited");
            }
            if v & 0x2000_0000 != 0 {
                flags.push("override");
            }
            field(out, ind, "flags", b, flags.join(", "));
        } else if v6 && self.icmp_type == ND_ROUTER_ADVERT {
            let hops = c.read_bytes(1)?;
            field(out, ind, "hop lim", hops, be_value(hops));
            let flags = c.read_bytes(1)?;
            let f = be_value(flags);
            field(
                out,
                ind,
                "flags",
                flags,
                format_args!(
                    "managed {}, other {}",
                    u8::from(f & 0x80 != 0),
                    u8::from(f & 0x40 != 0)
                ),
            );
            let life = c.read_bytes(2)?;
            field(
                out,
                ind,
                "lifetime",
                life,
                format_args!("{} s as default router", be_value(life)),
            );
            let reach = c.read_bytes(4)?;
            field(
                out,
                ind,
                "reach",
                reach,
                format_args!("{} ms", be_value(reach)),
            );
            let retrans = c.read_bytes(4)?;
            field(
                out,
                ind,
                "retrans",
                retrans,
                format_args!("{} ms", be_value(retrans)),
            );
        } else if (v6 && self.icmp_type == 2) || (!v6 && self.icmp_type == 3 && self.code == 4) {
            // Packet Too Big (v6) and Fragmentation Needed (v4, RFC 1191) carry
            // the MTU the sender should use. In v4 it's the low 16 bits.
            let b = c.read_bytes(4)?;
            field(
                out,
                ind,
                "mtu",
                b,
                be_value(b) & if v6 { u32::MAX } else { 0xffff },
            );
        } else {
            field(out, ind, "rest", c.read_bytes(4)?, "unused");
        }

        // The body.
        if let Some(target) = self.nd_target() {
            field(out, ind, "target", c.read_bytes(16)?, target);
            if self.icmp_type == ND_REDIRECT {
                let d = c.read_bytes(16)?;
                let dest = read_ipv6(&mut Cursor::new(d))?;
                field(out, ind, "dest", d, dest);
            }
        }
        if self.is_nd() {
            for (t, raw) in self.nd_options() {
                field(out, ind, "option", raw, nd_option_text(t, raw));
            }
        } else if c.remaining() > 0 {
            let label = if self.is_echo() {
                "data"
            } else if self.quotes_packet() {
                "original"
            } else {
                "body"
            };
            let _ = writeln!(out, "{ind}{label:<8} ({} bytes)", c.remaining());
        }
        Some(())
    }
}

/// The meaning column for one Neighbor Discovery option.
fn nd_option_text(t: u8, raw: &[u8]) -> String {
    let mut c = Cursor::new(raw);
    let _ = c.read_bytes(2);
    match t {
        1 | 2 => {
            let which = if t == 1 { "source" } else { "target" };
            match c.read_bytes(6).and_then(|b| <[u8; 6]>::try_from(b).ok()) {
                Some(mac) => format!("{which} link-layer address {}", MacAddr(mac)),
                None => format!("{which} link-layer address (not Ethernet)"),
            }
        }
        3 => "prefix information".to_string(),
        4 => "redirected header".to_string(),
        5 => {
            let _ = c.read_bytes(2); // reserved
            match c.read_u32_be() {
                Some(mtu) => format!("mtu {mtu}"),
                None => "mtu".to_string(),
            }
        }
        14 => "nonce (duplicate address detection, RFC 7527)".to_string(),
        25 => "recursive DNS servers".to_string(),
        _ => format!("option type {t}"),
    }
}

/// One-line summary, tcpdump style:
/// `icmp echo request id 0x1234 seq 1, 56 bytes data`,
/// `icmpv6 neighbor solicitation who-has fe80::2 (from 00:11:22:33:44:55)`.
impl fmt::Display for Icmp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = if self.is_v6() { "icmpv6" } else { "icmp" };
        write!(f, "{proto} {}", self.type_name())?;
        if let Some((id, seq)) = self.echo() {
            return write!(
                f,
                " id 0x{id:04x} seq {seq}, {} bytes data",
                self.body.len()
            );
        }
        if let Some(target) = self.nd_target() {
            return match self.icmp_type {
                ND_NEIGHBOR_SOLICIT => {
                    write!(f, " who-has {target}")?;
                    if let Some(mac) = self.nd_link_addr(1) {
                        write!(f, " (from {mac})")?;
                    }
                    Ok(())
                }
                ND_NEIGHBOR_ADVERT => {
                    write!(f, " {target}")?;
                    if let Some(mac) = self.nd_link_addr(2) {
                        write!(f, " is-at {mac}")?;
                    }
                    Ok(())
                }
                _ => write!(f, " target {target}"),
            };
        }
        let code_name = self.code_name();
        if !code_name.is_empty() {
            write!(f, " ({code_name})")
        } else if self.code != 0 {
            write!(f, " code {}", self.code)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// The network layer, implemented as an [`Operate`] layer. Like [`crate::level2::Level2`],
/// it keeps no state.
pub struct Level3;

impl Level3 {
    /// Summary lines and field tables for an IP packet, without a hexdump.
    /// Layer 2 calls this for IPv4 and IPv6 payloads and indents the result, so
    /// the hexdump of the whole frame is only printed once.
    pub(crate) fn render_fields(&self, data: &[u8]) -> String {
        let mut out = String::new();
        match Cursor::new(data).read_u8().map(|b| b >> 4) {
            Some(4) => render_ipv4(&mut out, data),
            Some(6) => render_ipv6(&mut out, data),
            Some(v) => {
                let _ = writeln!(
                    out,
                    "ip version {v}: not IPv4 or IPv6, {} bytes",
                    data.len()
                );
            }
            None => out.push_str("empty ip packet\n"),
        }
        out
    }

    /// The packet as short per-protocol lines (IP, then ICMP or layer 4 and up).
    pub(crate) fn layers(&self, data: &[u8], rel: Option<TcpRel>) -> Vec<LayerLine> {
        let mut out = Vec::new();
        match Cursor::new(data).read_u8().map(|b| b >> 4) {
            Some(4) => {
                let Some(ip) = Ipv4Header::parse(data) else {
                    return vec![LayerLine::new(3, "ipv4", "malformed or truncated header")];
                };
                let mut t = format!(
                    "{} → {}  ttl {}  {} B",
                    ip.src, ip.dst, ip.ttl, ip.total_length
                );
                if ip.dont_fragment {
                    t.push_str("  DF");
                }
                if ip.is_fragment() {
                    let _ = write!(
                        t,
                        "  fragment @{}{}",
                        u32::from(ip.fragment_offset) * 8,
                        if ip.more_fragments { " MF" } else { "" }
                    );
                }
                if ip.truncated {
                    t.push_str("  truncated");
                }
                out.push(
                    LayerLine::new(3, "ipv4", t).warn_if(!ip.checksum_ok(), "bad header checksum"),
                );
                if ip.is_fragment() {
                    return out;
                }
                if let Some((icmp, ok)) = ip.icmp() {
                    out.push(icmp_line(&icmp, ok));
                } else if matches!(ip.protocol, PROTO_TCP | PROTO_UDP) {
                    let ctx = (!ip.truncated).then(|| ip.context());
                    out.extend(
                        Level4 {
                            protocol: ip.protocol,
                        }
                        .layers(ip.payload, ctx.as_ref(), rel),
                    );
                } else {
                    out.push(LayerLine::new(
                        4,
                        "?",
                        format!(
                            "{} payload, {} B",
                            protocol_name(ip.protocol),
                            ip.payload.len()
                        ),
                    ));
                }
            }
            Some(6) => {
                let Some(ip) = Ipv6Header::parse(data) else {
                    return vec![LayerLine::new(3, "ipv6", "malformed or truncated header")];
                };
                let mut t = format!(
                    "{} → {}  hop limit {}  {} B",
                    ip.src, ip.dst, ip.hop_limit, ip.payload_length
                );
                if !ip.ext.is_empty() {
                    let names: Vec<&str> = ip.ext.iter().map(|e| protocol_name(e.kind)).collect();
                    let _ = write!(t, "  via {}", names.join(" + "));
                }
                out.push(LayerLine::new(3, "ipv6", t));
                if ip.fragment().is_some() {
                    return out;
                }
                if let Some((icmp, ok)) = ip.icmp() {
                    out.push(icmp_line(&icmp, ok));
                } else if matches!(ip.upper_protocol, PROTO_TCP | PROTO_UDP) {
                    let ctx = (!ip.truncated).then(|| ip.context());
                    out.extend(
                        Level4 {
                            protocol: ip.upper_protocol,
                        }
                        .layers(ip.payload, ctx.as_ref(), rel),
                    );
                }
            }
            _ => out.push(LayerLine::new(
                3,
                "ip",
                format!("not an IP packet, {} bytes", data.len()),
            )),
        }
        out
    }

    /// One line for an IP packet: the IP summary, then the ICMP summary if there
    /// is one, separated by ` | `. Used for `osiview read` without `-v`.
    pub(crate) fn summary(&self, data: &[u8]) -> String {
        match Cursor::new(data).read_u8().map(|b| b >> 4) {
            Some(4) => match Ipv4Header::parse(data) {
                Some(ip) => {
                    let mut s = format!("{ip}, checksum {}", ok_text(ip.checksum_ok()));
                    if let Some((icmp, ok)) = ip.icmp() {
                        let _ = write!(s, " | {icmp}, checksum {}", ok_text(ok));
                    } else if !ip.is_fragment() {
                        let ctx = (!ip.truncated).then(|| ip.context());
                        transport_summary(&mut s, ip.protocol, ip.payload, ctx.as_ref());
                    }
                    s
                }
                None => "ipv4 (malformed)".to_string(),
            },
            Some(6) => match Ipv6Header::parse(data) {
                Some(ip) => {
                    let mut s = ip.to_string();
                    if let Some((icmp, ok)) = ip.icmp() {
                        let _ = write!(s, " | {icmp}, checksum {}", ok_text(ok));
                    } else if ip.fragment().is_none() {
                        let ctx = (!ip.truncated).then(|| ip.context());
                        transport_summary(&mut s, ip.upper_protocol, ip.payload, ctx.as_ref());
                    }
                    s
                }
                None => "ipv6 (malformed)".to_string(),
            },
            _ => format!("not an ip packet, {} bytes", data.len()),
        }
    }
}

/// ICMP's line in the stacked view. ICMP is part of the network layer.
fn icmp_line(icmp: &Icmp<'_>, checksum_ok: bool) -> LayerLine {
    let s = icmp.to_string();
    let (proto, text) = match s.split_once(' ') {
        Some(("icmpv6", rest)) => ("icmpv6", rest.to_string()),
        Some((_, rest)) => ("icmp", rest.to_string()),
        None => ("icmp", s.clone()),
    };
    LayerLine::new(3, proto, text).warn_if(!checksum_ok, "checksum BAD")
}

/// IPv4: summary, field table, then the ICMP message or a note about the payload.
fn render_ipv4(out: &mut String, data: &[u8]) {
    let Some(ip) = Ipv4Header::parse(data) else {
        out.push_str("ipv4 (malformed or truncated header)\n");
        return;
    };
    let _ = writeln!(out, "{ip}, checksum {}", ok_text(ip.checksum_ok()));
    ip.write_fields(out, "  ");

    if ip.is_fragment() {
        out.push_str("  (fragment: not reassembled, payload not decoded)\n");
    } else if let Some((icmp, ok)) = ip.icmp() {
        render_icmp(out, &icmp, ok);
    } else {
        // A truncated packet can't have its transport checksum verified.
        let ctx = (!ip.truncated).then(|| ip.context());
        render_transport(out, ip.protocol, ip.payload, ctx.as_ref());
    }
}

/// IPv6: summary, field table (with extension headers), then the ICMPv6 message
/// or a note about the payload.
fn render_ipv6(out: &mut String, data: &[u8]) {
    let Some(ip) = Ipv6Header::parse(data) else {
        out.push_str("ipv6 (malformed or truncated header)\n");
        return;
    };
    let _ = writeln!(out, "{ip}");
    ip.write_fields(out, "  ");

    if ip.fragment().is_some() {
        out.push_str("  (fragment: not reassembled, payload not decoded)\n");
    } else if let Some((icmp, ok)) = ip.icmp() {
        render_icmp(out, &icmp, ok);
    } else {
        let ctx = (!ip.truncated).then(|| ip.context());
        render_transport(out, ip.upper_protocol, ip.payload, ctx.as_ref());
    }
}

/// TCP and UDP go up to layer 4, indented one level. Other protocols just get
/// their name and size.
fn render_transport(out: &mut String, protocol: u8, payload: &[u8], ctx: Option<&IpContext>) {
    if matches!(protocol, PROTO_TCP | PROTO_UDP) {
        for line in (Level4 { protocol }).render_fields(payload, ctx).lines() {
            let _ = writeln!(out, "  {line}");
        }
    } else {
        let _ = writeln!(
            out,
            "  {} payload, {} bytes",
            protocol_name(protocol),
            payload.len()
        );
    }
}

/// The layer 4 part of a summary line, for TCP and UDP.
fn transport_summary(s: &mut String, protocol: u8, payload: &[u8], ctx: Option<&IpContext>) {
    if matches!(protocol, PROTO_TCP | PROTO_UDP) {
        let _ = write!(s, " | {}", Level4 { protocol }.summary(payload, ctx));
    }
}

/// ICMP: summary and field table one level deeper than the IP header. For error
/// messages, also a summary of the quoted original packet.
fn render_icmp(out: &mut String, icmp: &Icmp<'_>, checksum_ok: bool) {
    let _ = writeln!(out, "  {icmp}, checksum {}", ok_text(checksum_ok));
    icmp.write_fields(out, "    ", checksum_ok);
    if icmp.quotes_packet() {
        let original = match icmp.version {
            IcmpVersion::V4 => Ipv4Header::parse(icmp.body).map(|h| h.to_string()),
            IcmpVersion::V6 => Ipv6Header::parse(icmp.body).map(|h| h.to_string()),
        };
        if let Some(original) = original {
            let _ = writeln!(out, "    original: {original}");
        }
    }
}

impl Operate for Level3 {
    /// Decodes one IP packet (starting at the IP header) into summary lines,
    /// field tables and a hexdump of the packet.
    fn render(&self, data: &[u8]) -> String {
        let mut out = self.render_fields(data);
        let _ = write!(out, "{}", HexDump(data));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level2::Level2;

    // -- builders ----------------------------------------------------------

    /// An IPv4 packet with a correct header checksum.
    fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0x1c, 0x46, 0x40, 0x00, 64, proto, 0, 0]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        let ck = internet_checksum(&[&p]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    /// An ICMP message with a correct checksum over `pseudo` + the message.
    fn icmp_message(t: u8, code: u8, rest: [u8; 4], body: &[u8], pseudo: &[u8]) -> Vec<u8> {
        let mut m = vec![t, code, 0, 0];
        m.extend_from_slice(&rest);
        m.extend_from_slice(body);
        let ck = internet_checksum(&[pseudo, &m]);
        m[2..4].copy_from_slice(&ck.to_be_bytes());
        m
    }

    fn ipv6_packet(next: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0x00, 0x00, 0x00];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.push(next);
        p.push(255);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    // -- checksum ----------------------------------------------------------

    #[test]
    fn checksum_rfc1071_example() {
        // RFC 1071 §3: these bytes sum to 0xddf2, so the checksum is !0xddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&[&data]), 0x220d);
    }

    #[test]
    fn checksum_pairs_bytes_across_chunks_and_pads_odd_length() {
        let whole = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let split: [&[u8]; 2] = [&whole[..3], &whole[3..]];
        assert_eq!(internet_checksum(&split), 0x220d);
        // A lone byte is the high half of a word: 0x0100.
        assert_eq!(internet_checksum(&[&[0x01]]), !0x0100);
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    // -- IPv4 --------------------------------------------------------------

    /// A well-known example header (it appears on Wikipedia's IPv4 page):
    /// UDP from 192.168.0.1 to 192.168.0.199, checksum 0xb861.
    fn known_ipv4() -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        p.extend_from_slice(&[0; 95]);
        p
    }

    #[test]
    fn parses_ipv4_header() {
        let data = known_ipv4();
        let ip = Ipv4Header::parse(&data).unwrap();
        assert_eq!(ip.ihl, 5);
        assert_eq!(ip.total_length, 115);
        assert!(ip.dont_fragment);
        assert!(!ip.is_fragment());
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, PROTO_UDP);
        assert_eq!(ip.checksum, 0xb861);
        assert_eq!(ip.src, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(192, 168, 0, 199));
        assert_eq!(ip.payload.len(), 95);
        assert!(ip.checksum_ok());
        assert!(!ip.truncated);
    }

    #[test]
    fn ipv4_bad_checksum_detected() {
        let mut data = known_ipv4();
        data[8] = 63; // change the TTL without fixing the checksum
        assert!(!Ipv4Header::parse(&data).unwrap().checksum_ok());
    }

    #[test]
    fn ipv4_payload_excludes_padding_and_flags_truncation() {
        // Total length 28 but 46 bytes present: the extra 18 are Ethernet padding.
        let mut padded = ipv4_packet(PROTO_ICMP, [10, 0, 0, 1], [10, 0, 0, 2], &[0; 8]);
        padded.extend_from_slice(&[0; 18]);
        let ip = Ipv4Header::parse(&padded).unwrap();
        assert_eq!(ip.payload.len(), 8);
        assert!(!ip.truncated);

        // Total length 115 but only 30 bytes present.
        let data = known_ipv4();
        let ip = Ipv4Header::parse(&data[..30]).unwrap();
        assert_eq!(ip.payload.len(), 10);
        assert!(ip.truncated);
    }

    #[test]
    fn ipv4_rejects_bad_headers() {
        let data = known_ipv4();
        assert_eq!(Ipv4Header::parse(&data[..19]), None); // short header
        let mut v6 = data.clone();
        v6[0] = 0x65;
        assert_eq!(Ipv4Header::parse(&v6), None); // wrong version
        let mut ihl4 = data.clone();
        ihl4[0] = 0x44;
        assert_eq!(Ipv4Header::parse(&ihl4), None); // IHL below 5
        let mut short_total = data;
        short_total[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(Ipv4Header::parse(&short_total), None); // total < header
    }

    #[test]
    fn ipv4_options_are_kept() {
        let mut p = known_ipv4();
        p[0] = 0x46; // IHL 6: 4 bytes of options
        p.splice(20..20, [0x01, 0x01, 0x01, 0x00]); // NOP, NOP, NOP, end
        let ip = Ipv4Header::parse(&p).unwrap();
        assert_eq!(ip.options, &[0x01, 0x01, 0x01, 0x00]);
        assert_eq!(ip.payload.len(), 115 - 24);
    }

    // -- ICMPv4 ------------------------------------------------------------

    #[test]
    fn icmp_echo_request() {
        let icmp = icmp_message(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", &[]);
        let packet = ipv4_packet(PROTO_ICMP, [10, 0, 0, 1], [1, 1, 1, 1], &icmp);
        let ip = Ipv4Header::parse(&packet).unwrap();
        let (msg, ok) = ip.icmp().unwrap();
        assert!(ok);
        assert_eq!(msg.echo(), Some((0x1234, 1)));
        assert_eq!(
            msg.to_string(),
            "icmp echo request id 0x1234 seq 1, 8 bytes data"
        );

        let out = Level3.render(&packet);
        assert!(out.contains("ipv4 10.0.0.1 > 1.1.1.1, ICMP (1), ttl 64"));
        assert!(out.contains("  icmp echo request id 0x1234 seq 1, 8 bytes data, checksum OK"));
        assert!(out.contains("    seq"));
    }

    #[test]
    fn icmp_bad_checksum_detected() {
        let mut icmp = icmp_message(8, 0, [0, 1, 0, 1], b"x", &[]);
        icmp[8] = b'y';
        let packet = ipv4_packet(PROTO_ICMP, [10, 0, 0, 1], [10, 0, 0, 2], &icmp);
        let (_, ok) = Ipv4Header::parse(&packet).unwrap().icmp().unwrap();
        assert!(!ok);
    }

    #[test]
    fn icmp_time_exceeded_quotes_original() {
        // What traceroute gets back: the router quotes our probe's IP header + 8 bytes.
        let probe = ipv4_packet(PROTO_UDP, [10, 0, 0, 1], [8, 8, 8, 8], &[0; 32]);
        let quoted = &probe[..28];
        let icmp = icmp_message(11, 0, [0; 4], quoted, &[]);
        let packet = ipv4_packet(PROTO_ICMP, [192, 168, 1, 1], [10, 0, 0, 1], &icmp);

        let out = Level3.render(&packet);
        assert!(out.contains("icmp time exceeded (TTL exceeded in transit), checksum OK"));
        assert!(out.contains("original: ipv4 10.0.0.1 > 8.8.8.8, UDP (17)"));
        assert!(out.contains("truncated"));
    }

    #[test]
    fn ipv4_fragments_are_not_decoded() {
        let mut packet = ipv4_packet(PROTO_ICMP, [10, 0, 0, 1], [10, 0, 0, 2], &[0; 16]);
        packet[6] = 0x20; // MF set, DF cleared
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert!(ip.is_fragment());
        assert!(ip.icmp().is_none());
        assert!(Level3.render(&packet).contains("fragment: not reassembled"));
    }

    // -- IPv6 + ICMPv6 -----------------------------------------------------

    fn neighbor_solicitation() -> (Vec<u8>, Ipv6Addr, Ipv6Addr) {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1:ff00:2".parse().unwrap(); // solicited-node multicast
        let target: Ipv6Addr = "fe80::2".parse().unwrap();

        let mut body = target.octets().to_vec();
        body.extend_from_slice(&[1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // source link-layer option
        let len = (8 + body.len()) as u32;
        let pseudo = ipv6_pseudo_header(src, dst, len, PROTO_ICMPV6);
        let icmp = icmp_message(ND_NEIGHBOR_SOLICIT, 0, [0; 4], &body, &pseudo);

        // Put a Hop-by-Hop header (8 bytes, only PadN) in front, to exercise the chain.
        let mut payload = vec![PROTO_ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(&icmp);
        (ipv6_packet(PROTO_HOPOPT, src, dst, &payload), src, dst)
    }

    #[test]
    fn parses_ipv6_and_walks_extension_headers() {
        let (packet, src, dst) = neighbor_solicitation();
        let ip = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(ip.src, src);
        assert_eq!(ip.dst, dst);
        assert_eq!(ip.hop_limit, 255);
        assert_eq!(ip.next_header, PROTO_HOPOPT);
        assert_eq!(ip.ext.len(), 1);
        assert_eq!(ip.ext[0].kind, PROTO_HOPOPT);
        assert_eq!(ip.upper_protocol, PROTO_ICMPV6);
        assert_eq!(ip.payload.len(), 32);
    }

    #[test]
    fn neighbor_solicitation_decodes() {
        let (packet, _, _) = neighbor_solicitation();
        let ip = Ipv6Header::parse(&packet).unwrap();
        let (icmp, ok) = ip.icmp().unwrap();
        assert!(ok, "pseudo-header checksum should verify");
        assert_eq!(icmp.nd_target(), Some("fe80::2".parse().unwrap()));
        assert_eq!(
            icmp.nd_link_addr(1),
            Some(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(
            icmp.to_string(),
            "icmpv6 neighbor solicitation who-has fe80::2 (from 00:11:22:33:44:55)"
        );

        let out = Level3.render(&packet);
        assert!(out.contains("ipv6 fe80::1 > ff02::1:ff00:2, ICMPv6 (58), hop limit 255"));
        assert!(out.contains("via hop-by-hop"));
        assert!(out.contains("source link-layer address 00:11:22:33:44:55"));
        assert!(out.contains("checksum OK"));
    }

    #[test]
    fn ipv6_checksum_covers_pseudo_header() {
        // Same ICMPv6 bytes, different destination: the checksum must now fail.
        let (mut packet, _, _) = neighbor_solicitation();
        packet[39] ^= 0x01; // last byte of the destination address
        let ip = Ipv6Header::parse(&packet).unwrap();
        let (_, ok) = ip.icmp().unwrap();
        assert!(!ok);
    }

    #[test]
    fn ipv6_later_fragment_stops_the_walk() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        // Fragment header: next ICMPv6, offset 1 (8 bytes), M = 0, id 0xdeadbeef.
        let mut payload = vec![PROTO_ICMPV6, 0, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef];
        payload.extend_from_slice(&[0xaa; 8]);
        let packet = ipv6_packet(PROTO_IPV6_FRAG, src, dst, &payload);

        let ip = Ipv6Header::parse(&packet).unwrap();
        assert_eq!(
            ip.fragment(),
            Some(Ipv6Fragment {
                offset: 1,
                more: false,
                id: 0xdead_beef
            })
        );
        assert!(ip.icmp().is_none());
        let out = Level3.render(&packet);
        assert!(out.contains("ipv6 2001:db8::1 > 2001:db8::2"));
        assert!(out.contains("fragment offset 8, id 0xdeadbeef"));
    }

    #[test]
    fn ipv6_rejects_short_or_wrong_version() {
        let (packet, _, _) = neighbor_solicitation();
        assert_eq!(Ipv6Header::parse(&packet[..39]), None);
        assert_eq!(Ipv6Header::parse(&known_ipv4()), None);
    }

    #[test]
    fn nd_option_with_zero_length_stops() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut body = src.octets().to_vec();
        body.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // length 0: invalid
        let icmp_bytes = icmp_message(ND_NEIGHBOR_SOLICIT, 0, [0; 4], &body, &[]);
        let icmp = Icmp::parse(IcmpVersion::V6, &icmp_bytes).unwrap();
        assert!(icmp.nd_options().is_empty());
    }

    // -- through layer 2 ---------------------------------------------------

    #[test]
    fn level2_render_includes_layer3() {
        let icmp = icmp_message(0, 0, [0x12, 0x34, 0x00, 0x07], b"pong", &[]);
        let packet = ipv4_packet(PROTO_ICMP, [1, 1, 1, 1], [10, 0, 0, 1], &icmp);
        let mut frame = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&packet);

        let out = Level2.render(&frame);
        assert!(out.contains("\n  ipv4 1.1.1.1 > 10.0.0.1, ICMP (1)"));
        assert!(out.contains("\n    icmp echo reply id 0x1234 seq 7, 4 bytes data, checksum OK"));

        let line = Level2.summary(&frame);
        assert!(line.contains("ipv4 1.1.1.1 > 10.0.0.1"));
        assert!(line.contains("| icmp echo reply id 0x1234 seq 7"));
        assert!(!line.contains('\n'));
    }
}
