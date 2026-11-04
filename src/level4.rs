//! Layer 4 (transport): UDP (RFC 768) and TCP (RFC 9293).
//!
//! Layer 3 gets a packet to the right *host*; layer 4 gets it to the right
//! *program* on that host, using port numbers. The two protocols do this very
//! differently:
//!
//! - **UDP** adds ports, a length and a checksum, nothing more. Each datagram
//!   stands alone: no connection, no ordering, no retransmission. DNS uses it.
//! - **TCP** turns packets into a reliable, ordered byte stream. Every byte has a
//!   sequence number; the receiver acknowledges what it has; lost data is resent;
//!   the window limits how much can be in flight. A connection opens with a
//!   three-way handshake (SYN, SYN-ACK, ACK) and closes with FINs.
//!
//! This module decodes single segments and datagrams, so it has no state. The
//! connection view (which flow, handshake step, reassembled stream) needs state
//! across packets, so it lives in [`crate::flow`].
//!
//! # How the pieces fit
//!
//! ```text
//! IP payload + IpContext (addresses, protocol)
//!   │
//!   ├─ protocol 17 ─► UdpDatagram::parse ─► port 53/5353 ─► DNS (layer 7)
//!   │
//!   └─ protocol 6 ──► TcpSegment::parse ──► options (MSS, window scale, SACK, timestamps)
//!                                       └─► payload starts with HTTP? ─► HTTP/1.1 (layer 7)
//! ```
//!
//! # Checksums and offload
//!
//! UDP and TCP checksums cover a *pseudo-header* built from the IP header
//! (addresses, protocol, length) as well as the segment. That's why rendering
//! takes an [`IpContext`].
//!
//! On Linux, frames this host *sends* are usually captured before the NIC fills
//! in the checksum ("checksum offload"), so outgoing TCP and UDP often show
//! `BAD`. That's expected; incoming ones should be `OK`. To see real outgoing
//! checksums, turn offload off: `ethtool -K eth0 tx off`.
//!
//! # Specs
//!
//! - UDP: RFC 768. TCP header: RFC 9293 §3.1. Pseudo-header: RFC 9293 §3.1
//!   (IPv4) and RFC 8200 §8.1 (IPv6).
//! - TCP options: RFC 9293 §3.2 (MSS), RFC 7323 (window scale, timestamps),
//!   RFC 2018 (SACK).
//! - Port numbers: the IANA "Service Name and Transport Protocol Port Number"
//!   registry.

use std::fmt;
use std::fmt::Write as _;

use crate::base_level::Operate;
use crate::cursor::{Cursor, HexDump};
use crate::display::{LayerLine, TcpRel};
use crate::level2::field;
use crate::level3::{IpContext, PROTO_TCP, PROTO_UDP, internet_checksum};
use crate::level5::{Level5, looks_like_tls};
use crate::level7::Level7;

/// Well-known port names, for printing. The lower of the two ports usually
/// identifies the service.
pub fn port_name(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp-server",
        68 => "dhcp-client",
        80 => "http",
        123 => "ntp",
        443 => "https",
        546 => "dhcpv6-client",
        547 => "dhcpv6-server",
        853 => "dns-over-tls",
        5353 => "mdns",
        8080 => "http-alt",
        _ => return None,
    })
}

/// A port with its name, if it has one: `443 (https)`.
struct Port(u16);

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match port_name(self.0) {
            Some(name) => write!(f, "{} ({name})", self.0),
            None => write!(f, "{}", self.0),
        }
    }
}

// ---------------------------------------------------------------------------
// Checksum status
// ---------------------------------------------------------------------------

/// The result of checking a UDP or TCP checksum. It's more than OK/BAD because
/// there are two cases where it can't be checked at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumStatus {
    Ok,
    Bad,
    /// UDP over IPv4 may send 0, meaning "not computed" (RFC 768). Not allowed
    /// for UDP over IPv6 or for TCP.
    Absent,
    /// There was no IP context (so no pseudo-header), or the segment was cut
    /// short, so the checksum can't be computed.
    Unverified,
}

impl fmt::Display for ChecksumStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChecksumStatus::Ok => "OK",
            ChecksumStatus::Bad => "BAD",
            ChecksumStatus::Absent => "none",
            ChecksumStatus::Unverified => "not verified",
        })
    }
}

/// Checks a transport checksum: the Internet checksum over the pseudo-header
/// from `ctx` followed by the whole segment must be 0.
fn verify(ctx: Option<&IpContext>, segment: &[u8], truncated: bool) -> ChecksumStatus {
    let Some(ctx) = ctx else {
        return ChecksumStatus::Unverified;
    };
    if truncated {
        return ChecksumStatus::Unverified;
    }
    let pseudo = ctx.pseudo_header(segment.len());
    if internet_checksum(&[&pseudo, segment]) == 0 {
        ChecksumStatus::Ok
    } else {
        ChecksumStatus::Bad
    }
}

// ---------------------------------------------------------------------------
// UDP (RFC 768)
// ---------------------------------------------------------------------------

/// A UDP datagram.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Length             |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          payload …                            |
/// ```
///
/// The whole header is 8 bytes. Length counts the header too, so it's at least 8.
#[derive(Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// The sender's port. For a client this is usually an "ephemeral" port the
    /// OS picked (32768–60999 on Linux); replies go back to it.
    pub src_port: u16,
    /// The receiving program's port, e.g. 53 for a DNS server.
    pub dst_port: u16,
    /// Header + payload, in bytes. Redundant with the IP length, but checked:
    /// a datagram can't be longer than its IP payload.
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
    /// The datagram as `length` says, for checksumming and the field table.
    pub raw: &'a [u8],
    /// The IP payload was shorter than `length`.
    pub truncated: bool,
}

impl<'a> UdpDatagram<'a> {
    /// Parses a datagram. Returns `None` if it's under 8 bytes or `length` is
    /// under 8.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let src_port = c.read_u16_be()?;
        let dst_port = c.read_u16_be()?;
        let length = c.read_u16_be()?;
        let checksum = c.read_u16_be()?;
        if length < 8 {
            return None;
        }
        let wanted = usize::from(length) - 8;
        let available = c.remaining();
        let payload = c.read_bytes(wanted.min(available))?;
        let raw = Cursor::new(data).read_bytes(8 + payload.len())?;
        Some(UdpDatagram {
            src_port,
            dst_port,
            length,
            checksum,
            payload,
            raw,
            truncated: available < wanted,
        })
    }

    /// The checksum result. A zero checksum over IPv4 means "none".
    pub fn checksum_status(&self, ctx: Option<&IpContext>) -> ChecksumStatus {
        if self.checksum == 0 && ctx.is_some_and(|c| c.is_v4()) {
            return ChecksumStatus::Absent;
        }
        verify(ctx, self.raw, self.truncated)
    }

    fn write_fields(&self, out: &mut String, ind: &str, status: ChecksumStatus) -> Option<()> {
        let mut c = Cursor::new(self.raw);
        field(out, ind, "src port", c.read_bytes(2)?, Port(self.src_port));
        field(out, ind, "dst port", c.read_bytes(2)?, Port(self.dst_port));
        field(
            out,
            ind,
            "length",
            c.read_bytes(2)?,
            format_args!(
                "{} bytes (header 8 + payload {})",
                self.length,
                self.payload.len()
            ),
        );
        field(out, ind, "checksum", c.read_bytes(2)?, status);
        Some(())
    }
}

/// `udp 51234 > 53 (dns), 33 bytes`.
impl fmt::Display for UdpDatagram<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "udp {} > {}, {} bytes",
            Port(self.src_port),
            Port(self.dst_port),
            self.payload.len()
        )?;
        if self.truncated {
            f.write_str(", truncated")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TCP (RFC 9293)
// ---------------------------------------------------------------------------

/// The 8 TCP control bits, from byte 13 of the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    /// No more data from the sender: half of the connection close.
    pub const FIN: u8 = 0x01;
    /// Synchronise sequence numbers: the first segment in each direction.
    pub const SYN: u8 = 0x02;
    /// Reset: abort the connection right away (or refuse it).
    pub const RST: u8 = 0x04;
    /// Push: deliver to the application now rather than waiting to buffer more.
    pub const PSH: u8 = 0x08;
    /// The acknowledgment number is valid. Set on every segment after the first SYN.
    pub const ACK: u8 = 0x10;
    /// The urgent pointer is valid. Almost never used today.
    pub const URG: u8 = 0x20;
    /// ECN-Echo: "a router marked congestion on a packet you sent" (RFC 3168).
    pub const ECE: u8 = 0x40;
    /// Congestion Window Reduced: "I got your ECE and slowed down".
    pub const CWR: u8 = 0x80;

    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

/// `[SYN, ACK]`, in header bit order from FIN up.
impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(u8, &str); 8] = [
            (TcpFlags::FIN, "FIN"),
            (TcpFlags::SYN, "SYN"),
            (TcpFlags::RST, "RST"),
            (TcpFlags::PSH, "PSH"),
            (TcpFlags::ACK, "ACK"),
            (TcpFlags::URG, "URG"),
            (TcpFlags::ECE, "ECE"),
            (TcpFlags::CWR, "CWR"),
        ];
        let names: Vec<&str> = NAMES
            .iter()
            .filter(|(bit, _)| self.has(*bit))
            .map(|(_, name)| *name)
            .collect();
        write!(f, "[{}]", names.join(", "))
    }
}

/// One decoded TCP option. Options are type-length-value, except End of List (0)
/// and No-Operation (1), which are a single byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpOption<'a> {
    /// Kind 1: one byte of padding, used to align the next option.
    Nop,
    /// Kind 2, SYN only: the largest segment payload the sender wants to receive.
    /// Typically 1460 on Ethernet (1500 MTU − 20 IP − 20 TCP).
    Mss(u16),
    /// Kind 3, SYN only (RFC 7323): later window values from this side are
    /// shifted left by this many bits, so windows can exceed 64 KiB.
    WindowScale(u8),
    /// Kind 4, SYN only (RFC 2018): "I understand SACK blocks".
    SackPermitted,
    /// Kind 5 (RFC 2018): "I also have these byte ranges", given as
    /// `(left edge, right edge)` sequence numbers, so the sender only resends the gaps.
    Sack(Vec<(u32, u32)>),
    /// Kind 8 (RFC 7323): the sender's clock value and an echo of the peer's.
    /// Used to measure round-trip time and to reject very old duplicates (PAWS).
    Timestamps { value: u32, echo: u32 },
    /// Any other kind, with its data bytes.
    Unknown { kind: u8, data: &'a [u8] },
}

impl fmt::Display for TcpOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpOption::Nop => f.write_str("nop"),
            TcpOption::Mss(m) => write!(f, "mss {m}"),
            TcpOption::WindowScale(s) => write!(f, "wscale {s} (window × {})", 1u32 << s.min(&14)),
            TcpOption::SackPermitted => f.write_str("sack permitted"),
            TcpOption::Sack(blocks) => {
                f.write_str("sack")?;
                for (l, r) in blocks {
                    write!(f, " {l}-{r}")?;
                }
                Ok(())
            }
            TcpOption::Timestamps { value, echo } => write!(f, "timestamps {value}, echo {echo}"),
            TcpOption::Unknown { kind, data } => {
                let name = match kind {
                    30 => "multipath tcp",
                    34 => "tcp fast open cookie",
                    _ => "option",
                };
                write!(f, "{name} (kind {kind}, {} bytes)", data.len())
            }
        }
    }
}

/// Parses the options area into `(option, raw bytes)` pairs. Stops at End of
/// List, or at the first malformed option (a length below 2, or one that runs
/// past the end): the rest can't be trusted.
fn parse_options(options: &[u8]) -> Vec<(TcpOption<'_>, &[u8])> {
    let mut out = Vec::new();
    let mut rest = options;
    while !rest.is_empty() {
        let mut peek = Cursor::new(rest);
        let Some(kind) = peek.read_u8() else { break };
        if kind == 0 {
            break;
        }
        if kind == 1 {
            let mut take = Cursor::new(rest);
            let (Some(raw), Some(after)) = (take.read_bytes(1), take.read_bytes(rest.len() - 1))
            else {
                break;
            };
            out.push((TcpOption::Nop, raw));
            rest = after;
            continue;
        }
        let Some(len) = peek.read_u8().map(usize::from) else {
            break;
        };
        if len < 2 {
            break;
        }
        let mut take = Cursor::new(rest);
        let Some(raw) = take.read_bytes(len) else {
            break;
        };
        let after = take.read_bytes(take.remaining()).unwrap_or(&[]);
        let Some(data) = peek.read_bytes(len - 2) else {
            break;
        };

        let mut d = Cursor::new(data);
        let opt = match (kind, len) {
            (2, 4) => d.read_u16_be().map(TcpOption::Mss),
            (3, 3) => d.read_u8().map(TcpOption::WindowScale),
            (4, 2) => Some(TcpOption::SackPermitted),
            (5, _) if (len - 2) % 8 == 0 => {
                let mut blocks = Vec::new();
                while let (Some(l), Some(r)) = (d.read_u32_be(), d.read_u32_be()) {
                    blocks.push((l, r));
                }
                Some(TcpOption::Sack(blocks))
            }
            (8, 10) => match (d.read_u32_be(), d.read_u32_be()) {
                (Some(value), Some(echo)) => Some(TcpOption::Timestamps { value, echo }),
                _ => None,
            },
            _ => None,
        }
        .unwrap_or(TcpOption::Unknown { kind, data });
        out.push((opt, raw));
        rest = after;
    }
    out
}

/// A TCP segment.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Acknowledgment Number                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Data |       |C|E|U|A|P|R|S|F|                               |
/// | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
/// |       |       |R|E|G|K|H|T|N|N|                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |         Urgent Pointer        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options (0–40 bytes)                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             data                              |
/// ```
///
/// TCP has no length field: the segment runs to the end of the IP payload.
#[derive(Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    /// Sequence number of the first data byte. On a SYN it's the Initial
    /// Sequence Number (ISN), chosen at random, and the SYN itself uses up one
    /// number; so does a FIN. Numbers wrap around at 2^32.
    pub seq: u32,
    /// With ACK set: the next sequence number the sender expects to receive,
    /// meaning "I have everything before this".
    pub ack: u32,
    /// Header length in 32-bit words (5–15), like IPv4's IHL.
    pub data_offset: u8,
    pub flags: TcpFlags,
    /// How many more bytes the sender can receive right now (flow control). To
    /// get the real value, shift it by the window scale from that side's SYN.
    pub window: u16,
    pub checksum: u16,
    /// With URG set: offset of the end of urgent data. Effectively unused.
    pub urgent: u16,
    /// Raw options. Use [`TcpSegment::options`] to decode them.
    pub options: &'a [u8],
    pub payload: &'a [u8],
    /// The whole segment, for checksumming and the field table.
    pub raw: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// Parses a segment. Returns `None` if it's shorter than its header or the
    /// data offset is below 5.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let src_port = c.read_u16_be()?;
        let dst_port = c.read_u16_be()?;
        let seq = c.read_u32_be()?;
        let ack = c.read_u32_be()?;
        let data_offset = c.read_u8()? >> 4;
        let flags = TcpFlags(c.read_u8()?);
        let window = c.read_u16_be()?;
        let checksum = c.read_u16_be()?;
        let urgent = c.read_u16_be()?;
        if data_offset < 5 {
            return None;
        }
        let options = c.read_bytes(usize::from(data_offset) * 4 - 20)?;
        let payload = c.read_bytes(c.remaining())?;
        Some(TcpSegment {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            checksum,
            urgent,
            options,
            payload,
            raw: data,
        })
    }

    pub fn options(&self) -> Vec<(TcpOption<'a>, &'a [u8])> {
        parse_options(self.options)
    }

    pub fn checksum_status(&self, ctx: Option<&IpContext>) -> ChecksumStatus {
        verify(ctx, self.raw, false)
    }

    fn write_fields(&self, out: &mut String, ind: &str, status: ChecksumStatus) -> Option<()> {
        let mut c = Cursor::new(self.raw);
        field(out, ind, "src port", c.read_bytes(2)?, Port(self.src_port));
        field(out, ind, "dst port", c.read_bytes(2)?, Port(self.dst_port));
        field(out, ind, "seq", c.read_bytes(4)?, self.seq);
        let ack = c.read_bytes(4)?;
        if self.flags.has(TcpFlags::ACK) {
            field(out, ind, "ack", ack, self.ack);
        } else {
            field(out, ind, "ack", ack, "(ACK flag not set, ignored)");
        }
        field(
            out,
            ind,
            "offset",
            c.read_bytes(1)?,
            format_args!("header {} bytes", usize::from(self.data_offset) * 4),
        );
        field(out, ind, "flags", c.read_bytes(1)?, self.flags);
        field(out, ind, "window", c.read_bytes(2)?, self.window);
        field(out, ind, "checksum", c.read_bytes(2)?, status);
        field(out, ind, "urgent", c.read_bytes(2)?, self.urgent);
        for (opt, raw) in self.options() {
            if opt != TcpOption::Nop {
                field(out, ind, "option", raw, opt);
            }
        }
        Some(())
    }
}

/// `tcp 51234 > 80 (http) [SYN] seq 1000 win 64240, mss 1460, sack permitted, 0 bytes`.
impl fmt::Display for TcpSegment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tcp {} > {} {} seq {}",
            Port(self.src_port),
            Port(self.dst_port),
            self.flags,
            self.seq
        )?;
        if self.flags.has(TcpFlags::ACK) {
            write!(f, " ack {}", self.ack)?;
        }
        write!(f, " win {}", self.window)?;
        for (opt, _) in self.options() {
            if opt != TcpOption::Nop {
                write!(f, ", {opt}")?;
            }
        }
        write!(f, ", {} bytes", self.payload.len())
    }
}

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// The transport layer. The IP header says whether the payload is TCP or UDP,
/// so that's the one piece of state this needs: which protocol to decode.
pub struct Level4 {
    /// [`PROTO_TCP`] or [`PROTO_UDP`].
    pub protocol: u8,
}

impl Level4 {
    /// Summary line and field table, then layer 7 if the payload is something
    /// osiview decodes. No hexdump: layer 2 prints one for the whole frame.
    /// `ctx` is needed to verify the checksum.
    pub(crate) fn render_fields(&self, data: &[u8], ctx: Option<&IpContext>) -> String {
        let mut out = String::new();
        match self.protocol {
            PROTO_UDP => match UdpDatagram::parse(data) {
                Some(udp) => {
                    let status = udp.checksum_status(ctx);
                    let _ = writeln!(out, "{udp}, checksum {status}");
                    udp.write_fields(&mut out, "  ", status);
                    let l7 = Level7::for_udp(udp.src_port, udp.dst_port);
                    write_payload(&mut out, &l7, udp.payload);
                }
                None => out.push_str("udp (malformed or truncated header)\n"),
            },
            PROTO_TCP => match TcpSegment::parse(data) {
                Some(tcp) => {
                    let status = tcp.checksum_status(ctx);
                    let _ = writeln!(out, "{tcp}, checksum {status}");
                    tcp.write_fields(&mut out, "  ", status);
                    if looks_like_tls(tcp.payload) {
                        // TLS: layer 5 shows the records; the content is encrypted.
                        for line in Level5.render_fields(tcp.payload).lines() {
                            let _ = writeln!(out, "  {line}");
                        }
                    } else {
                        let l7 = Level7::for_tcp(tcp.src_port, tcp.dst_port);
                        write_payload(&mut out, &l7, tcp.payload);
                    }
                }
                None => out.push_str("tcp (malformed or truncated header)\n"),
            },
            p => {
                let _ = writeln!(out, "protocol {p}: not TCP or UDP, {} bytes", data.len());
            }
        }
        out
    }

    /// The segment as short per-protocol lines: TCP or UDP, then layer 5 or 7.
    pub(crate) fn layers(
        &self,
        data: &[u8],
        ctx: Option<&IpContext>,
        rel: Option<TcpRel>,
    ) -> Vec<LayerLine> {
        let mut out = Vec::new();
        match self.protocol {
            PROTO_UDP => {
                let Some(udp) = UdpDatagram::parse(data) else {
                    return vec![LayerLine::new(4, "udp", "malformed")];
                };
                let t = format!(
                    "{} → {}  {} B",
                    Port(udp.src_port),
                    Port(udp.dst_port),
                    udp.payload.len()
                );
                out.push(LayerLine::new(4, "udp", t).warn_if(
                    udp.checksum_status(ctx) == ChecksumStatus::Bad,
                    "checksum BAD",
                ));
                out.extend(Level7::for_udp(udp.src_port, udp.dst_port).layer(udp.payload));
            }
            PROTO_TCP => {
                let Some(tcp) = TcpSegment::parse(data) else {
                    return vec![LayerLine::new(4, "tcp", "malformed")];
                };
                let mut t = format!(
                    "{} → {}  {}",
                    Port(tcp.src_port),
                    Port(tcp.dst_port),
                    tcp.flags
                );
                match rel {
                    Some(r) => {
                        let _ = write!(t, "  seq {}", r.seq);
                        if let Some(a) = r.ack {
                            let _ = write!(t, " ack {a}");
                        }
                    }
                    None => {
                        let _ = write!(t, "  seq {}", tcp.seq);
                        if tcp.flags.has(TcpFlags::ACK) {
                            let _ = write!(t, " ack {}", tcp.ack);
                        }
                    }
                }
                let _ = write!(t, "  win {}", tcp.window);
                let opts = options_short(&tcp);
                if !opts.is_empty() {
                    let _ = write!(t, "  {opts}");
                }
                let _ = write!(t, "  {} B", tcp.payload.len());
                out.push(LayerLine::new(4, "tcp", t).warn_if(
                    tcp.checksum_status(ctx) == ChecksumStatus::Bad,
                    "checksum BAD",
                ));
                if looks_like_tls(tcp.payload) {
                    out.push(Level5.layer(tcp.payload));
                } else {
                    out.extend(Level7::for_tcp(tcp.src_port, tcp.dst_port).layer(tcp.payload));
                }
            }
            p => out.push(LayerLine::new(
                4,
                "?",
                format!("protocol {p}, {} B", data.len()),
            )),
        }
        out
    }

    /// One line: the transport summary, then the layer 7 summary if any.
    pub(crate) fn summary(&self, data: &[u8], ctx: Option<&IpContext>) -> String {
        match self.protocol {
            PROTO_UDP => match UdpDatagram::parse(data) {
                Some(udp) => {
                    let mut s = format!("{udp}, checksum {}", udp.checksum_status(ctx));
                    let l7 = Level7::for_udp(udp.src_port, udp.dst_port);
                    if let Some(app) = l7.summary(udp.payload) {
                        let _ = write!(s, " | {app}");
                    }
                    s
                }
                None => "udp (malformed)".to_string(),
            },
            PROTO_TCP => match TcpSegment::parse(data) {
                Some(tcp) => {
                    let mut s = format!("{tcp}, checksum {}", tcp.checksum_status(ctx));
                    if looks_like_tls(tcp.payload) {
                        let _ = write!(s, " | {}", Level5.summary(tcp.payload));
                    } else if let Some(app) =
                        Level7::for_tcp(tcp.src_port, tcp.dst_port).summary(tcp.payload)
                    {
                        let _ = write!(s, " | {app}");
                    }
                    s
                }
                None => "tcp (malformed)".to_string(),
            },
            p => format!("protocol {p}, {} bytes", data.len()),
        }
    }
}

/// TCP options in brief, for the stacked view: `mss 1460  sack  ts  wscale 7`.
fn options_short(tcp: &TcpSegment<'_>) -> String {
    tcp.options()
        .into_iter()
        .filter_map(|(o, _)| match o {
            TcpOption::Nop => None,
            TcpOption::Mss(m) => Some(format!("mss {m}")),
            TcpOption::WindowScale(s) => Some(format!("wscale {s}")),
            TcpOption::SackPermitted => Some("sack".to_string()),
            TcpOption::Sack(b) => Some(format!(
                "sack {} block{}",
                b.len(),
                if b.len() == 1 { "" } else { "s" }
            )),
            TcpOption::Timestamps { .. } => Some("ts".to_string()),
            TcpOption::Unknown { kind, .. } => Some(format!("opt{kind}")),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The payload: decoded by layer 7 and indented if it recognises it, otherwise
/// just its size.
fn write_payload(out: &mut String, l7: &Level7, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    match l7.render_fields(payload) {
        Some(text) => {
            for line in text.lines() {
                let _ = writeln!(out, "  {line}");
            }
        }
        None => {
            let _ = writeln!(out, "  {:<8} ({} bytes)", "data", payload.len());
        }
    }
}

impl Operate for Level4 {
    /// Decodes a segment or datagram without IP context, so the checksum shows as
    /// "not verified". Layer 3 uses `render_fields` with the context instead.
    fn render(&self, data: &[u8]) -> String {
        let mut out = self.render_fields(data, None);
        let _ = write!(out, "{}", HexDump(data));
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub(crate) fn ctx4(protocol: u8) -> IpContext {
        IpContext {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            protocol,
        }
    }

    /// Builds a TCP segment with a correct checksum for `ctx`.
    pub(crate) fn tcp_segment(
        ctx: &IpContext,
        ports: (u16, u16),
        seq: u32,
        ack: u32,
        flags: u8,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        assert!(options.len().is_multiple_of(4));
        let offset = (20 + options.len()) / 4;
        let mut s = Vec::new();
        s.extend_from_slice(&ports.0.to_be_bytes());
        s.extend_from_slice(&ports.1.to_be_bytes());
        s.extend_from_slice(&seq.to_be_bytes());
        s.extend_from_slice(&ack.to_be_bytes());
        s.push((offset as u8) << 4);
        s.push(flags);
        s.extend_from_slice(&64240u16.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent
        s.extend_from_slice(options);
        s.extend_from_slice(payload);
        let ck = internet_checksum(&[&ctx.pseudo_header(s.len()), &s]);
        s[16..18].copy_from_slice(&ck.to_be_bytes());
        s
    }

    pub(crate) fn udp_datagram(ctx: &IpContext, ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&ports.0.to_be_bytes());
        d.extend_from_slice(&ports.1.to_be_bytes());
        d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(payload);
        let ck = internet_checksum(&[&ctx.pseudo_header(d.len()), &d]);
        d[6..8].copy_from_slice(&ck.to_be_bytes());
        d
    }

    /// A typical Linux SYN's options: MSS 1460, SACK permitted, timestamps,
    /// NOP, window scale 7.
    const SYN_OPTIONS: [u8; 20] = [
        2, 4, 0x05, 0xb4, // mss 1460
        4, 2, // sack permitted
        8, 10, 0, 0, 0x30, 0x39, 0, 0, 0, 0, // timestamps 12345, 0
        1, // nop
        3, 3, 7, // wscale 7
    ];

    #[test]
    fn parses_syn_with_options() {
        let ctx = ctx4(PROTO_TCP);
        let raw = tcp_segment(&ctx, (51234, 80), 1000, 0, TcpFlags::SYN, &SYN_OPTIONS, &[]);
        let seg = TcpSegment::parse(&raw).unwrap();
        assert_eq!(seg.src_port, 51234);
        assert_eq!(seg.dst_port, 80);
        assert_eq!(seg.seq, 1000);
        assert_eq!(seg.data_offset, 10);
        assert_eq!(seg.flags.to_string(), "[SYN]");
        assert_eq!(seg.checksum_status(Some(&ctx)), ChecksumStatus::Ok);

        let opts: Vec<TcpOption> = seg.options().into_iter().map(|(o, _)| o).collect();
        assert_eq!(
            opts,
            vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamps {
                    value: 12345,
                    echo: 0
                },
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ]
        );
        assert_eq!(
            seg.to_string(),
            "tcp 51234 > 80 (http) [SYN] seq 1000 win 64240, mss 1460, sack permitted, \
             timestamps 12345, echo 0, wscale 7 (window × 128), 0 bytes"
        );
    }

    #[test]
    fn tcp_checksum_covers_pseudo_header() {
        let ctx = ctx4(PROTO_TCP);
        let raw = tcp_segment(&ctx, (1, 2), 0, 0, TcpFlags::SYN, &[], &[]);
        let seg = TcpSegment::parse(&raw).unwrap();
        let mut other = ctx;
        other.dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(seg.checksum_status(Some(&other)), ChecksumStatus::Bad);
        assert_eq!(seg.checksum_status(None), ChecksumStatus::Unverified);
    }

    #[test]
    fn tcp_checksum_over_ipv6() {
        let ctx = IpContext {
            src: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            dst: IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
            protocol: PROTO_TCP,
        };
        let raw = tcp_segment(&ctx, (40000, 443), 7, 9, TcpFlags::ACK, &[], b"hi");
        let seg = TcpSegment::parse(&raw).unwrap();
        assert_eq!(seg.checksum_status(Some(&ctx)), ChecksumStatus::Ok);
        assert_eq!(seg.payload, b"hi");
    }

    #[test]
    fn malformed_tcp_is_none() {
        let ctx = ctx4(PROTO_TCP);
        let raw = tcp_segment(&ctx, (1, 2), 0, 0, 0, &SYN_OPTIONS, &[]);
        assert_eq!(TcpSegment::parse(&raw[..19]), None); // short fixed header
        assert_eq!(TcpSegment::parse(&raw[..30]), None); // options cut off
        let mut bad = raw.clone();
        bad[12] = 0x40; // data offset 4
        assert_eq!(TcpSegment::parse(&bad), None);
    }

    #[test]
    fn malformed_options_stop_the_walk() {
        // MSS, then an option with length 1 (invalid), then a window scale that
        // must not be decoded.
        let opts = [2, 4, 0x05, 0xb4, 9, 1, 3, 3];
        let parsed: Vec<_> = parse_options(&opts).into_iter().map(|(o, _)| o).collect();
        assert_eq!(parsed, vec![TcpOption::Mss(1460)]);
        // An option running past the end.
        assert!(parse_options(&[8, 10, 0, 0]).is_empty());
        // End of list stops even with bytes after it.
        assert!(parse_options(&[0, 2, 4, 5, 0xb4]).is_empty());
    }

    #[test]
    fn sack_blocks() {
        let opts = [5, 18, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 30, 0, 0, 0, 40];
        let parsed: Vec<_> = parse_options(&opts).into_iter().map(|(o, _)| o).collect();
        assert_eq!(parsed, vec![TcpOption::Sack(vec![(10, 20), (30, 40)])]);
    }

    #[test]
    fn udp_datagram_and_checksum() {
        let ctx = ctx4(PROTO_UDP);
        let raw = udp_datagram(&ctx, (51000, 9999), b"hello");
        let udp = UdpDatagram::parse(&raw).unwrap();
        assert_eq!(udp.length, 13);
        assert_eq!(udp.payload, b"hello");
        assert_eq!(udp.checksum_status(Some(&ctx)), ChecksumStatus::Ok);
        assert_eq!(udp.to_string(), "udp 51000 > 9999, 5 bytes");

        let mut zero = raw.clone();
        zero[6..8].copy_from_slice(&[0, 0]);
        let udp = UdpDatagram::parse(&zero).unwrap();
        assert_eq!(udp.checksum_status(Some(&ctx)), ChecksumStatus::Absent);
    }

    #[test]
    fn udp_length_rules() {
        let ctx = ctx4(PROTO_UDP);
        let mut raw = udp_datagram(&ctx, (1, 2), b"abcdef");
        raw.extend_from_slice(&[0; 4]); // trailing bytes beyond `length` are ignored
        let udp = UdpDatagram::parse(&raw).unwrap();
        assert_eq!(udp.payload, b"abcdef");
        assert!(!udp.truncated);

        let udp = UdpDatagram::parse(&raw[..10]).unwrap();
        assert!(udp.truncated);
        assert_eq!(udp.checksum_status(Some(&ctx)), ChecksumStatus::Unverified);

        let mut short = raw;
        short[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(UdpDatagram::parse(&short), None);
    }

    #[test]
    fn render_shows_fields() {
        let ctx = ctx4(PROTO_TCP);
        let raw = tcp_segment(&ctx, (51234, 80), 1000, 0, TcpFlags::SYN, &SYN_OPTIONS, &[]);
        let out = Level4 {
            protocol: PROTO_TCP,
        }
        .render_fields(&raw, Some(&ctx));
        let lines: Vec<String> = out
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        assert!(lines.iter().any(|l| l == "flags 02 [SYN]"));
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("checksum ") && l.ends_with(" OK"))
        );
        assert!(lines.iter().any(|l| l == "option 02 04 05 b4 mss 1460"));
        assert!(
            lines
                .iter()
                .any(|l| l == "ack 00 00 00 00 (ACK flag not set, ignored)")
        );
    }
}
