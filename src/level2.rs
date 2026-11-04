//! Layer 2 (data link): Ethernet II, IEEE 802.1Q VLAN tags and ARP (RFC 826).
//!
//! Capture uses a Linux packet socket, `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`,
//! which hands us whole frames starting at the destination MAC. The NIC has already
//! stripped the preamble, SFD and (usually) the FCS. See `man 7 packet`.
//!
//! # How the pieces fit
//!
//! ```text
//! raw bytes ──► EthernetFrame::parse ──► EthernetFrame { dst, src, vlan, ether_type, payload }
//!                                                                    │          │
//!                                     ether_type == 0x0806 (ARP) ◄───┘          │
//!                                                │                              │
//!                                     ArpPacket::parse(payload)     payload goes up to layer 3
//! ```
//!
//! Every parser here borrows from the input buffer (`&'a [u8]`) instead of copying.
//! That is why the frame and ARP types carry a lifetime: a parsed frame is a *view*
//! over the bytes, and cannot outlive them.
//!
//! # Specs
//!
//! - Ethernet frame format: IEEE 802.3, clause 3 (MAC frame structure).
//! - VLAN tag: IEEE 802.1Q, section 9.6 (VLAN tag format).
//! - ARP: RFC 826.
//! - EtherType and ARP number registries: RFC 7042 and the IANA
//!   "IEEE 802 Numbers" registry.

use std::ffi::{CStr, CString};
use std::fmt;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::base_level::Operate;
use crate::cursor::{Cursor, HexDump};
use crate::display::{LayerLine, TcpRel};
use crate::level3::Level3;
use crate::pcap::Timestamp;

// EtherTypes: the 2-byte field after the source MAC that says which protocol the
// payload belongs to. These are the ones osiview cares about; the full list is in
// the IANA "IEEE 802 Numbers" registry.

/// Internet Protocol version 4 (RFC 791). Decoded at layer 3.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// Address Resolution Protocol (RFC 826). Decoded in this module.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// IEEE 802.1Q VLAN tag. When this appears where the EtherType should be, it is
/// really a TPID (Tag Protocol Identifier): 2 bytes of tag follow, then the real
/// EtherType.
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// Internet Protocol version 6 (RFC 8200). Decoded at layer 3.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// The type/length field is overloaded. Values of 1500 (0x05dc) or less are an
/// IEEE 802.3 *length*, the original Ethernet design. Values of 0x0600 (1536) or
/// more are an Ethernet II *EtherType*. 1501–1535 is undefined. This split is why
/// both frame formats can share a wire.
const ETHERTYPE_MIN: u16 = 0x0600;

/// Returns a short name for an EtherType, for printing. Unknown values print as
/// `"unknown"`; the hex value is always shown alongside, so nothing is lost.
pub fn ether_type_name(t: u16) -> &'static str {
    match t {
        ETHERTYPE_IPV4 => "IPv4",
        ETHERTYPE_ARP => "ARP",
        ETHERTYPE_VLAN => "802.1Q",
        ETHERTYPE_IPV6 => "IPv6",
        0x88cc => "LLDP",
        0x888e => "EAPOL",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

/// A 48-bit IEEE MAC address, the "hardware address" of a network interface.
///
/// The first 3 bytes are usually the OUI (Organizationally Unique Identifier) of the
/// vendor; the last 3 are assigned by that vendor. Two bits in the first byte are
/// flags:
///
/// - bit 0 (`0x01`): **I/G**. 1 means group (multicast or broadcast), 0 means one
///   interface (unicast).
/// - bit 1 (`0x02`): **U/L**. 1 means locally administered (e.g. a randomised or
///   VM address), 0 means globally unique.
///
/// It's a newtype over `[u8; 6]`, not a bare array, so it can have its own
/// `Display` (`aa:bb:cc:dd:ee:ff`) and can't be mixed up with other 6-byte values.
/// It's `Copy` because it's only 6 bytes, cheaper to copy than to borrow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`: every interface on the segment accepts this. ARP
    /// requests are sent here because the sender doesn't yet know who to ask.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// Reads 6 bytes from the cursor. Returns `None`, without advancing, if fewer
    /// than 6 bytes remain. The `try_into` can't fail once `read_bytes(6)` succeeds,
    /// but using `?` instead of `unwrap` keeps the function panic-free.
    fn read(c: &mut Cursor<'_>) -> Option<Self> {
        Some(MacAddr(c.read_bytes(6)?.try_into().ok()?))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

// ---------------------------------------------------------------------------
// Ethernet II + 802.1Q
// ---------------------------------------------------------------------------

/// IEEE 802.1Q Tag Control Information: the 16 bits after TPID 0x8100.
///
/// ```text
///  0               1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-----+-+-----------------------+
/// | PCP |D|          VID          |
/// +-----+-+-----------------------+
/// ```
///
/// A VLAN splits one physical network into several logical ones. Switches add or
/// strip this 4-byte tag (TPID `0x8100` + TCI) between the source MAC and the
/// EtherType. Frames with no tag belong to the port's default VLAN.
///
/// The tag is 4 bytes, so a tagged frame's header is 18 bytes instead of 14.
/// Double tagging (802.1ad "Q-in-Q", TPID `0x88a8`) exists but isn't handled here.
///
/// Linux note: most NIC drivers strip the tag in hardware before the packet socket
/// sees the frame. To get it back, read the `PACKET_AUXDATA` control message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VlanTag {
    /// Priority Code Point, 3 bits (0–7). The 802.1p class of service: switches use
    /// it to queue traffic. 0 is best effort; higher values are for voice, control
    /// traffic, and so on.
    pub pcp: u8,
    /// Drop Eligible Indicator, 1 bit. If set, the frame may be dropped first when
    /// the network is congested. Older documents call it CFI.
    pub dei: bool,
    /// VLAN Identifier, 12 bits. 1–4094 are usable VLANs; 0 means "no VLAN, priority
    /// only" and 4095 is reserved.
    pub vid: u16,
}

impl VlanTag {
    /// Splits the 16-bit TCI into its fields with shifts and masks:
    /// `>> 13` keeps the top 3 bits (PCP), `& 0x1000` tests bit 12 (DEI) and
    /// `& 0x0fff` keeps the low 12 bits (VID).
    fn from_tci(tci: u16) -> Self {
        VlanTag {
            pcp: (tci >> 13) as u8,
            dei: tci & 0x1000 != 0,
            vid: tci & 0x0fff,
        }
    }
}

/// An Ethernet II frame, optionally carrying one 802.1Q tag.
///
/// ```text
/// +----------+----------+-----------------+-----------+---------+
/// | dst (6)  | src (6)  | [0x8100 TCI](4) | type (2)  | payload |
/// +----------+----------+-----------------+-----------+---------+
/// ```
///
/// What's on the wire is longer: a 7-byte preamble and 1-byte SFD come before `dst`,
/// and a 4-byte FCS (CRC-32 checksum) comes after the payload. The NIC handles
/// those, so a packet socket starts at `dst` and usually ends at the payload.
///
/// Size limits: the payload is 46–1500 bytes, so a frame without FCS is 60–1514
/// bytes. Senders pad short payloads with zeros to reach 46, which is why a 28-byte
/// ARP packet arrives with 18 bytes of padding. Frames you *send* may show up
/// shorter than 60 in your own capture, because the kernel sees them before the NIC
/// pads them.
///
/// The struct borrows `payload` from the input instead of copying it. The `'a`
/// lifetime ties the frame to the buffer it was parsed from.
#[derive(Debug, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    /// Destination MAC: who the frame is for. It may be unicast, multicast or
    /// broadcast. It comes first so a NIC can decide to drop the frame early.
    pub dst: MacAddr,
    /// Source MAC: which interface sent the frame. Always unicast.
    pub src: MacAddr,
    /// The 802.1Q tag, if the frame had one (TPID `0x8100` after `src`).
    pub vlan: Option<VlanTag>,
    /// Which protocol `payload` holds (≥ 0x0600), or, for the rare 802.3 frame,
    /// the payload length (≤ 1500). See [`EthernetFrame::is_802_3`].
    pub ether_type: u16,
    /// Everything after the header. This is handed up to layer 3 (IPv4/IPv6) or
    /// to the ARP parser. It may include padding at the end: layer 2 can't tell
    /// padding from data, but the layer-3 header has its own length and can.
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Parses a frame starting at the destination MAC. Returns `None` if the
    /// buffer is too short for the full header (14 bytes, or 18 with a VLAN tag).
    ///
    /// An empty payload is allowed; the 46-byte minimum is not enforced, because
    /// outgoing frames often appear short in a capture (see the type docs).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let dst = MacAddr::read(&mut c)?;
        let src = MacAddr::read(&mut c)?;
        let mut ether_type = c.read_u16_be()?;

        let mut vlan = None;
        if ether_type == ETHERTYPE_VLAN {
            vlan = Some(VlanTag::from_tci(c.read_u16_be()?));
            ether_type = c.read_u16_be()?;
        }

        let payload = c.read_bytes(c.remaining())?;
        Some(EthernetFrame {
            dst,
            src,
            vlan,
            ether_type,
            payload,
        })
    }

    /// True if this is an IEEE 802.3 frame (length field) rather than Ethernet II.
    ///
    /// 802.3 frames are usually followed by an 802.2 LLC header, which says what's
    /// in the payload. You still see them for Spanning Tree (STP) BPDUs from
    /// switches. osiview labels them but doesn't decode LLC.
    pub fn is_802_3(&self) -> bool {
        self.ether_type < ETHERTYPE_MIN
    }

    /// Writes one row per header field: name, the raw bytes, then what they mean.
    /// `raw` must be the buffer this frame was parsed from.
    ///
    /// It walks `raw` again with a `Cursor` rather than slicing at fixed offsets,
    /// so all the bounds checks stay in `Cursor` and this can never panic. It returns
    /// `None` only if `raw` is shorter than the parsed header, which can't happen
    /// when `raw` is the original buffer.
    fn write_fields(&self, out: &mut String, raw: &[u8]) -> Option<()> {
        let mut c = Cursor::new(raw);
        field(out, "  ", "dst", c.read_bytes(6)?, self.dst);
        field(out, "  ", "src", c.read_bytes(6)?, self.src);
        if let Some(v) = self.vlan {
            field(out, "  ", "tpid", c.read_bytes(2)?, "802.1Q tag follows");
            field(
                out,
                "  ",
                "tci",
                c.read_bytes(2)?,
                format_args!("pcp {} dei {} vid {}", v.pcp, v.dei as u8, v.vid),
            );
        }
        let type_bytes = c.read_bytes(2)?;
        if self.is_802_3() {
            field(
                out,
                "  ",
                "length",
                type_bytes,
                format_args!("802.3 length {}", self.ether_type),
            );
        } else {
            field(
                out,
                "  ",
                "type",
                type_bytes,
                ether_type_name(self.ether_type),
            );
        }
        Some(())
    }
}

/// Writes one row of a field table:
///
/// ```text
/// <indent><name>  <bytes in hex>      <decoded meaning>
///   dst    ff ff ff ff ff ff  ff:ff:ff:ff:ff:ff
/// ```
///
/// The hex column is 17 characters wide, enough for a 6-byte MAC, so values line
/// up. Longer fields just push their meaning further right.
pub(crate) fn field(
    out: &mut String,
    indent: &str,
    name: &str,
    bytes: &[u8],
    meaning: impl fmt::Display,
) {
    let mut hex = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        // Writing to a String can't fail, so the Result is ignored.
        let _ = write!(hex, "{b:02x}");
    }
    let _ = writeln!(out, "{indent}{name:<8} {hex:<17}  {meaning}");
}

/// One-line summary in source → destination order, like tcpdump:
/// `eth 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff, ARP (0x0806), payload 46 bytes`.
impl fmt::Display for EthernetFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "eth {} > {}", self.src, self.dst)?;
        if let Some(v) = self.vlan {
            write!(f, ", vlan {} pcp {}", v.vid, v.pcp)?;
            if v.dei {
                f.write_str(" dei")?;
            }
        }
        if self.is_802_3() {
            write!(f, ", 802.3 length {}", self.ether_type)?;
        } else {
            write!(
                f,
                ", {} (0x{:04x})",
                ether_type_name(self.ether_type),
                self.ether_type
            )?;
        }
        write!(f, ", payload {} bytes", self.payload.len())
    }
}

// ---------------------------------------------------------------------------
// ARP (RFC 826)
// ---------------------------------------------------------------------------

/// ARP hardware type 1: Ethernet (10 Mb, and all later speeds). Others exist, e.g.
/// 6 for IEEE 802 networks and 32 for InfiniBand, but on Ethernet you'll only see 1.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// "Who has IP X? Tell IP Y." Sent to the broadcast MAC. The target hardware
/// address (`tha`) is all zeros, because that's the unknown being asked for.
pub const ARP_OP_REQUEST: u16 = 1;
/// "IP X is at MAC M." Sent unicast back to the requester.
pub const ARP_OP_REPLY: u16 = 2;

/// An ARP packet (RFC 826): how a host finds the MAC address for an IPv4 address
/// on the local network. It's the bridge between layer 3 addresses (IP) and
/// layer 2 addresses (MAC). IPv6 uses Neighbor Discovery over ICMPv6 instead.
///
/// The exchange is:
/// 1. A wants to send to 192.168.0.2, so it broadcasts "who-has 192.168.0.2 tell
///    192.168.0.1".
/// 2. The host that owns 192.168.0.2 replies "192.168.0.2 is-at `<its MAC>`".
/// 3. A caches the answer (see `ip neigh` on Linux) and sends its IP packet.
///
/// Gratuitous ARP is a special case: a host announces its own address, with
/// `spa == tpa`. It's used to detect address conflicts and after failover.
///
/// RFC 826 was designed for any hardware and protocol pair, so the address lengths
/// are in the header (`hlen`, `plen`) rather than fixed. That's why the address
/// fields are slices and not `MacAddr` / `Ipv4Addr`. For Ethernet + IPv4,
/// `hlen = 6`, `plen = 4` and the packet is 28 bytes.
///
/// ARP has no authentication. Anyone on the segment can send a fake reply ("ARP
/// spoofing"), which is a classic way to intercept traffic on a LAN.
///
/// ```text
/// +--------+--------+------+------+--------+
/// | htype  | ptype  | hlen | plen |  oper  |
/// |  (2)   |  (2)   | (1)  | (1)  |  (2)   |
/// +--------+--------+------+------+--------+
/// | sha (hlen) | spa (plen) | tha (hlen) | tpa (plen) |
/// +------------+------------+------------+------------+
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ArpPacket<'a> {
    /// Hardware type: what kind of link layer the hardware addresses are for.
    /// 1 = Ethernet ([`ARP_HTYPE_ETHERNET`]).
    pub htype: u16,
    /// Protocol type: which layer 3 protocol the protocol addresses are for. It
    /// reuses the EtherType numbers, so IPv4 is `0x0800` ([`ETHERTYPE_IPV4`]).
    pub ptype: u16,
    /// Operation: 1 = request, 2 = reply ([`ARP_OP_REQUEST`], [`ARP_OP_REPLY`]).
    /// RARP and InARP use other values.
    pub oper: u16,
    /// Sender hardware address: the MAC of whoever sent this packet.
    pub sha: &'a [u8],
    /// Sender protocol address: the sender's IP. Receivers may cache `spa → sha`
    /// even from requests, which saves a round trip later.
    pub spa: &'a [u8],
    /// Target hardware address: in a request this is zeros (it's what's being
    /// asked); in a reply it's the requester's MAC.
    pub tha: &'a [u8],
    /// Target protocol address: the IP being looked up (request) or the
    /// requester's IP (reply).
    pub tpa: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    /// Parses an ARP packet from an Ethernet payload. The fixed 8-byte header is
    /// read first; `hlen` and `plen` from it then decide how many bytes each
    /// address field takes. Returns `None` if the packet is cut short anywhere.
    /// `hlen` and `plen` are not checked against `htype` and `ptype`, so an odd
    /// combination still parses and prints as hex.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        let htype = c.read_u16_be()?;
        let ptype = c.read_u16_be()?;
        let hlen = c.read_u8()? as usize;
        let plen = c.read_u8()? as usize;
        let oper = c.read_u16_be()?;
        let sha = c.read_bytes(hlen)?;
        let spa = c.read_bytes(plen)?;
        let tha = c.read_bytes(hlen)?;
        let tpa = c.read_bytes(plen)?;
        // Anything left over is Ethernet padding up to the 60-byte minimum frame.
        Some(ArpPacket {
            htype,
            ptype,
            oper,
            sha,
            spa,
            tha,
            tpa,
        })
    }
}

/// Display helper for ARP address fields, whose length is only known at runtime.
/// 6 bytes print as a MAC, 4 bytes as dotted-quad IPv4, and anything else as
/// colon-separated hex.
///
/// Guessing from the length alone is good enough for printing: on real networks
/// 6/4 means Ethernet/IPv4. A stricter decoder would check `htype` and `ptype`.
struct Addr<'a>(&'a [u8]);

impl fmt::Display for Addr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(mac) = <[u8; 6]>::try_from(self.0) {
            return write!(f, "{}", MacAddr(mac));
        }
        if let Ok(ip) = <[u8; 4]>::try_from(self.0) {
            return write!(f, "{}", Ipv4Addr::from(ip));
        }
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// tcpdump-style summary: `arp request who-has <tpa> tell <spa> (<sha>)` or
/// `arp reply <spa> is-at <sha>`. Other operations print their numbers.
impl ArpPacket<'_> {
    /// Writes one row per ARP field, like [`EthernetFrame::write_fields`]. `raw`
    /// must be the Ethernet payload this packet was parsed from. Any Ethernet
    /// padding after the packet is shown as a byte count; the hexdump below the
    /// table shows the actual bytes.
    fn write_fields(&self, out: &mut String, raw: &[u8]) -> Option<()> {
        const IND: &str = "    ";
        let mut c = Cursor::new(raw);

        let htype = match self.htype {
            ARP_HTYPE_ETHERNET => "Ethernet",
            _ => "unknown",
        };
        field(out, IND, "htype", c.read_bytes(2)?, htype);
        field(
            out,
            IND,
            "ptype",
            c.read_bytes(2)?,
            ether_type_name(self.ptype),
        );
        field(
            out,
            IND,
            "hlen",
            c.read_bytes(1)?,
            format_args!("{} bytes", self.sha.len()),
        );
        field(
            out,
            IND,
            "plen",
            c.read_bytes(1)?,
            format_args!("{} bytes", self.spa.len()),
        );
        let oper = match self.oper {
            ARP_OP_REQUEST => "request",
            ARP_OP_REPLY => "reply",
            _ => "unknown",
        };
        field(out, IND, "oper", c.read_bytes(2)?, oper);
        field(
            out,
            IND,
            "sha",
            c.read_bytes(self.sha.len())?,
            Addr(self.sha),
        );
        field(
            out,
            IND,
            "spa",
            c.read_bytes(self.spa.len())?,
            Addr(self.spa),
        );
        field(
            out,
            IND,
            "tha",
            c.read_bytes(self.tha.len())?,
            Addr(self.tha),
        );
        field(
            out,
            IND,
            "tpa",
            c.read_bytes(self.tpa.len())?,
            Addr(self.tpa),
        );

        let pad = c.remaining();
        if pad > 0 {
            let _ = writeln!(out, "{IND}{:<8} ({pad} bytes)", "pad");
        }
        Some(())
    }
}

impl fmt::Display for ArpPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (sha, spa, tpa) = (Addr(self.sha), Addr(self.spa), Addr(self.tpa));
        match self.oper {
            ARP_OP_REQUEST => write!(f, "arp request who-has {tpa} tell {spa} ({sha})"),
            ARP_OP_REPLY => write!(f, "arp reply {spa} is-at {sha}"),
            op => write!(
                f,
                "arp op {op} htype {} ptype 0x{:04x}",
                self.htype, self.ptype
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// The data link layer, implemented as an [`Operate`] layer.
///
/// It's a unit struct (no fields) because layer 2 keeps no state between frames.
/// Live capture state lives in [`Capture`] instead, so decoding (which is pure)
/// stays separate from the socket (which isn't).
pub struct Level2;

impl Level2 {
    /// One line for a frame: the Ethernet summary, then the ARP or IP summary if
    /// there is one, separated by ` | `. This is what `osiview read` and
    /// `osiview capture` print without `-v`.
    /// The frame as one short line per protocol, for the default stacked
    /// display. `rel` carries relative TCP sequence numbers from the flow table.
    pub fn layers(&self, data: &[u8], rel: Option<TcpRel>) -> Vec<LayerLine> {
        let Some(frame) = EthernetFrame::parse(data) else {
            return vec![LayerLine::new(
                2,
                "eth",
                format!("truncated frame, {} bytes", data.len()),
            )];
        };
        let mut text = format!("{} → {}", frame.src, frame.dst);
        if frame.dst == MacAddr::BROADCAST {
            text.push_str(" (broadcast)");
        }
        if let Some(v) = frame.vlan {
            let _ = write!(text, "  vlan {}", v.vid);
        }
        if frame.is_802_3() {
            let _ = write!(text, "  802.3 length {}", frame.ether_type);
        } else {
            let _ = write!(text, "  {}", ether_type_name(frame.ether_type));
        }
        let mut out = vec![LayerLine::new(2, "eth", text)];
        match frame.ether_type {
            ETHERTYPE_ARP => out.push(match ArpPacket::parse(frame.payload) {
                Some(arp) => {
                    let s = arp.to_string();
                    LayerLine::new(2, "arp", s.strip_prefix("arp ").unwrap_or(&s))
                }
                None => LayerLine::new(2, "arp", "truncated"),
            }),
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => out.extend(Level3.layers(frame.payload, rel)),
            _ => {}
        }
        out
    }

    pub fn summary(&self, data: &[u8]) -> String {
        let Some(frame) = EthernetFrame::parse(data) else {
            return format!("truncated frame, {} bytes", data.len());
        };
        let mut s = frame.to_string();
        match frame.ether_type {
            ETHERTYPE_ARP => match ArpPacket::parse(frame.payload) {
                Some(arp) => {
                    let _ = write!(s, " | {arp}");
                }
                None => s.push_str(" | arp (truncated)"),
            },
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                let _ = write!(s, " | {}", Level3.summary(frame.payload));
            }
            _ => {}
        }
        s
    }
}

impl Operate for Level2 {
    /// Decodes one raw frame into text: the Ethernet summary line and field
    /// table; then, indented, ARP or the whole layer 3 decode (IPv4/IPv6 and
    /// ICMP); then a hexdump of the frame. This is pure (no I/O), so it can be
    /// tested with byte arrays and works the same on frames from pcap files.
    fn render(&self, data: &[u8]) -> String {
        let Some(frame) = EthernetFrame::parse(data) else {
            return format!("truncated frame, {} bytes\n{}", data.len(), HexDump(data));
        };

        // Summary line, then the Ethernet field table.
        let mut out = format!("{frame}\n");
        frame.write_fields(&mut out, data);

        match frame.ether_type {
            // ARP: its own summary line and field table, indented one level deeper.
            ETHERTYPE_ARP => match ArpPacket::parse(frame.payload) {
                Some(arp) => {
                    let _ = writeln!(out, "  {arp}");
                    arp.write_fields(&mut out, frame.payload);
                }
                None => out.push_str("  arp (truncated)\n"),
            },
            // IP: hand the payload up to layer 3 and indent what it prints.
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                for line in Level3.render_fields(frame.payload).lines() {
                    let _ = writeln!(out, "  {line}");
                }
            }
            _ => {}
        }

        // Every byte of the frame, so you can check the tables against the raw data.
        let _ = write!(out, "{}", HexDump(data));
        out
    }
}

// ---------------------------------------------------------------------------
// Network interfaces
// ---------------------------------------------------------------------------

/// Looks up an interface's index from its name (`eth0`, `lo`, `en0`, …) with
/// `if_nametoindex(3)`. The kernel identifies interfaces by index, not name,
/// so this is what binding a packet socket needs.
///
/// These interface functions work on macOS too, so `osiview interfaces` runs
/// anywhere.
pub fn interface_index(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains a NUL byte",
        )
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the whole call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: {name} (run `osiview interfaces` to list them)"),
        ));
    }
    Ok(index)
}

/// Looks up an interface's name from its index with `if_indextoname(3)`. Used to
/// label frames when capturing on all interfaces.
pub fn interface_name(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, which is what if_indextoname requires.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: on success, if_indextoname wrote a NUL-terminated name into `buf`.
    Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// One network interface, as listed by `osiview interfaces`.
#[derive(Debug)]
pub struct InterfaceInfo {
    /// Kernel interface index (what `bind` and `sockaddr_ll` use).
    pub index: u32,
    /// Name, e.g. `eth0`.
    pub name: String,
    /// Administratively up (`IFF_UP`).
    pub up: bool,
    /// Loopback (`IFF_LOOPBACK`). On Linux, frames on `lo` still get an Ethernet
    /// header, with all-zero MACs.
    pub loopback: bool,
    /// IPv4 and IPv6 addresses assigned to it.
    pub addrs: Vec<IpAddr>,
}

/// Lists interfaces with `getifaddrs(3)`.
///
/// `getifaddrs` returns a linked list with one entry per *address*, so an
/// interface with an IPv4 and an IPv6 address appears several times. The
/// entries are merged by name here.
pub fn list_interfaces() -> io::Result<Vec<InterfaceInfo>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer. On success it points at a list we
    // must free with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut list: Vec<InterfaceInfo> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list from getifaddrs, which stays valid
        // until freeifaddrs below.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let flags = ifa.ifa_flags as libc::c_int;

        let pos = match list.iter().position(|i| i.name == name) {
            Some(pos) => pos,
            None => {
                list.push(InterfaceInfo {
                    index: interface_index(&name).unwrap_or(0),
                    name,
                    up: flags & libc::IFF_UP != 0,
                    loopback: flags & libc::IFF_LOOPBACK != 0,
                    addrs: Vec::new(),
                });
                list.len() - 1
            }
        };
        // SAFETY: `ifa_addr` is null or points at a sockaddr owned by the list.
        if let Some(addr) = unsafe { sockaddr_ip(ifa.ifa_addr) }
            && let Some(entry) = list.get_mut(pos)
        {
            entry.addrs.push(addr);
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };

    list.sort_by_key(|i| i.index);
    Ok(list)
}

/// The IP address in a `sockaddr`, if it's IPv4 or IPv6. Other families (like
/// Linux's `AF_PACKET` entries, which carry the MAC) give `None`.
///
/// # Safety
/// `sa` must be null or point at a valid `sockaddr` whose real size matches its
/// `sa_family`.
unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `sa` is valid, and the family check decides
    // which larger struct it really is.
    unsafe {
        match libc::c_int::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*sa.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sin6 = &*sa.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Live capture (Linux AF_PACKET)
// ---------------------------------------------------------------------------

/// Receive buffer size. Bigger than any normal frame (1514 bytes), because
/// offloads like GRO can hand up merged "frames" far bigger than the MTU.
#[cfg(target_os = "linux")]
const CAPTURE_BUF_LEN: usize = 65536;

/// One frame from a live capture.
#[derive(Debug)]
pub struct CapturedFrame<'a> {
    /// When the frame was read: wall-clock time taken right after `recvfrom`
    /// returns. (The kernel's own timestamp, via `SO_TIMESTAMP`, would be slightly
    /// more accurate.)
    pub time: Timestamp,
    /// The bytes received. Shorter than `orig_len` only if the frame didn't fit in
    /// the buffer.
    pub data: &'a [u8],
    /// The frame's real length. `recvfrom` with `MSG_TRUNC` returns this even when
    /// the buffer was too small, and the pcap writer records it.
    pub orig_len: usize,
    /// Index of the interface the frame was seen on.
    pub interface_index: u32,
    /// True if this host sent the frame (`PACKET_OUTGOING`). A packet socket sees
    /// both directions.
    pub outgoing: bool,
}

/// A live packet socket: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`.
///
/// - `AF_PACKET` + `SOCK_RAW` gives whole frames, including the Ethernet header.
///   (`SOCK_DGRAM` would strip it.)
/// - `ETH_P_ALL` means every EtherType. It must be in network byte order, hence
///   `.to_be()`, the Rust form of C's `htons`.
/// - Unbound, the socket receives from every interface. Bound (with `bind` and a
///   `sockaddr_ll` holding the interface index) it only gets that interface's
///   frames.
/// - Interfaces without an Ethernet header (a WireGuard or TUN device, for
///   example) are skipped. `sll_hatype` says what kind of header a frame has,
///   and everything downstream, including the pcap link type, assumes Ethernet.
/// - The socket isn't put into promiscuous mode, so on a real NIC you only see
///   frames addressed to this host, plus broadcast and multicast.
///
/// Needs root or `CAP_NET_RAW`. The fd is an `OwnedFd`, closed on drop.
#[cfg(target_os = "linux")]
pub struct Capture {
    fd: std::os::fd::OwnedFd,
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl Capture {
    /// Opens a packet socket, bound to `interface` if one is given.
    ///
    /// Between `socket` and `bind` there's a short window where frames from
    /// other interfaces can be queued. tcpdump drains them; here the first few
    /// frames may come from another interface.
    pub fn open(interface: Option<&str>) -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        // The protocol argument is in network byte order (htons).
        let proto = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: plain syscall with constant arguments.
        let raw =
            unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::c_int::from(proto)) };
        if raw < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(io::Error::new(
                    err.kind(),
                    "opening a packet socket needs root or CAP_NET_RAW",
                ));
            }
            return Err(err);
        }
        // SAFETY: `raw` is a freshly opened, valid fd that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        if let Some(name) = interface {
            let index = interface_index(name)?;
            // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            sll.sll_family = libc::AF_PACKET as libc::c_ushort;
            sll.sll_protocol = proto;
            sll.sll_ifindex = index as libc::c_int;
            // SAFETY: `sll` is a valid sockaddr_ll and the length matches it.
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&sll as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Capture {
            fd,
            buf: vec![0; CAPTURE_BUF_LEN],
        })
    }

    /// Makes [`Capture::next_frame`] give up after `timeout` with an error of
    /// kind `WouldBlock` (`SO_RCVTIMEO`), so a capture thread can check whether
    /// it should stop instead of blocking forever.
    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: `tv` is a valid timeval and the length matches it.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Blocks until the next Ethernet frame arrives. Frames from non-Ethernet
    /// interfaces are skipped. The returned frame borrows the capture's buffer,
    /// so it must be used (or copied) before the next call.
    pub fn next_frame(&mut self) -> io::Result<CapturedFrame<'_>> {
        use std::os::fd::AsRawFd;

        /// `ARPHRD_ETHER` and `ARPHRD_LOOPBACK` from `<linux/if_arp.h>`: the
        /// hardware types whose frames start with an Ethernet header.
        const ARPHRD_ETHER: u16 = 1;
        const ARPHRD_LOOPBACK: u16 = 772;

        loop {
            // SAFETY: plain data; all-zero is a valid value.
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: the buffer and address pointers are valid for the lengths given.
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    libc::MSG_TRUNC,
                    (&mut addr as *mut libc::sockaddr_ll).cast(),
                    &mut addr_len,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if !matches!(addr.sll_hatype, ARPHRD_ETHER | ARPHRD_LOOPBACK) {
                continue;
            }
            let time = Timestamp::now();
            let orig_len = n as usize;
            let data = self.buf.get(..orig_len.min(self.buf.len())).unwrap_or(&[]);
            return Ok(CapturedFrame {
                time,
                data,
                orig_len,
                interface_index: u32::try_from(addr.sll_ifindex).unwrap_or(0),
                outgoing: addr.sll_pkttype == libc::PACKET_OUTGOING,
            });
        }
    }
}

/// Stand-in for non-Linux targets, so the crate (and every decoder test) still
/// builds on macOS. macOS has no `AF_PACKET`; the native equivalent is BPF
/// (`/dev/bpf*`, `man 4 bpf`). `osiview read` works everywhere.
#[cfg(not(target_os = "linux"))]
pub struct Capture {
    _private: (),
}

#[cfg(not(target_os = "linux"))]
impl Capture {
    const UNSUPPORTED: &str =
        "live capture needs Linux AF_PACKET sockets; run osiview in a Linux VM or container";

    /// Always fails, after checking the interface name so typos are still reported.
    pub fn open(interface: Option<&str>) -> io::Result<Self> {
        if let Some(name) = interface {
            interface_index(name)?;
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            Self::UNSUPPORTED,
        ))
    }

    pub fn set_read_timeout(&self, _timeout: std::time::Duration) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            Self::UNSUPPORTED,
        ))
    }

    pub fn next_frame(&mut self) -> io::Result<CapturedFrame<'_>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            Self::UNSUPPORTED,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn arp_request_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // dst: broadcast
        f.extend_from_slice(&SRC); // src
        f.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // htype, ptype, hlen, plen, oper=request
        f.extend_from_slice(&SRC); // sha
        f.extend_from_slice(&[192, 168, 0, 1]); // spa
        f.extend_from_slice(&[0; 6]); // tha
        f.extend_from_slice(&[192, 168, 0, 2]); // tpa
        f.extend_from_slice(&[0; 18]); // padding to 60 bytes
        f
    }

    #[test]
    fn parses_ethernet_header() {
        let data = arp_request_frame();
        let frame = EthernetFrame::parse(&data).unwrap();
        assert_eq!(frame.dst, MacAddr::BROADCAST);
        assert_eq!(frame.src, MacAddr(SRC));
        assert_eq!(frame.vlan, None);
        assert_eq!(frame.ether_type, ETHERTYPE_ARP);
        assert_eq!(frame.payload.len(), 60 - 14);
    }

    #[test]
    fn parses_vlan_tag() {
        let mut data = vec![0xff; 6];
        data.extend_from_slice(&SRC);
        data.extend_from_slice(&[0x81, 0x00, 0x30, 0x64]); // TPID, TCI: pcp 1, dei 1, vid 100
        data.extend_from_slice(&[0x08, 0x00, 0x45]); // IPv4 + 1 payload byte
        let frame = EthernetFrame::parse(&data).unwrap();
        assert_eq!(
            frame.vlan,
            Some(VlanTag {
                pcp: 1,
                dei: true,
                vid: 100
            })
        );
        assert_eq!(frame.ether_type, ETHERTYPE_IPV4);
        assert_eq!(frame.payload, &[0x45]);
    }

    #[test]
    fn truncated_header_is_none() {
        assert_eq!(EthernetFrame::parse(&[0; 13]), None);
        // VLAN TPID present but tag cut off.
        let mut data = vec![0; 12];
        data.extend_from_slice(&[0x81, 0x00, 0x00]);
        assert_eq!(EthernetFrame::parse(&data), None);
    }

    #[test]
    fn detects_802_3_length() {
        let mut data = vec![0; 12];
        data.extend_from_slice(&[0x00, 0x26]); // length 38
        let frame = EthernetFrame::parse(&data).unwrap();
        assert!(frame.is_802_3());
        assert!(frame.to_string().contains("802.3 length 38"));
    }

    #[test]
    fn parses_arp_request() {
        let data = arp_request_frame();
        let frame = EthernetFrame::parse(&data).unwrap();
        let arp = ArpPacket::parse(frame.payload).unwrap();
        assert_eq!(arp.htype, ARP_HTYPE_ETHERNET);
        assert_eq!(arp.ptype, ETHERTYPE_IPV4);
        assert_eq!(arp.oper, ARP_OP_REQUEST);
        assert_eq!(arp.spa, &[192, 168, 0, 1]);
        assert_eq!(arp.tpa, &[192, 168, 0, 2]);
        assert_eq!(
            arp.to_string(),
            "arp request who-has 192.168.0.2 tell 192.168.0.1 (00:11:22:33:44:55)"
        );
    }

    #[test]
    fn truncated_arp_is_none() {
        assert_eq!(
            ArpPacket::parse(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00]),
            None
        );
    }

    #[test]
    fn render_arp_frame() {
        let data = arp_request_frame();
        let out = Level2.render(&data);

        // Compare with runs of spaces collapsed, so the test checks content, not
        // column widths.
        let lines: Vec<String> = out
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        let expected = [
            "eth 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff, ARP (0x0806), payload 46 bytes",
            "dst ff ff ff ff ff ff ff:ff:ff:ff:ff:ff",
            "src 00 11 22 33 44 55 00:11:22:33:44:55",
            "type 08 06 ARP",
            "arp request who-has 192.168.0.2 tell 192.168.0.1 (00:11:22:33:44:55)",
            "htype 00 01 Ethernet",
            "ptype 08 00 IPv4",
            "hlen 06 6 bytes",
            "plen 04 4 bytes",
            "oper 00 01 request",
            "sha 00 11 22 33 44 55 00:11:22:33:44:55",
            "spa c0 a8 00 01 192.168.0.1",
            "tha 00 00 00 00 00 00 00:00:00:00:00:00",
            "tpa c0 a8 00 02 192.168.0.2",
            "pad (18 bytes)",
        ];
        assert_eq!(&lines[..expected.len()], &expected);

        // The rest is the hexdump of the whole frame.
        assert!(out.ends_with(&HexDump(&data).to_string()));
    }

    #[test]
    fn render_vlan_fields() {
        let mut data = vec![0xff; 6];
        data.extend_from_slice(&SRC);
        data.extend_from_slice(&[0x81, 0x00, 0x30, 0x64, 0x08, 0x00]);
        let out = Level2.render(&data);
        let lines: Vec<String> = out
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        assert!(lines.iter().any(|l| l == "tpid 81 00 802.1Q tag follows"));
        assert!(lines.iter().any(|l| l == "tci 30 64 pcp 1 dei 1 vid 100"));
        assert!(lines.iter().any(|l| l == "type 08 00 IPv4"));
    }

    #[test]
    fn render_truncated_frame_hexdumps() {
        let out = Level2.render(&[0xab; 4]);
        assert!(out.starts_with("truncated frame, 4 bytes"));
    }
}
