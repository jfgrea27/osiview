//! TCP connections across packets: the flow table, stream reassembly and the
//! state tracker.
//!
//! Layers 2–4 decode one packet at a time. To say "this is step 2 of the
//! handshake" or to rebuild an HTTP response that arrived in 40 segments, you
//! need memory across packets. This module is that memory:
//!
//! ```text
//! frame ─► Ethernet ─► IP ─► TCP segment ─► Table::observe
//!                                              │
//!                         4-tuple ─► Flow ─────┼─► StateTracker: label ("handshake 2/3")
//!                                              └─► Reassembler (one per direction): byte stream
//! ```
//!
//! It's passive: osiview watches both directions of other programs'
//! connections and never sends anything. So this isn't a TCP stack; it's an
//! *observer* that has to cope with what a capture gives it: segments out of
//! order, duplicated, missing, or a connection that started before the capture did.
//!
//! # Specs
//!
//! - Connection states: RFC 9293 §3.3.2. Sequence numbers and wraparound:
//!   RFC 9293 §3.4. Opening: §3.5. Closing: §3.6.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use crate::display::TcpRel;
use crate::level2::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame};
use crate::level3::{self, IpContext, PROTO_TCP};
use crate::level4::{TcpFlags, TcpSegment};

// ---------------------------------------------------------------------------
// Endpoints and flow keys
// ---------------------------------------------------------------------------

/// One end of a connection: an address and a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

/// `10.0.0.1:51234`, or `[2001:db8::1]:443` for IPv6 (RFC 3986 style, so the
/// port isn't mistaken for part of the address).
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr {
            IpAddr::V4(a) => write!(f, "{a}:{}", self.port),
            IpAddr::V6(a) => write!(f, "[{a}]:{}", self.port),
        }
    }
}

/// The key for a connection. A TCP connection is identified by its 4-tuple
/// (source address, source port, destination address, destination port), but
/// the two directions have those swapped. Storing the two endpoints in sorted
/// order gives both directions the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey(Endpoint, Endpoint);

impl FlowKey {
    fn new(a: Endpoint, b: Endpoint) -> Self {
        if a <= b { FlowKey(a, b) } else { FlowKey(b, a) }
    }
}

/// Which end sent a segment. The client is whoever sent the first SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    fn index(self) -> usize {
        match self {
            Side::Client => 0,
            Side::Server => 1,
        }
    }
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Side::Client => "client",
            Side::Server => "server",
        })
    }
}

// ---------------------------------------------------------------------------
// Reassembler
// ---------------------------------------------------------------------------

/// Out-of-order data waiting for a gap to fill is capped at this many bytes
/// per direction, so a capture with a permanent gap can't use unbounded memory.
const MAX_PENDING: usize = 4 * 1024 * 1024;

/// Each direction's reassembled stream is kept up to this size. Bytes after it
/// are still counted but not stored.
const MAX_STREAM: usize = 64 * 1024 * 1024;

/// Where a segment's data went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// The segment carried no data (a pure ACK, SYN or FIN).
    Empty,
    /// Some or all of the data was new and in order. `new` is how many bytes
    /// were added; fewer than the payload means it overlapped data already received.
    InOrder { new: usize },
    /// The data starts after a gap, so it's held until the gap is filled.
    Buffered,
    /// All of the data had already been received: a retransmission.
    Retransmission,
}

/// Rebuilds one direction of a TCP connection into a contiguous byte stream.
///
/// The core idea: track `next`, the sequence number of the next byte expected.
/// For each segment, compare its sequence number with `next`:
///
/// ```text
///            next
///             │
///   ──────────┼──────────────────────►  sequence space
///   ├──old────┤                          already have: skip these bytes
///             ├──in order──┤             append, advance next
///                            ├─ahead─┤   gap before it: buffer until filled
/// ```
///
/// Sequence numbers wrap at 2^32, so "before" and "after" are judged with
/// wrapping subtraction read as a signed 32-bit number: `seq.wrapping_sub(next)
/// as i32` is negative if `seq` is behind `next`, positive if ahead. That works
/// as long as the two are within 2^31 of each other, which TCP's window rules
/// guarantee (RFC 9293 §3.4).
#[derive(Debug, Default)]
pub struct Reassembler {
    /// Next expected sequence number. `None` until the first SYN or data segment.
    next: Option<u32>,
    /// Segments that arrived ahead of `next`: `(seq, data)`.
    pending: Vec<(u32, Vec<u8>)>,
    pending_bytes: usize,
    stream: Vec<u8>,
    /// Bytes received in order but not stored because of [`MAX_STREAM`], or
    /// dropped because the pending buffer was full.
    pub dropped: usize,
}

impl Reassembler {
    /// The stream so far.
    pub fn stream(&self) -> &[u8] {
        &self.stream
    }

    /// Records a SYN. The SYN uses up one sequence number, so data starts at
    /// `seq + 1`. A SYN seen after data (from a reordered capture) is ignored,
    /// since the stream's start is already fixed.
    pub fn syn(&mut self, seq: u32) {
        if self.next.is_none() {
            self.next = Some(seq.wrapping_add(1));
        }
    }

    /// Adds a segment's data at sequence number `seq`.
    ///
    /// If no SYN was seen (the capture started mid-connection), the first data
    /// segment fixes where the stream starts.
    pub fn push(&mut self, seq: u32, data: &[u8]) -> Placement {
        if data.is_empty() {
            return Placement::Empty;
        }
        let next = *self.next.get_or_insert(seq);
        let distance = seq.wrapping_sub(next) as i32;

        if distance > 0 {
            if self.pending_bytes + data.len() <= MAX_PENDING {
                self.pending_bytes += data.len();
                self.pending.push((seq, data.to_vec()));
            } else {
                self.dropped += data.len();
            }
            return Placement::Buffered;
        }

        // `distance <= 0`: the first `-distance` bytes are ones we already have.
        let skip = distance.unsigned_abs() as usize;
        let Some(fresh) = data.get(skip..).filter(|f| !f.is_empty()) else {
            return Placement::Retransmission;
        };
        let new = fresh.len();
        self.accept(fresh);
        self.drain_pending();
        Placement::InOrder { new }
    }

    /// Appends in-order bytes and advances `next`.
    fn accept(&mut self, bytes: &[u8]) {
        let room = MAX_STREAM.saturating_sub(self.stream.len());
        let keep = bytes.len().min(room);
        self.stream
            .extend_from_slice(bytes.get(..keep).unwrap_or(&[]));
        self.dropped += bytes.len() - keep;
        let next = self.next.unwrap_or(0);
        self.next = Some(next.wrapping_add(bytes.len() as u32));
    }

    /// Moves buffered segments that the latest data has reached into the
    /// stream. Repeats until nothing more fits, since each one may fill the gap
    /// before another.
    fn drain_pending(&mut self) {
        loop {
            let next = self.next.unwrap_or(0);
            let Some(i) = self
                .pending
                .iter()
                .position(|(s, _)| s.wrapping_sub(next) as i32 <= 0)
            else {
                return;
            };
            let (seq, data) = self.pending.swap_remove(i);
            self.pending_bytes -= data.len();
            let skip = next.wrapping_sub(seq) as usize;
            if let Some(fresh) = data.get(skip..).filter(|f| !f.is_empty()) {
                let fresh = fresh.to_vec();
                self.accept(&fresh);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// State tracking
// ---------------------------------------------------------------------------

/// A connection's state as an observer sees it. This is a simplified view of
/// RFC 9293 §3.3.2's diagram. Each real endpoint has its own state (one side
/// is in FIN-WAIT-1 while the other is in CLOSE-WAIT), but from the wire you
/// only see the messages between them, so these states describe the connection
/// as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    /// SYN seen, waiting for SYN-ACK.
    SynSent,
    /// SYN-ACK seen, waiting for the client's ACK.
    SynReceived,
    /// Handshake done (or the capture started mid-connection).
    Established,
    /// One side has sent FIN.
    Closing,
    /// Both sides have sent FIN.
    BothClosed,
    /// Both FINs have been acknowledged.
    Closed,
    /// Ended by RST.
    Reset,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TcpState::SynSent => "SYN sent",
            TcpState::SynReceived => "SYN received",
            TcpState::Established => "established",
            TcpState::Closing => "closing",
            TcpState::BothClosed => "both sides closed",
            TcpState::Closed => "closed",
            TcpState::Reset => "reset",
        })
    }
}

/// One TCP connection.
#[derive(Debug)]
pub struct Flow {
    /// 1-based number, in order of first appearance.
    pub id: usize,
    pub client: Endpoint,
    pub server: Endpoint,
    /// True if a SYN or SYN-ACK showed who the client is. If the capture started
    /// mid-connection, the side with the lower port is assumed to be the server
    /// (servers usually use well-known ports), and this is false.
    pub roles_known: bool,
    pub state: TcpState,
    /// Index 0: client → server. Index 1: server → client.
    streams: [Reassembler; 2],
    fin: [bool; 2],
    /// Each side's initial sequence number: from its SYN, or the first segment
    /// seen if the capture started mid-connection. Used for relative numbers.
    isn: [Option<u32>; 2],
    pub segments: u64,
}

impl Flow {
    /// The reassembled bytes sent by `side`.
    pub fn stream(&self, side: Side) -> &[u8] {
        self.streams[side.index()].stream()
    }

    pub fn dropped(&self, side: Side) -> usize {
        self.streams[side.index()].dropped
    }

    /// `10.0.0.1:51234 -> 93.184.216.34:80`.
    pub fn describe(&self) -> String {
        let guess = if self.roles_known {
            ""
        } else {
            " (roles guessed)"
        };
        format!("{} -> {}{guess}", self.client, self.server)
    }
}

/// What the table made of one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The flow's number ([`Flow::id`]).
    pub flow: usize,
    pub side: Side,
    /// What this segment did: `handshake 1/3 (SYN)`, `data 517 B from client`,
    /// `retransmission 1448 B from server`, `FIN from client`, …
    pub label: String,
    /// Sequence and acknowledgment numbers relative to each side's first
    /// sequence number, as Wireshark shows them.
    pub rel: Option<TcpRel>,
}

/// `flow 3: data 517 B from client`.
impl fmt::Display for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flow {}: {}", self.flow, self.label)
    }
}

/// Every TCP connection seen so far.
#[derive(Debug, Default)]
pub struct Table {
    index: HashMap<FlowKey, usize>,
    flows: Vec<Flow>,
}

impl Table {
    pub fn new() -> Self {
        Self::default()
    }

    /// Flows in order of first appearance.
    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    /// Decodes a frame down to TCP and observes it. Returns `None` for anything
    /// that isn't a complete, unfragmented TCP segment.
    pub fn observe_frame(&mut self, frame: &[u8]) -> Option<Observation> {
        let eth = EthernetFrame::parse(frame)?;
        if !matches!(eth.ether_type, ETHERTYPE_IPV4 | ETHERTYPE_IPV6) {
            return None;
        }
        let (ctx, payload) = level3::transport(eth.payload)?;
        if ctx.protocol != PROTO_TCP {
            return None;
        }
        let seg = TcpSegment::parse(payload)?;
        Some(self.observe(&ctx, &seg))
    }

    /// Updates the flow this segment belongs to and labels the segment.
    pub fn observe(&mut self, ctx: &IpContext, seg: &TcpSegment<'_>) -> Observation {
        let src = Endpoint {
            addr: ctx.src,
            port: seg.src_port,
        };
        let dst = Endpoint {
            addr: ctx.dst,
            port: seg.dst_port,
        };
        let flags = seg.flags;
        let syn = flags.has(TcpFlags::SYN);
        let ack = flags.has(TcpFlags::ACK);

        let key = FlowKey::new(src, dst);
        let id = match self.index.get(&key) {
            Some(&id) => id,
            None => {
                let (client, server, roles_known) = if syn && !ack {
                    (src, dst, true)
                } else if syn && ack {
                    // Missed the SYN: the SYN-ACK comes from the server.
                    (dst, src, true)
                } else if src.port > dst.port {
                    (src, dst, false)
                } else {
                    (dst, src, false)
                };
                let id = self.flows.len() + 1;
                self.flows.push(Flow {
                    id,
                    client,
                    server,
                    roles_known,
                    state: if syn {
                        TcpState::SynSent
                    } else {
                        TcpState::Established
                    },
                    streams: Default::default(),
                    fin: [false, false],
                    isn: [None, None],
                    segments: 0,
                });
                self.index.insert(key, id);
                id
            }
        };

        // `id` came from `self.flows.len() + 1`, so it's always in range.
        let flow = &mut self.flows[id - 1];
        let side = if src == flow.client {
            Side::Client
        } else {
            Side::Server
        };
        flow.segments += 1;
        let dir = side.index();
        let isn = *flow.isn[dir].get_or_insert(seg.seq);
        let rel = TcpRel {
            seq: seg.seq.wrapping_sub(isn),
            ack: if seg.flags.has(TcpFlags::ACK) {
                flow.isn[1 - dir].map(|other| seg.ack.wrapping_sub(other))
            } else {
                None
            },
        };
        let label = label_segment(flow, side, seg);
        Observation {
            flow: id,
            side,
            label,
            rel: Some(rel),
        }
    }
}

/// The state tracker: updates `flow` for one segment from `side` and describes
/// what the segment did.
fn label_segment(flow: &mut Flow, side: Side, seg: &TcpSegment<'_>) -> String {
    let flags = seg.flags;
    let dir = side.index();
    let mut parts: Vec<String> = Vec::new();

    if flags.has(TcpFlags::RST) {
        flow.state = TcpState::Reset;
        return format!("RST from {side}");
    }

    if flags.has(TcpFlags::SYN) {
        flow.streams[dir].syn(seg.seq);
        if flags.has(TcpFlags::ACK) {
            if flow.state == TcpState::SynReceived {
                return "SYN-ACK retransmission".to_string();
            }
            flow.state = TcpState::SynReceived;
            return "handshake 2/3 (SYN-ACK)".to_string();
        }
        if flow.segments > 1 {
            return "SYN retransmission".to_string();
        }
        return "handshake 1/3 (SYN)".to_string();
    }

    // The client's ACK of the SYN-ACK completes the handshake. It may already
    // carry data (TCP allows it).
    if flow.state == TcpState::SynReceived && side == Side::Client && flags.has(TcpFlags::ACK) {
        flow.state = TcpState::Established;
        if seg.payload.is_empty() {
            parts.push("handshake 3/3 (ACK)".to_string());
        }
    }

    let len = seg.payload.len();
    match flow.streams[dir].push(seg.seq, seg.payload) {
        Placement::Empty => {}
        Placement::InOrder { new } if new == len => parts.push(format!("data {len} B from {side}")),
        Placement::InOrder { new } => parts.push(format!(
            "data {len} B from {side} ({} B already received)",
            len - new
        )),
        Placement::Buffered => parts.push(format!("data {len} B from {side}, out of order")),
        Placement::Retransmission => parts.push(format!("retransmission {len} B from {side}")),
    }

    if flags.has(TcpFlags::FIN) {
        if flow.fin[dir] {
            parts.push(format!("FIN retransmission from {side}"));
        } else {
            flow.fin[dir] = true;
            parts.push(format!("FIN from {side}"));
            flow.state = if flow.fin[0] && flow.fin[1] {
                TcpState::BothClosed
            } else {
                TcpState::Closing
            };
        }
    } else if parts.is_empty() && flags.has(TcpFlags::ACK) {
        if flow.state == TcpState::BothClosed {
            flow.state = TcpState::Closed;
            parts.push("final ACK".to_string());
        } else {
            parts.push(format!("ACK from {side}"));
        }
    }

    if parts.is_empty() {
        parts.push(format!("segment from {side}"));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level4::tests::{ctx4, tcp_segment};

    const C: (u16, u16) = (51234, 80);
    const S: (u16, u16) = (80, 51234);

    /// Observes a segment from the client (`from_client`) or server, built with
    /// correct addresses for each direction.
    fn send(
        t: &mut Table,
        from_client: bool,
        seq: u32,
        ack: u32,
        flags: u8,
        data: &[u8],
    ) -> Observation {
        let mut ctx = ctx4(PROTO_TCP);
        let ports = if from_client { C } else { S };
        if !from_client {
            std::mem::swap(&mut ctx.src, &mut ctx.dst);
        }
        let raw = tcp_segment(&ctx, ports, seq, ack, flags, &[], data);
        t.observe(&ctx, &TcpSegment::parse(&raw).unwrap())
    }

    const SYN: u8 = TcpFlags::SYN;
    const ACK: u8 = TcpFlags::ACK;
    const PSH_ACK: u8 = TcpFlags::PSH | TcpFlags::ACK;
    const FIN_ACK: u8 = TcpFlags::FIN | TcpFlags::ACK;

    #[test]
    fn labels_a_whole_connection() {
        let mut t = Table::new();
        let labels: Vec<String> = [
            send(&mut t, true, 100, 0, SYN, b""),
            send(&mut t, false, 900, 101, SYN | ACK, b""),
            send(&mut t, true, 101, 901, ACK, b""),
            send(&mut t, true, 101, 901, PSH_ACK, b"GET / HTTP/1.1\r\n\r\n"),
            send(&mut t, false, 901, 119, ACK, b""),
            send(&mut t, false, 901, 119, PSH_ACK, b"HTTP/1.1 200 OK\r\n\r\n"),
            send(&mut t, false, 901, 119, PSH_ACK, b"HTTP/1.1 200 OK\r\n\r\n"),
            send(&mut t, true, 119, 920, FIN_ACK, b""),
            send(&mut t, false, 920, 120, FIN_ACK, b""),
            send(&mut t, true, 120, 921, ACK, b""),
        ]
        .into_iter()
        .map(|o| o.label)
        .collect();

        assert_eq!(
            labels,
            [
                "handshake 1/3 (SYN)",
                "handshake 2/3 (SYN-ACK)",
                "handshake 3/3 (ACK)",
                "data 18 B from client",
                "ACK from server",
                "data 19 B from server",
                "retransmission 19 B from server",
                "FIN from client",
                "FIN from server",
                "final ACK",
            ]
        );
        let flow = &t.flows()[0];
        assert_eq!(flow.state, TcpState::Closed);
        assert!(flow.roles_known);
        assert_eq!(flow.stream(Side::Client), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(flow.stream(Side::Server), b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(flow.describe(), "10.0.0.1:51234 -> 93.184.216.34:80");
    }

    #[test]
    fn relative_sequence_numbers() {
        let mut t = Table::new();
        let syn = send(&mut t, true, 1000, 0, SYN, b"");
        assert_eq!(syn.rel, Some(TcpRel { seq: 0, ack: None }));
        let synack = send(&mut t, false, 5000, 1001, SYN | ACK, b"");
        assert_eq!(
            synack.rel,
            Some(TcpRel {
                seq: 0,
                ack: Some(1)
            })
        );
        let data = send(&mut t, true, 1001, 5001, PSH_ACK, b"hi");
        assert_eq!(
            data.rel,
            Some(TcpRel {
                seq: 1,
                ack: Some(1)
            })
        );
    }

    #[test]
    fn both_directions_share_one_flow() {
        let mut t = Table::new();
        let a = send(&mut t, true, 1, 0, SYN, b"");
        let b = send(&mut t, false, 1, 2, SYN | ACK, b"");
        assert_eq!(a.flow, b.flow);
        assert_eq!(a.side, Side::Client);
        assert_eq!(b.side, Side::Server);
        assert_eq!(t.flows().len(), 1);
    }

    #[test]
    fn mid_stream_capture_guesses_roles() {
        let mut t = Table::new();
        let o = send(&mut t, false, 5000, 10, PSH_ACK, b"hello");
        assert_eq!(o.side, Side::Server);
        assert_eq!(o.label, "data 5 B from server");
        assert!(!t.flows()[0].roles_known);
    }

    #[test]
    fn out_of_order_and_overlap_labels() {
        let mut t = Table::new();
        send(&mut t, true, 0, 0, SYN, b"");
        assert_eq!(
            send(&mut t, true, 6, 0, ACK, b"world").label,
            "data 5 B from client, out of order"
        );
        assert_eq!(
            send(&mut t, true, 1, 0, ACK, b"hello").label,
            "data 5 B from client"
        );
        assert_eq!(t.flows()[0].stream(Side::Client), b"helloworld");
        assert_eq!(
            send(&mut t, true, 9, 0, ACK, b"ld!!").label,
            "data 4 B from client (2 B already received)"
        );
        assert_eq!(t.flows()[0].stream(Side::Client), b"helloworld!!");
    }

    #[test]
    fn reset_ends_the_flow() {
        let mut t = Table::new();
        send(&mut t, true, 0, 0, SYN, b"");
        assert_eq!(
            send(&mut t, false, 0, 1, TcpFlags::RST | ACK, b"").label,
            "RST from server"
        );
        assert_eq!(t.flows()[0].state, TcpState::Reset);
    }

    #[test]
    fn reassembly_handles_sequence_wraparound() {
        let mut r = Reassembler::default();
        r.syn(u32::MAX - 2); // data starts at MAX - 1
        assert_eq!(r.push(u32::MAX - 1, b"ab"), Placement::InOrder { new: 2 });
        assert_eq!(r.push(0, b"cd"), Placement::InOrder { new: 2 }); // wrapped
        assert_eq!(r.stream(), b"abcd");
        assert_eq!(r.push(u32::MAX, b"bc"), Placement::Retransmission);
    }

    /// A small deterministic PRNG (xorshift64), so the property test needs no
    /// extra crates and every failure is reproducible from its seed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// The reassembly property: shuffle, duplicate and overlap segments, and the
    /// output stream is the same. The ISN is near 2^32 so the stream wraps.
    #[test]
    fn reassembly_property_shuffled_duplicated_overlapping() {
        for seed in 1..=200u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let len = 1 + rng.below(5000);
            let original: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let isn = u32::MAX - rng.below(3000) as u32;

            // Segments covering the whole stream...
            let mut segments: Vec<(usize, usize)> = Vec::new();
            let mut at = 0;
            while at < len {
                let n = 1 + rng.below(1460).min(len - at - 1);
                segments.push((at, at + n));
                at += n;
            }
            // ...plus duplicates of some of them and random overlapping ranges.
            for _ in 0..rng.below(10) {
                let s = segments[rng.below(segments.len())];
                segments.push(s);
            }
            for _ in 0..rng.below(10) {
                let a = rng.below(len);
                let b = a + 1 + rng.below(len - a);
                segments.push((a, b));
            }
            // Fisher–Yates shuffle.
            for i in (1..segments.len()).rev() {
                segments.swap(i, rng.below(i + 1));
            }

            let mut r = Reassembler::default();
            r.syn(isn);
            for (a, b) in segments {
                let seq = isn.wrapping_add(1).wrapping_add(a as u32);
                r.push(seq, &original[a..b]);
            }
            assert_eq!(r.stream(), &original[..], "seed {seed}");
            assert!(r.pending.is_empty(), "seed {seed}");
        }
    }
}
