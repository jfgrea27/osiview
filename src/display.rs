//! How packets are shown on the terminal.
//!
//! Three styles:
//!
//! - **Stack** (default): a header line per packet, then one short line per
//!   layer, colour-coded by OSI layer:
//!
//!   ```text
//!   #7   +12.905 ms  →  flow 1 · handshake 3/3 (ACK)
//!        L2 eth     9a:ad:8e:ec:a4:e8 → 32:69:d9:1e:2d:58  IPv4
//!        L3 ipv4    172.17.0.5 → 172.66.147.243  ttl 64  52 B  DF
//!        L4 tcp     51878 → 80 (http)  [ACK]  seq 1 ack 1  win 502  0 B
//!   ```
//!
//! - **One line** (`--oneline`): every layer's summary on one line, joined by `|`.
//! - **Full** (`-v`): field tables for every layer, then a hexdump.
//!
//! Colour is used only when stdout is a terminal and `NO_COLOR` isn't set
//! (no-color.org), so piped output and tests stay plain text.

use std::io::IsTerminal as _;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::flow::{Observation, Side};
use crate::level2::{ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame, Level2};
use crate::level3::{self, Icmp, IcmpVersion, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::level4::{TcpSegment, UdpDatagram};
use crate::pcap::Timestamp;

use crate::base_level::Operate as _;

static COLOR: AtomicBool = AtomicBool::new(false);

/// Turns colour on if stdout is a terminal and `NO_COLOR` is unset or empty.
pub fn init_color() {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    COLOR.store(
        std::io::stdout().is_terminal() && !no_color,
        Ordering::Relaxed,
    );
}

/// Wraps `text` in an ANSI SGR code (`1` bold, `2` dim, `31` red, …) if colour
/// is on.
pub fn paint(text: &str, code: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// The colour for each OSI layer, so the eye can follow one layer down a list.
fn layer_color(layer: u8) -> &'static str {
    match layer {
        2 => "34",     // blue
        3 => "36",     // cyan
        4 => "32",     // green
        5 | 6 => "35", // magenta
        7 => "33",     // yellow
        _ => "0",
    }
}

/// TCP sequence numbers relative to the start of each direction (from the
/// flow table), so they read `seq 1 ack 1` instead of `seq 2199386899 ack
/// 421545652`. The ISN is random (RFC 9293 §3.4.1), so the raw values carry no
/// meaning; only differences do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpRel {
    pub seq: u32,
    /// `None` if the ACK flag isn't set or the other side's ISN isn't known.
    pub ack: Option<u32>,
}

/// One protocol's line in the stacked view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerLine {
    /// OSI layer number, 2–7.
    pub layer: u8,
    /// Short protocol name: `eth`, `arp`, `ipv4`, `tcp`, `dns`, `http`, …
    pub proto: &'static str,
    pub text: String,
    /// Something wrong with this layer, e.g. a bad checksum.
    pub warning: Option<String>,
}

impl LayerLine {
    pub fn new(layer: u8, proto: &'static str, text: impl Into<String>) -> Self {
        LayerLine {
            layer,
            proto,
            text: text.into(),
            warning: None,
        }
    }

    /// Adds `warning` if `bad` is true.
    pub fn warn_if(mut self, bad: bool, warning: &str) -> Self {
        if bad {
            self.warning = Some(warning.to_string());
        }
        self
    }
}

/// Which display style to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Stack,
    OneLine,
    Full,
}

impl Style {
    pub fn from_flags(verbose: bool, oneline: bool) -> Self {
        if verbose {
            Style::Full
        } else if oneline {
            Style::OneLine
        } else {
            Style::Stack
        }
    }
}

/// What's known about where a frame came from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Origin<'a> {
    /// `Some(true)` if this host sent it (live capture only).
    pub outgoing: Option<bool>,
    /// The interface, when capturing on all of them.
    pub interface: Option<&'a str>,
    /// Extra text for the header, e.g. "(truncated: 60 of 1514 bytes)".
    pub note: Option<&'a str>,
}

/// Prints packets one after another in a chosen style, numbering them and
/// showing time relative to the first.
pub struct Printer {
    style: Style,
    /// Also print each packet's application payload (`--payload`).
    payload: bool,
    first: Option<Timestamp>,
    count: usize,
}

impl Printer {
    pub fn new(style: Style) -> Self {
        Printer {
            style,
            payload: false,
            first: None,
            count: 0,
        }
    }

    pub fn style(&self) -> Style {
        self.style
    }

    /// Show payloads under the layer lines (stacked style only; `-v` already
    /// hexdumps the whole frame).
    pub fn with_payload(mut self, on: bool) -> Self {
        self.payload = on;
        self
    }

    /// The first packet's time in full; later ones as `+12.345 ms` since then.
    fn time(&mut self, t: Timestamp) -> String {
        match self.first {
            None => {
                self.first = Some(t);
                t.to_string()
            }
            Some(first) => format_offset(t.micros_since(first)),
        }
    }

    pub fn print(
        &mut self,
        time: Timestamp,
        origin: Origin<'_>,
        data: &[u8],
        obs: Option<&Observation>,
    ) {
        self.count += 1;
        let n = self.count;
        let when = self.time(time);
        let arrow = match (origin.outgoing, obs.map(|o| o.side)) {
            (Some(true), _) | (None, Some(Side::Client)) => "→",
            (Some(false), _) | (None, Some(Side::Server)) => "←",
            _ => " ",
        };
        let iface = origin
            .interface
            .map(|i| format!("{i} "))
            .unwrap_or_default();
        let note = origin.note.map(|n| format!("  {n}")).unwrap_or_default();

        match self.style {
            Style::OneLine => {
                let flow = obs.map(|o| format!(" | {o}")).unwrap_or_default();
                println!("{when} {iface}{arrow} {}{flow}{note}", Level2.summary(data));
            }
            Style::Full | Style::Stack => {
                let rel = obs.and_then(|o| o.rel);
                let layers = Level2.layers(data, rel);
                let headline = match (obs, layers.last()) {
                    (Some(o), _) => format!("flow {} · {}", o.flow, o.label),
                    (None, Some(top)) => format!("{} {}", top.proto, top.text),
                    (None, None) => String::new(),
                };
                println!(
                    "{} {}  {iface}{arrow}  {}{note}",
                    paint(&format!("#{n:<4}"), "2"),
                    paint(&format!("{when:<15}"), "2"),
                    paint(&headline, "1")
                );
                if self.style == Style::Full {
                    println!("{}", Level2.render(data));
                    return;
                }
                for l in &layers {
                    print_layer(l, origin.outgoing == Some(true));
                }
                if self.payload
                    && let Some((what, bytes)) = payload_of(data)
                    && !bytes.is_empty()
                {
                    print!("{}", format_payload(what, bytes));
                }
            }
        }
    }
}

/// One layer line: `     L4 tcp     51878 → 80 …  checksum BAD`.
fn print_layer(l: &LayerLine, outgoing: bool) {
    let tag = paint(
        &format!("L{} {:<6}", l.layer, l.proto),
        layer_color(l.layer),
    );
    let warning = match &l.warning {
        // Linux captures sent frames before the NIC computes transport
        // checksums, so on outgoing frames a bad one is expected.
        Some(w) if outgoing && w.starts_with("checksum") => {
            format!("  {}", paint("(checksum offload)", "2"))
        }
        Some(w) => format!("  {}", paint(w, "31")),
        None => String::new(),
    };
    println!("      {tag} {}{warning}", l.text);
}

/// `+12.345 ms`, or `+1.234 s` past a second.
pub fn format_offset(micros: i64) -> String {
    if micros.abs() >= 1_000_000 {
        format!("+{:.3} s", micros as f64 / 1e6)
    } else {
        format!("+{:.3} ms", micros as f64 / 1e3)
    }
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// The innermost payload of a frame, with what it is: the TCP or UDP data
/// (what the application sent), or the data in an ICMP echo. `None` for frames
/// that carry nothing above their headers, like ARP.
pub fn payload_of(frame: &[u8]) -> Option<(&'static str, &[u8])> {
    let eth = EthernetFrame::parse(frame)?;
    if !matches!(eth.ether_type, ETHERTYPE_IPV4 | ETHERTYPE_IPV6) {
        return None;
    }
    let (ctx, l4) = level3::transport(eth.payload)?;
    match ctx.protocol {
        PROTO_TCP => TcpSegment::parse(l4).map(|s| ("tcp payload", s.payload)),
        PROTO_UDP => UdpDatagram::parse(l4).map(|d| ("udp payload", d.payload)),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let version = if ctx.protocol == PROTO_ICMP {
                IcmpVersion::V4
            } else {
                IcmpVersion::V6
            };
            Icmp::parse(version, l4).map(|i| ("icmp data", i.body))
        }
        _ => None,
    }
}

/// True for bytes that read as text: printable ASCII, tab, CR, LF.
fn is_text(b: u8) -> bool {
    matches!(b, b' '..=b'~' | b'\t' | b'\r' | b'\n')
}

/// A payload for the terminal, indented under the layer lines with a `│`
/// gutter. A text prefix (such as HTTP headers) is shown as text, line by line;
/// whatever follows (a gzip body, TLS, DNS) is shown as a hexdump whose offsets
/// carry on from the end of the text, so they still match the payload.
pub fn format_payload(what: &str, bytes: &[u8]) -> String {
    let text_len = bytes
        .iter()
        .position(|&b| !is_text(b))
        .unwrap_or(bytes.len());
    // A few printable bytes at the start of binary data are a coincidence, not
    // text; only treat it as text if it's a decent run or the whole payload.
    let text_len = if text_len == bytes.len() || text_len >= 16 {
        text_len
    } else {
        0
    };
    let (text, binary) = bytes.split_at(text_len);

    let kind = match (text.is_empty(), binary.is_empty()) {
        (false, true) => "text",
        (true, false) => "binary",
        _ => "text, then binary",
    };
    let gutter = paint("│", "2");
    let mut out = format!(
        "      {}\n",
        paint(&format!("{what} · {} B · {kind}", bytes.len()), "2")
    );
    if !text.is_empty() {
        let s = String::from_utf8_lossy(text);
        for line in s.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            out.push_str(&format!("      {gutter} {line}\n"));
        }
        // A payload ending in a newline gives an empty last line; drop it.
        if s.ends_with('\n') {
            let cut = out.trim_end_matches('\n').rfind('\n').map_or(0, |i| i + 1);
            out.truncate(cut);
        }
    }
    for line in hexdump_from(binary, text_len).lines() {
        out.push_str(&format!("      {gutter} {}\n", paint(line, "2")));
    }
    out
}

/// A hexdump like [`crate::cursor::HexDump`], but with offsets starting at
/// `base`, for a dump that continues after a text section.
fn hexdump_from(data: &[u8], base: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x} ", base + i * 16));
        for j in 0..16 {
            if j % 8 == 0 {
                out.push(' ');
            }
            match chunk.get(j) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
        }
        out.push_str(" |");
        for &b in chunk {
            out.push(if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Ladder diagrams
// ---------------------------------------------------------------------------

/// One arrow in a ladder diagram.
pub struct Rung {
    /// True for left → right (client to server).
    pub to_right: bool,
    pub label: String,
    /// Shown in the left margin, e.g. `+12.905 ms`.
    pub time: String,
}

/// Width between the two vertical lines.
const LADDER_WIDTH: usize = 50;

/// A sequence diagram of messages between two endpoints, the classic way to
/// draw a TCP exchange:
///
/// ```text
///               172.17.0.5:51878                       172.66.147.243:80
///    +0.000 ms  │──────────────────── SYN ──────────────────▶│
///   +12.871 ms  │◀────────────────── SYN-ACK ────────────────│
/// ```
pub fn ladder(left: &str, right: &str, rungs: &[Rung]) -> String {
    let mut out = String::new();
    let margin = 12;
    let total = LADDER_WIDTH + 2;
    let gap = total
        .saturating_sub(left.chars().count() + right.chars().count())
        .max(1);
    out.push_str(&format!(
        "{:margin$}  {}{}{}\n",
        "",
        paint(left, "1"),
        " ".repeat(gap),
        paint(right, "1")
    ));
    for r in rungs {
        let max_label = LADDER_WIDTH - 6;
        let mut label: String = r.label.chars().take(max_label).collect();
        if r.label.chars().count() > max_label {
            label.pop();
            label.push('…');
        }
        let label = format!(" {label} ");
        let dashes = LADDER_WIDTH - label.chars().count() - 1;
        let (l, rt) = (dashes / 2, dashes - dashes / 2);
        let line = if r.to_right {
            format!("{}{}{}▶", "─".repeat(l), paint(&label, "1"), "─".repeat(rt))
        } else {
            format!("◀{}{}{}", "─".repeat(l), paint(&label, "1"), "─".repeat(rt))
        };
        // Pad before painting: the colour codes are invisible but would count
        // towards the width, and the rails wouldn't line up.
        let time = format!("{:>margin$}", r.time);
        out.push_str(&format!("{}  │{line}│\n", paint(&time, "2")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets() {
        assert_eq!(format_offset(0), "+0.000 ms");
        assert_eq!(format_offset(12_905), "+12.905 ms");
        assert_eq!(format_offset(2_500_000), "+2.500 s");
    }

    #[test]
    fn payload_text_then_binary() {
        let mut p = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        let text_len = p.len();
        p.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0xff]);
        let out = format_payload("tcp payload", &p);
        assert!(out.contains(&format!("tcp payload · {} B · text, then binary", p.len())));
        assert!(out.contains("│ HTTP/1.1 200 OK\n"));
        assert!(out.contains("│ Content-Encoding: gzip\n"));
        // The hexdump offset continues from the end of the text.
        assert!(out.contains(&format!("{text_len:08x}  1f 8b 08 00 ff")));
    }

    #[test]
    fn payload_binary_and_text_only() {
        let out = format_payload("udp payload", &[0x7b, 0x76, 0x01, 0x00]);
        assert!(out.contains("4 B · binary"));
        assert!(out.contains("00000000  7b 76 01 00"));
        let out = format_payload("tcp payload", b"hello\n");
        assert!(out.contains("6 B · text"));
        assert!(out.trim_end().ends_with("│ hello"));
    }

    #[test]
    fn ladder_rungs_have_equal_width() {
        let d = ladder(
            "client",
            "server",
            &[
                Rung {
                    to_right: true,
                    label: "SYN".into(),
                    time: "+0.000 ms".into(),
                },
                Rung {
                    to_right: false,
                    label: "a very long label that must be cut down to fit the ladder".into(),
                    time: "+1.000 ms".into(),
                },
            ],
        );
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("─ SYN ─") && lines[1].ends_with("▶│"));
        assert!(lines[2].contains("◀─") && lines[2].contains('…'));
        assert_eq!(lines[1].chars().count(), lines[2].chars().count());
    }
}
