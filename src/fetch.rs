//! The end-to-end run: `osiview http://example.com` or `osiview https://example.com`.
//!
//! osiview makes a request itself and shows every packet that request caused,
//! decoded from layer 2 up to layer 7.
//!
//! ```text
//! 1. open a packet socket   (layer 2: so nothing that follows is missed)
//! 2. resolve the host       (layer 7 DNS: osiview's own query, over UDP; no getaddrinfo)
//! 3. connect + GET          (layer 4 TCP via the kernel's stack, std::net::TcpStream;
//!                           for https, TLS 1.3 on top via rustls, which hands us its secrets)
//! 4. stop capturing
//! 5. keep only the packets of *this* DNS lookup and *this* TCP connection
//! 6. print each one, L2 → L7, with flow labels (handshake 1/3, data, FIN, …)
//! 7. rebuild the HTTP response from the captured segments and compare it with
//!    what the socket actually received
//! ```
//!
//! Step 7 is the proof that layers 2–4 are right: if the reassembled bytes
//! equal the bytes the kernel delivered to the socket, every segment was
//! decoded and put back in the right order.
//!
//! Capture runs on all interfaces in a background thread. The socket is opened
//! *before* anything is sent, so the kernel queues every frame from then on,
//! even before the thread starts reading.
//!
//! # HTTPS
//!
//! osiview doesn't have its own TLS client. For `https://` URLs, `rustls` makes
//! the request, the same way curl would. rustls is only the *client*: it never
//! sees the capture. The decoding is the same code `osiview follow --keylog`
//! runs:
//!
//! ```text
//!   rustls ── TLS 1.3 bytes on the wire ──► capture ──► L2–L4, reassembly
//!     │                                                    │
//!     └── KeyLog callback: traffic secrets ──► level5::KeyLog
//!                                                          ▼
//!                                level5::analyse: handshake, keys, decryption
//!                                                          ▼
//!                                level7: HTTP response, rebuilt from ciphertext
//! ```
//!
//! rustls's `KeyLog` trait is the in-process version of `SSLKEYLOGFILE`: rustls
//! calls it with each secret as it derives it. osiview collects the lines in
//! memory, in the keylog file format, and parses them back with the same
//! [`crate::level5::KeyLog`] that reads files. `--keylog FILE` saves them too,
//! so a `-w` capture can be decrypted again later with `osiview follow`.
//!
//! The client offers only TLS 1.3 (osiview decrypts nothing older) and only
//! ALPN `http/1.1` (osiview doesn't decode HTTP/2 yet). The final check is the same as
//! for plain HTTP, one layer up: the response decrypted from the *captured*
//! records must equal the plaintext rustls handed the program.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::cursor::Cursor;
use crate::display::{Origin, Printer, Rung, Style, format_offset, ladder, paint};
use crate::flow::{Side, Table};
use crate::level2::{Capture, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame};
use crate::level3::{self, PROTO_TCP, PROTO_UDP};
use crate::level4::{TcpFlags, TcpSegment, UdpDatagram};
use crate::level5::{self, TlsRecord};
use crate::level7::{self, DNS_A, DnsMessage, HttpSegment, RData};
use crate::pcap::{self, Timestamp};

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

/// The parts of an `http://` or `https://` URL needed to make a request
/// (RFC 3986 §3, just scheme, host, port and path).
#[derive(Debug, PartialEq, Eq)]
pub struct Url {
    /// `https://`: speak TLS on the connection.
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (tls, rest) = if let Some(rest) = s.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = s.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(format!("not an http:// or https:// URL: {s}"));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        // An IPv6 literal is written in brackets: http://[2001:db8::1]:8080/
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("unclosed [ in URL")?;
            (h, after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err(format!("no host in URL: {s}"));
        }
        let port = match port {
            Some(p) => p.parse().map_err(|_| format!("bad port: {p}"))?,
            None => Self::default_port(tls),
        };
        Ok(Url {
            tls,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// 443 for https, 80 for http (RFC 9110 §4.2.1, §4.2.2).
    fn default_port(tls: bool) -> u16 {
        if tls { 443 } else { 80 }
    }

    fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }

    /// The `Host` header value: the host, plus the port if it isn't the
    /// scheme's default.
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == Self::default_port(self.tls) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

// ---------------------------------------------------------------------------
// DNS client
// ---------------------------------------------------------------------------

/// The first `nameserver` line in `/etc/resolv.conf`: the resolver the system
/// is configured to use. (In a Colima container it's the VM's DNS forwarder.)
pub fn system_resolver() -> io::Result<IpAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf")?;
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .find_map(|addr| addr.trim().parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no nameserver in /etc/resolv.conf"))
}

/// The result of a lookup, including the two endpoints of the DNS exchange so
/// its packets can be picked out of the capture.
pub struct Resolution {
    pub server: SocketAddr,
    pub local: SocketAddr,
    pub addrs: Vec<IpAddr>,
}

/// A query ID. RFC 5452 says it should be unpredictable, so off-path attackers
/// can't forge answers; this mixes the clock and process ID, which is enough
/// for a tool that sends one query, though not for a real resolver.
fn query_id() -> u16 {
    let t = Timestamp::now();
    (t.nanos ^ (t.secs as u32) ^ std::process::id().rotate_left(16)) as u16
}

/// Resolves `name` to IPv4 addresses with osiview's own DNS code: builds the
/// query (layer 7), sends it in a UDP datagram to the system resolver, and
/// parses the answer. Retries up to 3 times, since UDP can lose packets.
pub fn resolve(name: &str) -> io::Result<Resolution> {
    let server = SocketAddr::new(system_resolver()?, 53);
    let sock = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    sock.connect(server)?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let local = sock.local_addr()?;

    let id = query_id();
    let query = level7::build_query(id, name, DNS_A).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a valid DNS name: {name}"),
        )
    })?;
    let mut buf = [0u8; 4096];
    for _ in 0..3 {
        sock.send(&query)?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let Some(msg) = buf.get(..n).and_then(DnsMessage::parse) else {
            continue;
        };
        if msg.id != id || !msg.is_response() {
            continue; // not the answer to our question
        }
        if msg.flags & 0x0200 != 0 {
            return Err(io::Error::other(
                "DNS answer truncated (DNS over TCP isn't implemented)",
            ));
        }
        if msg.rcode() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{name}: {}", level7::dns_rcode_name(msg.rcode())),
            ));
        }
        // CNAMEs are followed by the resolver; their A records come after them.
        let addrs: Vec<IpAddr> = msg
            .answers
            .iter()
            .filter_map(|r| match r.data {
                RData::A(a) => Some(IpAddr::V4(a)),
                _ => None,
            })
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{name} has no A records"),
            ));
        }
        return Ok(Resolution {
            server,
            local,
            addrs,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("no answer from {server}"),
    ))
}

// ---------------------------------------------------------------------------
// TLS client (rustls), for https:// only
// ---------------------------------------------------------------------------

/// Collects the secrets rustls derives, as keylog-file text.
///
/// rustls calls [`rustls::KeyLog::log`] once per secret, from inside the
/// handshake, with a label such as `SERVER_HANDSHAKE_TRAFFIC_SECRET`, the
/// ClientHello random (which identifies the connection) and the secret. One
/// line per call is exactly the `SSLKEYLOGFILE` format
/// (draft-ietf-tls-keylogfile), so [`level5::KeyLog::parse`] can read it back.
#[derive(Debug, Default)]
struct MemoryKeyLog(Mutex<String>);

impl rustls::KeyLog for MemoryKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        // A poisoned lock means another thread panicked mid-write; the text is
        // still usable, so keep going rather than lose the secret.
        let mut text = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(text, "{label} {} {}", hex(client_random), hex(secret));
    }

    /// Ask for every secret, not just the ones a file would usually get.
    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The rustls client settings:
///
/// - **TLS 1.3 only.** osiview's decryptor implements the TLS 1.3 key schedule;
///   a TLS 1.2 connection would be captured but stay opaque.
/// - **ALPN `http/1.1` only** (RFC 7301). Without it, most servers pick `h2`,
///   and osiview doesn't decode HTTP/2's binary framing yet.
/// - **Certificates checked** against the Mozilla root store
///   (`webpki-roots`), as any real client would. osiview decodes the chain
///   itself afterwards (layer 6); rustls's check is just so the request is a
///   normal, trusted one.
fn tls_config(keylog: Arc<MemoryKeyLog>) -> io::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.key_log = keylog;
    Ok(Arc::new(config))
}

/// Reads until the server is done. With `Connection: close` that's when it
/// closes the connection. A well-behaved server sends a TLS `close_notify`
/// alert first (RFC 8446 §6.1), which rustls reports as a clean EOF. Some just
/// close the TCP connection; rustls then says `UnexpectedEof`, because an
/// attacker could truncate a response that way. Here the HTTP framing
/// (Content-Length or the last chunk) still tells us whether the body is
/// whole, so the data read so far is kept.
fn read_until_close(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    match stream.read_to_end(&mut data) {
        Ok(_) => Ok(data),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !data.is_empty() => {
            eprintln!("osiview: server closed without a TLS close_notify");
            Ok(data)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Background capture
// ---------------------------------------------------------------------------

/// A captured frame, copied out of the capture buffer so it outlives it.
struct OwnedFrame {
    time: Timestamp,
    data: Vec<u8>,
    orig_len: usize,
    outgoing: bool,
}

type CaptureThread = thread::JoinHandle<io::Result<Vec<OwnedFrame>>>;

/// Opens the packet socket now, and reads from it on a thread until `stop` is
/// set. The 100 ms read timeout is what lets the thread notice `stop`.
fn start_capture() -> io::Result<(Arc<AtomicBool>, CaptureThread)> {
    let mut cap = Capture::open(None)?;
    cap.set_read_timeout(Duration::from_millis(100))?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let mut frames = Vec::new();
        while !flag.load(Ordering::Relaxed) {
            match cap.next_frame() {
                Ok(f) => frames.push(OwnedFrame {
                    time: f.time,
                    data: f.data.to_vec(),
                    orig_len: f.orig_len,
                    outgoing: f.outgoing,
                }),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(frames)
    });
    Ok((stop, handle))
}

/// A transport conversation to keep: protocol and the two endpoints.
type Conversation = (u8, SocketAddr, SocketAddr);

/// The protocol and endpoints of a frame's TCP or UDP layer.
fn endpoints(frame: &[u8]) -> Option<Conversation> {
    let eth = EthernetFrame::parse(frame)?;
    if !matches!(eth.ether_type, ETHERTYPE_IPV4 | ETHERTYPE_IPV6) {
        return None;
    }
    let (ctx, payload) = level3::transport(eth.payload)?;
    let mut c = Cursor::new(payload);
    let (sp, dp) = (c.read_u16_be()?, c.read_u16_be()?);
    Some((
        ctx.protocol,
        SocketAddr::new(ctx.src, sp),
        SocketAddr::new(ctx.dst, dp),
    ))
}

/// True if a frame is part of one of our conversations, in either direction.
/// ARP is kept too: it's often the very first thing a request causes (finding
/// the gateway's MAC), and it has no ports to match on.
fn belongs(frame: &[u8], ours: &[Conversation]) -> bool {
    if EthernetFrame::parse(frame).is_some_and(|e| e.ether_type == ETHERTYPE_ARP) {
        return true;
    }
    let Some((p, s, d)) = endpoints(frame) else {
        return false;
    };
    ours.iter()
        .any(|(cp, a, b)| *cp == p && ((s == *a && d == *b) || (s == *b && d == *a)))
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// What the request part of the run produced.
struct Exchange {
    dns: Option<Conversation>,
    tcp: Conversation,
    /// What the socket (or, for https, rustls) handed the program: the
    /// plaintext response.
    response: Vec<u8>,
    /// For https: the session secrets, as keylog-file text.
    keylog: Option<String>,
}

/// Resolves, connects and sends the request; reads the whole response.
/// `Connection: close` makes the server close when it's done, so the response
/// ends at EOF and the capture includes the whole teardown. For https the
/// same request goes through a TLS 1.3 session on the same TCP connection.
fn exchange(url: &Url) -> io::Result<Exchange> {
    let (ip, dns) = match url.host.parse::<IpAddr>() {
        Ok(ip) => (ip, None),
        Err(_) => {
            let r = resolve(&url.host)?;
            let list: Vec<String> = r.addrs.iter().map(IpAddr::to_string).collect();
            eprintln!(
                "osiview: {} -> {} (own DNS query to {})",
                url.host,
                list.join(", "),
                r.server
            );
            let first = r
                .addrs
                .first()
                .copied()
                .ok_or_else(|| io::Error::other("no address"))?;
            (first, Some((PROTO_UDP, r.local, r.server)))
        }
    };

    let remote = SocketAddr::new(ip, url.port);
    let mut stream = TcpStream::connect_timeout(&remote, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let local = stream.local_addr()?;
    eprintln!("osiview: connected {local} -> {remote}");

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: osiview/{}\r\nAccept: */*\r\n\
         Accept-Encoding: gzip\r\nConnection: close\r\n\r\n",
        url.path,
        url.host_header(),
        env!("CARGO_PKG_VERSION")
    );

    let (response, keylog) = if url.tls {
        let secrets = Arc::new(MemoryKeyLog::default());
        let name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let conn = rustls::ClientConnection::new(tls_config(Arc::clone(&secrets))?, name)
            .map_err(io::Error::other)?;
        // StreamOwned runs the handshake on first use: the write below sends
        // the ClientHello, waits for the server's flight, sends Finished, and
        // only then the request, encrypted.
        let mut tls = rustls::StreamOwned::new(conn, stream);
        tls.write_all(request.as_bytes())?;
        tls.flush()?;
        let response = read_until_close(&mut tls)?;
        // Our own close_notify, then the TCP FIN when the socket drops. The
        // server may already have gone, so a failure here doesn't matter.
        tls.conn.send_close_notify();
        let _ = tls.conn.complete_io(&mut tls.sock);
        drop(tls);
        let text = secrets.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        (response, Some(text))
    } else {
        stream.write_all(request.as_bytes())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        drop(stream); // our FIN
        (response, None)
    };
    Ok(Exchange {
        dns,
        tcp: (PROTO_TCP, local, remote),
        response,
        keylog,
    })
}

/// `osiview http(s)://…`: request the URL and show every packet it caused.
/// `keylog_out` saves an https run's secrets, for `osiview follow --keylog`.
pub fn run(
    url: &str,
    mut printer: Printer,
    write: Option<PathBuf>,
    keylog_out: Option<PathBuf>,
) -> io::Result<()> {
    let url = Url::parse(url).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let (stop, handle) = start_capture()?;

    let result = exchange(&url);
    // Give the last ACK and FIN a moment to arrive before stopping.
    thread::sleep(Duration::from_millis(400));
    stop.store(true, Ordering::Relaxed);
    let frames = handle
        .join()
        .map_err(|_| io::Error::other("capture thread panicked"))??;
    let ex = result?;

    if let Some(path) = &keylog_out {
        match &ex.keylog {
            Some(text) => {
                std::fs::write(path, text)?;
                eprintln!("osiview: wrote TLS secrets to {}", path.display());
            }
            None => eprintln!("osiview: --keylog ignored: http:// has no TLS secrets"),
        }
    }

    let ours: Vec<Conversation> = ex.dns.into_iter().chain([ex.tcp]).collect();
    let frames: Vec<&OwnedFrame> = frames.iter().filter(|f| belongs(&f.data, &ours)).collect();

    if let Some(path) = &write {
        let mut w = pcap::Writer::new(
            BufWriter::new(File::create(path)?),
            pcap::DEFAULT_SNAPLEN,
            pcap::LINKTYPE_ETHERNET,
        )?;
        for f in &frames {
            w.write_packet(f.time, &f.data, f.orig_len)?;
        }
        w.flush()?;
        eprintln!(
            "osiview: wrote {} packets to {}",
            frames.len(),
            path.display()
        );
    }

    let title = format!(
        "{} packets caused by GET {}://{}{}",
        frames.len(),
        url.scheme(),
        url.host_header(),
        url.path
    );
    println!("{}\n", paint(&format!("━━━ {title} ━━━"), "1"));
    let mut table = Table::new();
    let mut observations = Vec::new();
    for f in &frames {
        let obs = table.observe_frame(&f.data);
        let origin = Origin {
            outgoing: Some(f.outgoing),
            ..Origin::default()
        };
        printer.print(f.time, origin, &f.data, obs.as_ref());
        observations.push(obs);
    }
    if frames.iter().any(|f| f.outgoing) && printer.style() != Style::OneLine {
        println!(
            "\n{}",
            paint(
                "(checksum offload: Linux captures outgoing frames before the NIC fills in the \
                 TCP/UDP checksum)",
                "2"
            )
        );
    }

    // The same exchange as sequence diagrams, one per conversation.
    let Some(start) = frames.first().map(|f| f.time) else {
        return Ok(());
    };
    if let Some((_, client, server)) = ex.dns {
        println!("\n{}", paint("━━━ DNS (L7 over UDP) ━━━", "1"));
        print!(
            "{}",
            ladder_for(&frames, start, client, server, &mut |_, data| dns_label(
                data
            ))
        );
    }
    let (_, local, remote) = ex.tcp;
    let carrying = if url.tls {
        "TLS 1.3 (L5/L6) and HTTP (L7)"
    } else {
        "HTTP (L7)"
    };
    println!(
        "\n{}",
        paint(
            &format!("━━━ TCP connection (L4) carrying {carrying} ━━━"),
            "1"
        )
    );
    print!(
        "{}",
        ladder_for(&frames, start, local, remote, &mut |seg, _| seg
            .map(tcp_label)
            .unwrap_or_default())
    );
    if let Some(t) = timings(&frames, start, &ex) {
        println!("\n{t}");
    }

    let (_, local, remote) = ex.tcp;
    let flow = table.flows().iter().find(|f| {
        (f.client.addr, f.client.port) == (local.ip(), local.port())
            && (f.server.addr, f.server.port) == (remote.ip(), remote.port())
    });
    let Some(flow) = flow else {
        println!("(the TCP connection wasn't in the capture)");
        return Ok(());
    };
    let rebuilt = match &ex.keylog {
        None => {
            println!(
                "\n{}",
                paint(
                    "━━━ HTTP response, rebuilt from the captured TCP segments (L4 → L7) ━━━",
                    "1"
                )
            );
            let stream = flow.stream(Side::Server);
            for m in level7::parse_http_stream(stream, true) {
                crate::print_http(&m);
            }
            stream.to_vec()
        }
        Some(secrets) => {
            // Exactly what `osiview follow --keylog` does with a pcap and a
            // keylog file: both reassembled streams plus the secrets go to
            // layer 5, which walks the handshake, derives keys (layer 6) and
            // decrypts every record.
            println!(
                "\n{}",
                paint(
                    "━━━ TLS session, decrypted from the captured segments (L4 → L5/L6 → L7) ━━━",
                    "1"
                )
            );
            let keys = level5::KeyLog::parse(secrets);
            let conn = level5::analyse(
                flow.stream(Side::Client),
                flow.stream(Side::Server),
                Some(&keys),
            );
            crate::print_tls(flow, &conn, &HashMap::new());
            conn.app_data[1].clone()
        }
    };
    // The proof: what we rebuilt from captured packets is byte for byte what
    // the program received. For https that means every record was decrypted
    // with keys osiview derived itself.
    let what = if url.tls { "decrypted" } else { "reassembled" };
    if rebuilt == ex.response {
        println!(
            "{}",
            paint(
                &format!(
                    "✓ the {} {what} bytes match exactly what the {} received",
                    rebuilt.len(),
                    if url.tls { "TLS client" } else { "socket" }
                ),
                "32"
            )
        );
    } else {
        println!(
            "{}",
            paint(
                &format!(
                    "✗ {what} {} bytes, but the program received {}",
                    rebuilt.len(),
                    ex.response.len()
                ),
                "31"
            )
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Diagrams and timings
// ---------------------------------------------------------------------------

/// A ladder diagram of every frame between `a` (left) and `b` (right).
/// `label` gets the frame's TCP segment (if it is one) and its transport
/// payload, and returns the arrow's text.
fn ladder_for(
    frames: &[&OwnedFrame],
    start: Timestamp,
    a: SocketAddr,
    b: SocketAddr,
    label: &mut dyn FnMut(Option<&TcpSegment<'_>>, &[u8]) -> String,
) -> String {
    let mut rungs = Vec::new();
    for f in frames {
        let Some((proto, src, dst)) = endpoints(&f.data) else {
            continue;
        };
        if !((src == a && dst == b) || (src == b && dst == a)) {
            continue;
        }
        let Some(payload) = transport_payload(&f.data) else {
            continue;
        };
        let (seg, app) = if proto == PROTO_TCP {
            let seg = TcpSegment::parse(payload);
            let app = seg.as_ref().map(|s| s.payload).unwrap_or_default();
            (seg, app)
        } else {
            (
                None,
                UdpDatagram::parse(payload)
                    .map(|d| d.payload)
                    .unwrap_or_default(),
            )
        };
        rungs.push(Rung {
            to_right: src == a,
            label: label(seg.as_ref(), app),
            time: format_offset(f.time.micros_since(start)),
        });
    }
    ladder(&a.to_string(), &b.to_string(), &rungs)
}

/// The TCP or UDP part of a frame.
fn transport_payload(frame: &[u8]) -> Option<&[u8]> {
    let eth = EthernetFrame::parse(frame)?;
    level3::transport(eth.payload).map(|(_, p)| p)
}

/// The arrow label for a TCP segment: the HTTP start line or TLS records if it
/// carries them, otherwise its role (`SYN`, `SYN-ACK`, `FIN`, `ACK`,
/// `data N B`).
fn tcp_label(seg: &TcpSegment<'_>) -> String {
    let f = seg.flags;
    let n = seg.payload.len();
    if let Some(h) = HttpSegment::parse(seg.payload) {
        return format!("{} ({n} B)", h.start_line);
    }
    if let Some(tls) = tls_label(seg.payload) {
        return format!("{tls} ({n} B)");
    }
    let role = if f.has(TcpFlags::RST) {
        "RST"
    } else if f.has(TcpFlags::SYN) && f.has(TcpFlags::ACK) {
        "SYN-ACK"
    } else if f.has(TcpFlags::SYN) {
        "SYN"
    } else if f.has(TcpFlags::FIN) {
        "FIN"
    } else if n > 0 {
        return format!("data {n} B");
    } else {
        "ACK"
    };
    if n > 0 {
        format!("{role} + {n} B")
    } else {
        role.to_string()
    }
}

/// The TLS records a segment starts with, e.g. `ServerHello, CCS, encrypted
/// 2834 B…`.
///
/// This is a per-packet view, so it only works when a segment starts on a
/// record boundary. TLS records ignore TCP segment boundaries: a 4 KB record
/// of certificates spans several segments. A segment that starts mid-record
/// gets no TLS label (`data N B`), and a trailing `…` means the last record
/// continues in the next segment. The full picture, decrypted, comes from the
/// reassembled stream below the diagram.
///
/// After the hellos everything is content type 23 ("application data") on
/// the wire, whatever it really is: the true type is inside the encryption
/// (RFC 8446 §5.2). So these are just "encrypted N B".
fn tls_label(payload: &[u8]) -> Option<String> {
    if !level5::looks_like_tls(payload) {
        return None;
    }
    let (records, rest) = TlsRecord::split(payload);
    let mut parts: Vec<String> = records
        .iter()
        .map(|r| match r.content_type {
            // Plaintext handshake (the hellos): name the first message.
            22 => r
                .fragment
                .first()
                .map(|&t| level5::handshake_type_name(t).to_string())
                .unwrap_or_else(|| "Handshake".into()),
            20 => "CCS".into(),
            23 => format!("encrypted {} B", r.fragment.len()),
            t => level5::content_type_name(t).to_string(),
        })
        .collect();
    if !rest.is_empty() {
        // An incomplete record: say what it is, from its header.
        let mut c = Cursor::new(rest);
        let what = match c.read_u8() {
            Some(22) => rest
                .get(5)
                .map(|&t| level5::handshake_type_name(t).to_string())
                .unwrap_or_else(|| "Handshake".into()),
            Some(23) => "encrypted".into(),
            Some(t) => level5::content_type_name(t).to_string(),
            None => String::new(),
        };
        parts.push(format!("{what}…"));
    }
    Some(parts.join(", "))
}

/// The arrow label for a DNS datagram.
fn dns_label(payload: &[u8]) -> String {
    let Some(msg) = DnsMessage::parse(payload) else {
        return format!("udp {} B", payload.len());
    };
    let q = msg
        .questions
        .first()
        .map(|q| format!("{} {}", level7::dns_type_name(q.qtype), q.name))
        .unwrap_or_default();
    if !msg.is_response() {
        return format!("query {q}");
    }
    let answers: Vec<String> = msg
        .answers
        .iter()
        .filter_map(|r| match r.data {
            RData::A(a) => Some(a.to_string()),
            _ => None,
        })
        .collect();
    format!(
        "{} {}",
        level7::dns_rcode_name(msg.rcode()),
        answers.join(", ")
    )
}

/// Where the time went: DNS round trip, TCP handshake round trip, time to the
/// first response byte, and the whole exchange.
fn timings(frames: &[&OwnedFrame], start: Timestamp, ex: &Exchange) -> Option<String> {
    let (_, local, remote) = ex.tcp;
    let tcp: Vec<(&OwnedFrame, TcpSegment<'_>, bool)> = frames
        .iter()
        .filter_map(|f| {
            let (_, src, dst) = endpoints(&f.data)?;
            let outgoing = src == local && dst == remote;
            if !(outgoing || (src == remote && dst == local)) {
                return None;
            }
            Some((
                *f,
                TcpSegment::parse(transport_payload(&f.data)?)?,
                outgoing,
            ))
        })
        .collect();
    let ms = |a: Timestamp, b: Timestamp| b.micros_since(a) as f64 / 1000.0;
    let syn = tcp
        .iter()
        .find(|(_, s, o)| *o && s.flags.has(TcpFlags::SYN))?
        .0
        .time;
    let synack = tcp
        .iter()
        .find(|(_, s, o)| !*o && s.flags.has(TcpFlags::SYN))
        .map(|(f, ..)| f.time);
    let request = tcp
        .iter()
        .find(|(_, s, o)| *o && !s.payload.is_empty())
        .map(|(f, ..)| f.time);
    let first_byte = tcp
        .iter()
        .find(|(_, s, o)| !*o && !s.payload.is_empty())
        .map(|(f, ..)| f.time);
    let end = frames.last()?.time;

    let mut parts = Vec::new();
    if ex.dns.is_some() {
        parts.push(format!("DNS {:.1} ms", ms(start, syn)));
    }
    if let Some(sa) = synack {
        parts.push(format!("TCP handshake RTT {:.1} ms", ms(syn, sa)));
    }
    if let (Some(rq), Some(fb)) = (request, first_byte) {
        parts.push(format!("server response {:.1} ms", ms(rq, fb)));
    }
    parts.push(format!("total {:.1} ms", ms(start, end)));
    Some(paint(&format!("⏱  {}", parts.join("  ·  ")), "1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        assert_eq!(
            Url::parse("http://example.com").unwrap(),
            Url {
                tls: false,
                host: "example.com".into(),
                port: 80,
                path: "/".into()
            }
        );
        let u = Url::parse("http://localhost:8080/a/b?c=d").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("localhost", 8080, "/a/b?c=d")
        );
        assert_eq!(u.host_header(), "localhost:8080");
        let v6 = Url::parse("http://[2001:db8::1]:81/").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(v6.host_header(), "[2001:db8::1]:81");
        let tls = Url::parse("https://example.com/x").unwrap();
        assert!(tls.tls);
        assert_eq!((tls.port, tls.host_header()), (443, "example.com".into()));
        let odd = Url::parse("https://example.com:8443").unwrap();
        assert_eq!(odd.host_header(), "example.com:8443");
        // 443 isn't the default for http, so it's kept in the Host header.
        assert_eq!(
            Url::parse("http://example.com:443").unwrap().host_header(),
            "example.com:443"
        );
        assert!(Url::parse("ftp://x").is_err());
        assert!(Url::parse("http://x:notaport/").is_err());
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use rustls::KeyLog as _;

    /// What rustls hands the KeyLog callback comes out as keylog-file lines
    /// that osiview's own parser reads back.
    #[test]
    fn memory_keylog_round_trips_through_level5() {
        let log = MemoryKeyLog::default();
        let random = [0xab; 32];
        log.log("CLIENT_TRAFFIC_SECRET_0", &random, &[1, 2, 3]);
        let text = log.0.lock().unwrap().clone();
        assert_eq!(
            text,
            format!("CLIENT_TRAFFIC_SECRET_0 {} 010203\n", "ab".repeat(32))
        );
        let parsed = level5::KeyLog::parse(&text);
        assert_eq!(
            parsed.secret(&random, "CLIENT_TRAFFIC_SECRET_0"),
            Some(&[1u8, 2, 3][..])
        );
    }

    #[test]
    fn labels_tls_records_in_a_segment() {
        // A ServerHello record (type 22, msg 2), a CCS, then the start of an
        // encrypted record that continues in the next segment.
        let mut seg = vec![22, 3, 3, 0, 4, 2, 0, 0, 0];
        seg.extend([20, 3, 3, 0, 1, 1]);
        seg.extend([23, 3, 3, 0x10, 0x00, 0xde, 0xad]);
        assert_eq!(tls_label(&seg).unwrap(), "ServerHello, CCS, encrypted…");
        assert_eq!(tls_label(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn tls_config_builds() {
        let cfg = tls_config(Arc::new(MemoryKeyLog::default())).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
