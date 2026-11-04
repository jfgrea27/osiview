mod base_level;
mod cursor;
mod display;
mod fetch;
mod flow;
mod level2;
mod level3;
mod level4;
mod level5;
mod level6;
mod level7;
mod pcap;
#[cfg(test)]
mod tls_vectors;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use base_level::Operate;
use display::{Origin, Printer, Style};
use flow::{Side, Table};
use level2::Capture;
use level5::KeyLog;
use level7::HttpMessage;

/// Decode network traffic layer by layer, from the Ethernet frame up.
#[derive(Parser)]
#[command(name = "osiview", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture live frames (Linux only; needs root or CAP_NET_RAW).
    Capture {
        /// Interface to capture on, e.g. eth0 or lo. Default: all interfaces.
        #[arg(short, long)]
        interface: Option<String>,
        /// Also save every frame to this pcap file.
        #[arg(short, long, value_name = "FILE")]
        write: Option<PathBuf>,
        /// Stop after this many frames.
        #[arg(short, long)]
        count: Option<u64>,
        /// Print field tables and a hexdump for each frame.
        #[arg(short, long)]
        verbose: bool,
        /// One line per frame instead of one line per layer.
        #[arg(long, conflicts_with = "verbose")]
        oneline: bool,
        /// Also print each packet's payload: text as text, binary as a hexdump.
        #[arg(short, long, conflicts_with = "verbose")]
        payload: bool,
        /// Don't print frames (useful with --write).
        #[arg(short, long, conflicts_with_all = ["verbose", "oneline"])]
        quiet: bool,
    },
    /// Decode frames from a pcap file (any OS, no privileges needed).
    Read {
        file: PathBuf,
        /// Print field tables and a hexdump for each frame.
        #[arg(short, long)]
        verbose: bool,
        /// One line per frame instead of one line per layer.
        #[arg(long, conflicts_with = "verbose")]
        oneline: bool,
        /// Also print each packet's payload: text as text, binary as a hexdump.
        #[arg(short, long, conflicts_with = "verbose")]
        payload: bool,
    },
    /// Print each TCP connection in a pcap file as its two reassembled byte
    /// streams, with HTTP/1.1 messages decoded.
    Follow {
        file: PathBuf,
        /// Only this flow (the number shown by `read` as "flow N").
        #[arg(short, long)]
        flow: Option<usize>,
        /// Print the streams as escaped text, without decoding TLS or HTTP.
        #[arg(long)]
        raw: bool,
        /// TLS key log (the file curl or a browser writes when SSLKEYLOGFILE is
        /// set). With it, TLS 1.3 connections are decrypted.
        #[arg(short, long, value_name = "FILE")]
        keylog: Option<PathBuf>,
    },
    /// Request an http:// or https:// URL and print every packet it caused,
    /// L2 → L7, with TLS decrypted (Linux; needs root or CAP_NET_RAW).
    /// `osiview http(s)://…` does the same.
    Get {
        url: String,
        /// Print field tables and a hexdump for each packet.
        #[arg(short, long)]
        verbose: bool,
        /// One line per packet instead of one line per layer.
        #[arg(long, conflicts_with = "verbose")]
        oneline: bool,
        /// Also print each packet's payload: text as text, binary as a hexdump.
        #[arg(short, long, conflicts_with = "verbose")]
        payload: bool,
        /// Also save the packets to this pcap file.
        #[arg(short, long, value_name = "FILE")]
        write: Option<PathBuf>,
        /// For https: also save the TLS secrets to this keylog file, so the
        /// --write capture can be decrypted later with `follow --keylog`.
        #[arg(short, long, value_name = "FILE")]
        keylog: Option<PathBuf>,
    },
    /// Resolve a name with osiview's own DNS client.
    Resolve { name: String },
    /// `osiview http://example.com`: shorthand for `osiview get http://example.com`.
    #[command(external_subcommand)]
    Url(Vec<String>),
    /// Decode a DER X.509 certificate file (layer 6 on its own).
    Cert { file: PathBuf },
    /// List network interfaces, to pick one for `capture -i`.
    Interfaces,
}

fn main() -> ExitCode {
    // Rust ignores SIGPIPE, so `osiview read x.pcap | head` would panic when
    // `head` exits. Restore the default: die quietly, like other Unix tools.
    // SAFETY: called before any threads exist; SIG_DFL is always valid.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let mut command = Cli::parse().command;
    // A bare URL is treated as `get URL`, with any flags after it.
    if let Command::Url(args) = &command {
        if args
            .first()
            .is_some_and(|a| a.starts_with("http://") || a.starts_with("https://"))
        {
            let argv = ["osiview", "get"]
                .into_iter()
                .map(String::from)
                .chain(args.iter().cloned());
            command = Cli::parse_from(argv).command;
        } else {
            eprintln!(
                "osiview: unknown command {:?} (see `osiview --help`)",
                args.first().map(String::as_str).unwrap_or("")
            );
            return ExitCode::FAILURE;
        }
    }
    display::init_color();
    let result = match command {
        Command::Capture {
            interface,
            write,
            count,
            verbose,
            oneline,
            payload,
            quiet,
        } => capture(
            interface.as_deref(),
            write,
            count,
            Printer::new(Style::from_flags(verbose, oneline)).with_payload(payload),
            quiet,
        ),
        Command::Read {
            file,
            verbose,
            oneline,
            payload,
        } => read(
            file,
            Printer::new(Style::from_flags(verbose, oneline)).with_payload(payload),
        ),
        Command::Follow {
            file,
            flow,
            raw,
            keylog,
        } => follow(file, flow, raw, keylog),
        Command::Get {
            url,
            verbose,
            oneline,
            payload,
            write,
            keylog,
        } => fetch::run(
            &url,
            Printer::new(Style::from_flags(verbose, oneline)).with_payload(payload),
            write,
            keylog,
        ),
        Command::Resolve { name } => fetch::resolve(&name).map(|r| {
            let addrs: Vec<String> = r.addrs.iter().map(|a| a.to_string()).collect();
            println!("{name} A {} (asked {})", addrs.join(", "), r.server);
        }),
        Command::Url(_) => unreachable!("rewritten to Get above"),
        Command::Cert { file } => {
            std::fs::read(&file).map(|der| print!("{}", level6::Level6.render(&der)))
        }
        Command::Interfaces => interfaces(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("osiview: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Opens a pcap file and checks it holds Ethernet frames.
fn open_pcap(file: &PathBuf) -> io::Result<pcap::Reader<BufReader<File>>> {
    let reader = pcap::Reader::new(BufReader::new(File::open(file)?))?;
    if reader.link_type() != pcap::LINKTYPE_ETHERNET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} has link type {}; osiview only decodes Ethernet (1)",
                file.display(),
                reader.link_type()
            ),
        ));
    }
    Ok(reader)
}

/// `osiview capture`: read frames from a packet socket, optionally save them to
/// a pcap file, and print them.
fn capture(
    interface: Option<&str>,
    write: Option<PathBuf>,
    count: Option<u64>,
    mut printer: Printer,
    quiet: bool,
) -> io::Result<()> {
    let mut cap = Capture::open(interface)?;
    let mut writer = match &write {
        Some(path) => Some(pcap::Writer::new(
            BufWriter::new(File::create(path)?),
            pcap::DEFAULT_SNAPLEN,
            pcap::LINKTYPE_ETHERNET,
        )?),
        None => None,
    };
    eprintln!(
        "osiview: capturing on {}{}",
        interface.unwrap_or("all interfaces"),
        write
            .as_ref()
            .map(|p| format!(", writing to {}", p.display()))
            .unwrap_or_default()
    );

    let mut table = Table::new();
    let mut seen = 0u64;
    while count.is_none_or(|c| seen < c) {
        let frame = cap.next_frame()?;
        seen += 1;

        if let Some(w) = writer.as_mut() {
            w.write_packet(frame.time, frame.data, frame.orig_len)?;
            // Flush every frame so the file is complete even after Ctrl-C.
            w.flush()?;
        }
        let obs = table.observe_frame(frame.data);
        if !quiet {
            // On all interfaces, say which one each frame came from.
            let name = interface.is_none().then(|| {
                level2::interface_name(frame.interface_index).unwrap_or_else(|| "?".into())
            });
            let origin = Origin {
                outgoing: Some(frame.outgoing),
                interface: name.as_deref(),
                note: None,
            };
            printer.print(frame.time, origin, frame.data, obs.as_ref());
        }
    }
    eprintln!("osiview: {seen} frames captured");
    Ok(())
}

/// `osiview read`: decode every frame in a pcap file.
fn read(file: PathBuf, mut printer: Printer) -> io::Result<()> {
    let mut reader = open_pcap(&file)?;
    let mut table = Table::new();
    while let Some(packet) = reader.next_packet()? {
        let obs = table.observe_frame(packet.data);
        let note = (packet.data.len() < packet.orig_len as usize).then(|| {
            format!(
                "(truncated: {} of {} bytes)",
                packet.data.len(),
                packet.orig_len
            )
        });
        let origin = Origin {
            note: note.as_deref(),
            ..Origin::default()
        };
        printer.print(packet.time, origin, packet.data, obs.as_ref());
    }
    Ok(())
}

/// `osiview follow`: rebuild every TCP connection in a pcap file and print each
/// direction. Packet order in the file doesn't matter: the reassembler puts
/// the bytes back in sequence order. TLS connections are decoded at layers 5
/// and 6, and decrypted if a keylog has their secrets.
fn follow(
    file: PathBuf,
    only: Option<usize>,
    raw: bool,
    keylog: Option<PathBuf>,
) -> io::Result<()> {
    let keylog = match keylog {
        Some(path) => {
            let log = KeyLog::parse(&std::fs::read_to_string(&path)?);
            eprintln!(
                "osiview: keylog has secrets for {} connection(s)",
                log.len()
            );
            Some(log)
        }
        None => None,
    };
    let mut reader = open_pcap(&file)?;
    let mut table = Table::new();
    while let Some(packet) = reader.next_packet()? {
        table.observe_frame(packet.data);
    }

    // Session tickets seen so far, so a later connection that resumes from one
    // can be linked back to the flow that issued it.
    let mut tickets: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut shown = 0;
    for f in table.flows() {
        let client = f.stream(Side::Client);
        let server = f.stream(Side::Server);
        let tls = (!raw && level5::looks_like_tls(client))
            .then(|| level5::analyse(client, server, keylog.as_ref()));
        if let Some(conn) = &tls {
            for t in &conn.tickets {
                tickets.insert(t.clone(), f.id);
            }
        }
        if only.is_some_and(|n| n != f.id) {
            continue;
        }
        shown += 1;
        println!(
            "=== flow {}: {} ({} segments, {})",
            f.id,
            f.describe(),
            f.segments,
            f.state
        );
        match &tls {
            Some(conn) => print_tls(f, conn, &tickets),
            None => {
                for side in [Side::Client, Side::Server] {
                    print_direction(f, side);
                    print_payload(f.stream(side), side, raw);
                }
            }
        }
        println!();
    }
    if let Some(n) = only
        && shown == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no flow {n} in {}", file.display()),
        ));
    }
    Ok(())
}

/// `--- client 10.0.0.1:5000 -> 1.2.3.4:80: 75 bytes`.
fn print_direction(f: &flow::Flow, side: Side) {
    let (from, to) = match side {
        Side::Client => (f.client, f.server),
        Side::Server => (f.server, f.client),
    };
    let dropped = match f.dropped(side) {
        0 => String::new(),
        n => format!(", {n} bytes not kept"),
    };
    println!(
        "--- {side} {from} -> {to}: {} bytes{dropped}",
        f.stream(side).len()
    );
}

/// A plaintext stream: HTTP/1.1 messages if it is HTTP, escaped text otherwise.
fn print_payload(data: &[u8], side: Side, raw: bool) {
    if data.is_empty() {
        return;
    }
    if !raw && level7::looks_like_http(data) {
        for m in level7::parse_http_stream(data, side == Side::Server) {
            print_http(&m);
        }
    } else {
        println!("{}", escape_text(data));
    }
}

/// A TLS connection: the session (layer 5), the certificates (layer 6), then
/// the decrypted application data (layer 7).
fn print_tls(f: &flow::Flow, conn: &level5::TlsConnection, tickets: &HashMap<Vec<u8>, usize>) {
    println!("--- L5 tls: {}", conn.headline());
    if conn.resumed {
        let from = conn
            .psk_identities
            .iter()
            .find_map(|id| tickets.get(id).filter(|&&n| n != f.id));
        match from {
            Some(n) => println!("    resumes the session from flow {n} (its NewSessionTicket)"),
            None => println!("    resumes a session whose ticket isn't in this capture"),
        }
    }
    if let Some(note) = &conn.note {
        println!("    not decrypted: {note}");
    }
    for side in [Side::Client, Side::Server] {
        let (from, to) = match side {
            Side::Client => (f.client, f.server),
            Side::Server => (f.server, f.client),
        };
        println!("--- L5 {side} {from} -> {to}:");
        for e in &conn.events[match side {
            Side::Client => 0,
            Side::Server => 1,
        }] {
            println!("    {e}");
        }
    }
    if !conn.certificates.is_empty() {
        println!("--- L6 certificate chain ({}):", conn.certificates.len());
        for (i, der) in conn.certificates.iter().enumerate() {
            match level6::Certificate::parse(der) {
                Ok(cert) => {
                    println!("  [{i}]");
                    for line in cert.to_string().lines() {
                        println!("    {line}");
                    }
                }
                Err(e) => println!("  [{i}] {} bytes, could not decode: {e}", der.len()),
            }
        }
    }
    if conn.decrypted {
        for (i, side) in [Side::Client, Side::Server].into_iter().enumerate() {
            let data = &conn.app_data[i];
            println!(
                "--- L7 {side} application data (decrypted): {} bytes",
                data.len()
            );
            if conn.alpn.as_deref() == Some("h2") {
                println!("(HTTP/2 is binary framing, which osiview doesn't decode yet)");
            } else {
                print_payload(data, side, false);
            }
        }
    }
}

/// One HTTP message: start line, headers, then the body if it's text.
fn print_http(m: &HttpMessage) {
    println!("{}", m.start_line);
    for (name, value) in &m.headers {
        println!("{name}: {value}");
    }
    println!();
    if !m.body.is_empty() {
        // Layer 6: undo the Content-Encoding (gzip, deflate) first.
        let body = match m.header("content-encoding") {
            Some(enc) if !enc.eq_ignore_ascii_case("identity") => {
                match level6::decode_content(enc, &m.body) {
                    Ok(decoded) => {
                        println!(
                            "[L6 Content-Encoding: {enc}: {} bytes -> {} bytes inflated]",
                            m.body.len(),
                            decoded.len()
                        );
                        decoded
                    }
                    Err(e) => {
                        println!("[L6 {e}]");
                        m.body.clone()
                    }
                }
            }
            _ => m.body.clone(),
        };
        match std::str::from_utf8(&body) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("({} bytes of binary body)", body.len()),
        }
    }
    if !m.complete {
        println!("(message incomplete: the capture ends before it does)");
    }
    println!();
}

/// A byte stream as text: printable ASCII, newlines and tabs as they are,
/// carriage returns dropped, anything else as `\xNN`.
fn escape_text(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'\n' | b'\t' | b' '..=b'~' => s.push(b as char),
            b'\r' => {}
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

/// `osiview interfaces`: list interfaces with their index, state and addresses.
fn interfaces() -> io::Result<()> {
    for i in level2::list_interfaces()? {
        let addrs: Vec<String> = i.addrs.iter().map(|a| a.to_string()).collect();
        println!(
            "{:>3}  {:<12} {:<4} {:<8}  {}",
            i.index,
            i.name,
            if i.up { "up" } else { "down" },
            if i.loopback { "loopback" } else { "" },
            addrs.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level2::Level2;
    use crate::pcap::Timestamp;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn capture_flags_parse() {
        let cli = Cli::try_parse_from([
            "osiview", "capture", "-i", "eth0", "-w", "out.pcap", "-c", "5",
        ])
        .unwrap();
        let Command::Capture {
            interface,
            write,
            count,
            ..
        } = cli.command
        else {
            panic!("expected capture");
        };
        assert_eq!(interface.as_deref(), Some("eth0"));
        assert_eq!(write, Some(PathBuf::from("out.pcap")));
        assert_eq!(count, Some(5));
    }

    /// A pcap file written by the Writer decodes end to end through `read`'s
    /// pieces: Reader → Level2 summary (→ Level3).
    #[test]
    fn written_pcap_decodes() {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06]);
        frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 0, 0, 1]);
        frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 10, 0, 0, 2]);

        let mut w = pcap::Writer::new(Vec::new(), 65535, pcap::LINKTYPE_ETHERNET).unwrap();
        w.write_packet(Timestamp::now(), &frame, frame.len())
            .unwrap();
        let bytes = w.into_inner();

        let mut r = pcap::Reader::new(bytes.as_slice()).unwrap();
        let p = r.next_packet().unwrap().unwrap();
        assert!(
            Level2
                .summary(p.data)
                .ends_with("| arp request who-has 10.0.0.2 tell 10.0.0.1 (00:11:22:33:44:55)")
        );
    }

    #[test]
    fn escape_text_keeps_text_and_escapes_bytes() {
        assert_eq!(escape_text(b"GET /\r\nok\x00\xff"), "GET /\nok\\x00\\xff");
    }

    #[test]
    fn interfaces_lists_loopback() {
        let list = level2::list_interfaces().unwrap();
        assert!(list.iter().any(|i| i.loopback));
    }
}
