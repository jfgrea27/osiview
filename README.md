# osiview

osiview makes a web request and prints every packet the request caused,
decoded layer by layer from the Ethernet frame up to the HTTP response. For
HTTPS it decrypts the TLS itself. The packet decoders are written by hand from
the RFCs and use no packet libraries.

```text
$ osiview https://example.com
osiview: example.com -> 172.66.147.243, 104.20.23.154 (own DNS query to 192.168.5.1:53)
osiview: connected 172.17.0.5:59460 -> 172.66.147.243:443
━━━ 27 packets caused by GET https://example.com/ ━━━
...
━━━ TCP connection (L4) carrying TLS 1.3 (L5/L6) and HTTP (L7) ━━━
              172.17.0.5:59460                  172.66.147.243:443
 +117.679 ms  │────────────────────── SYN ──────────────────────▶│
 +136.750 ms  │◀──────────────────── SYN-ACK ────────────────────│
 +136.770 ms  │────────────────────── ACK ──────────────────────▶│
 +137.338 ms  │────────────── ClientHello (233 B) ──────────────▶│
 +294.756 ms  │◀───── ServerHello, CCS, encrypted… (1420 B) ─────│
 +294.782 ms  │◀────────────────── data 1436 B ──────────────────│
 +295.675 ms  │─────────────────── CCS (6 B) ───────────────────▶│
 +300.094 ms  │───────────── encrypted 69 B (74 B) ─────────────▶│
 +300.257 ms  │──────────── encrypted 136 B (141 B) ────────────▶│
 +318.705 ms  │◀─ encrypted 477 B, encrypted 765 B, encrypted… ──│
 +318.717 ms  │◀────────────────────── FIN ──────────────────────│
...
⏱  DNS 117.7 ms  ·  TCP handshake RTT 19.1 ms  ·  server response 157.4 ms  ·  total 319.2 ms

━━━ TLS session, decrypted from the captured segments (L4 → L5/L6 → L7) ━━━
--- L5 tls: TLS 1.3, TLS_AES_256_GCM_SHA384, sni example.com, alpn http/1.1, full handshake
...
    {Certificate: 4 certificate(s)}
    {CertificateVerify ecdsa_secp256r1_sha256, 70-byte signature}
    {Finished (verify_data 48 bytes)} - verified
...
--- L7 server application data (decrypted): 753 bytes
HTTP/1.1 200 OK
...
[L6 Content-Encoding: gzip: 400 bytes -> 577 bytes inflated]
<!doctype html><html lang=en><head>...

✓ the 753 decrypted bytes match exactly what the TLS client received
```

osiview is also a way to learn networking. Each module starts with an
explanation of its protocol, with diagrams, and cites the RFC sections it
implements.

## Contents

- [Quick start](#quick-start)
- [Usage](#usage)
- [How it works](#how-it-works)
- [What it decodes](#what-it-decodes)
- [Platform](#platform)
- [Development](#development)
- [Design rules](#design-rules)
- [Roadmap](#roadmap)
- [Specs](#specs)

## Quick start

Live capture needs Linux. On macOS, the justfile runs osiview in a Docker
container:

```sh
just e2e                          # osiview http://example.com
just e2e https://example.com      # with TLS decrypted
just e2e https://example.com -v   # field tables and hexdumps for every packet
```

On Linux, build it and give the binary permission to open raw sockets:

```sh
cargo build
sudo setcap cap_net_raw,cap_net_admin+ep target/debug/osiview
target/debug/osiview https://example.com
```

`setcap` has to be run again after every build. Running with `sudo` works too.

## Usage

```sh
osiview http://example.com           # request a URL, print every packet L2 → L7
osiview https://example.com          # the same, with TLS 1.3 decrypted
osiview capture -i eth0 -w out.pcap  # live capture, optionally saved to a pcap file
osiview read out.pcap                # decode a saved capture, packet by packet
osiview follow out.pcap              # each TCP connection as two reassembled streams
osiview follow out.pcap -k keys.log  # ...with TLS 1.3 decrypted from a keylog
osiview resolve example.com          # DNS lookup with osiview's own resolver
osiview cert server.der              # decode one X.509 certificate
osiview interfaces                   # list interfaces for `capture -i`
```

`osiview http(s)://…` is short for `osiview get http(s)://…`.

### Output flags

`capture`, `read` and `get` print packets, and share these flags:

| Flag | Effect |
|---|---|
| (none) | A header line per packet, then one line per layer, coloured by layer |
| `-v` | A field table for every layer, then a hexdump of the frame |
| `--oneline` | One line per packet, with the layers joined by `\|` |
| `-p` | Also print each packet's payload: text as text, binary as a hexdump |
| `-w FILE` | Save the packets to a pcap file (`capture` and `get`) |
| `-k FILE` | Save the TLS secrets of an `https://` request (`get`) |
| `-c N` | Stop after N frames (`capture`) |
| `-q` | Don't print frames, useful with `-w` (`capture`) |

`follow` takes `--flow N` to show one connection (the number `read` prints
as "flow N"), `--raw` to print the streams as escaped text without decoding,
and `-k FILE` for a keylog.

Colour is used only when stdout is a terminal and `NO_COLOR` is unset.

### Requesting a URL

`osiview get` does the whole run:

1. It opens a packet socket on all interfaces, so it misses nothing that
   follows.
2. It resolves the host with its own DNS query over UDP. It never calls
   `getaddrinfo`.
3. It connects, sends a `GET` with `Connection: close`, and reads the response
   until the server closes.
4. It stops capturing and keeps only the packets of that DNS lookup and that
   TCP connection, plus any ARP.
5. It prints:
   - every packet, L2 → L7;
   - a sequence diagram for the DNS exchange and one for the TCP connection;
   - the timings: DNS, the TCP handshake round trip, server response time and
     total;
   - the response rebuilt from the captured packets.
6. It checks that the rebuilt response is byte-for-byte what the program
   received. That check shows reassembly (and, for HTTPS, decryption) is
   correct.

### HTTPS

For `https://` URLs, `rustls` is the TLS client. It offers only TLS 1.3, because
osiview's decryptor implements only the TLS 1.3 key schedule. It offers only
ALPN `http/1.1`, because osiview doesn't decode HTTP/2 yet. It checks the
server's certificate against the Mozilla root store, as any real client would.

rustls only makes the request. Through its `KeyLog` callback, it hands osiview
each traffic secret as it derives it. osiview turns them into `SSLKEYLOGFILE`
lines and decrypts the captured packets with its own layer 5 and 6 code.

To save a run and decrypt it again later:

```sh
osiview https://example.com -w tls.pcap -k tls.keys
osiview follow tls.pcap -k tls.keys
```

`follow --keylog` works with any program that writes a keylog, for example:

```sh
osiview capture -w curl.pcap &
SSLKEYLOGFILE=curl.keys curl --tlsv1.3 --http1.1 https://example.com
osiview follow curl.pcap -k curl.keys
```

When a connection resumes an earlier session from a ticket, `follow` says so
and names the flow that issued the ticket.

## How it works

Each layer's parser takes the payload slice handed up by the layer below. It
returns a view of its own header, plus the payload for the next layer.

```text
request side                          decode pipeline
------------                          ---------------
osiview <url>                         capture: AF_PACKET socket, or a pcap file
  │                                     │
DNS resolver (own code, UDP)          L2  Ethernet, VLAN, ARP
  │                                     │
TCP (kernel) + TLS (rustls) ─packets─▶ L3  IPv4, IPv6, ICMP
  │                                     │
KeyLog callback ───────── secrets ──▶  L4  UDP, TCP → flow table → reassembly
                                        │
                                      L5  TLS records, handshake, session state
                                        │
                                      L6  key schedule, AEAD decryption,
                                        │   X.509 certificates, gzip
                                      L7  DNS, HTTP/1.1
                                        │
                                      display: per packet, ladders, streams
```

The request side feeds the decode pipeline twice: once as packets on the wire,
and once (for HTTPS) as TLS secrets.

Decoding happens at two levels:

- **Per packet** (`read`, `capture`, `get`): each frame is decoded on its own,
  as far up as one packet allows. A TCP segment that starts a TLS record or an
  HTTP message shows that layer too.
- **Per stream** (`follow`, the end of `get`): `flow.rs` keys each TCP
  connection by its 4-tuple. It reassembles each direction into a byte stream,
  handling segments that are out of order, duplicated or overlapping, and
  sequence-number wraparound. Messages that span many segments are decoded
  from these streams. That covers TLS records, handshake messages and HTTP
  bodies.

### Layers 5 and 6

The internet stack doesn't map cleanly onto OSI layers 5 and 6, and TLS does
both jobs. osiview splits it like this:

- **Layer 5 (session), `level5.rs`:** the conversation.
  - record framing and handshake messages with all their extensions;
  - the connection state machine (plaintext → handshake keys → application
    keys → KeyUpdate);
  - Finished verification;
  - matching keylog secrets to a connection by its ClientHello random;
  - session tickets and PSK resumption.
- **Layer 6 (presentation), `level6.rs`:** the encodings.
  - the key schedule, from traffic secret to key and IV;
  - per-record nonces and AEAD decryption;
  - the ASN.1 DER reader and X.509 certificates;
  - HTTP content-codings.

## What it decodes

| OSI layer | Module | Protocols |
|---|---|---|
| 7 Application | `level7.rs` | DNS (name compression, EDNS(0), DNS over TCP framing), HTTP/1.1 (Content-Length, chunked, keep-alive) |
| 6 Presentation | `level6.rs` | TLS 1.3 key schedule and record decryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305), ASN.1 DER, X.509, gzip/deflate bodies |
| 5 Session | `level5.rs` | TLS records, handshake messages, extensions (SNI, ALPN, key_share, …), state machine, keylog, tickets and resumption |
| 4 Transport | `level4.rs`, `flow.rs` | UDP, TCP with options (MSS, window scale, SACK, timestamps), checksums, flow table, reassembly, connection labels |
| 3 Network | `level3.rs` | IPv4, IPv6 and its extension-header chain, ICMPv4, ICMPv6, Neighbor Discovery, the internet checksum |
| 2 Data link | `level2.rs` | Ethernet II, 802.1Q VLAN tags, ARP, live capture with `AF_PACKET` |
| 1 Physical | — | Out of scope. The NIC strips the preamble, SFD and usually the FCS before software sees a frame. |

The other modules:

| Module | Role |
|---|---|
| `main.rs` | The command line (clap) and the `read` and `follow` commands |
| `fetch.rs` | `osiview get`: DNS client, TLS client setup, background capture, sequence diagrams, timings |
| `display.rs` | Terminal output: stack, one-line and verbose styles, colours, ladder diagrams |
| `pcap.rs` | The classic pcap file format, read and written by hand. Wireshark and tcpdump can open osiview's captures, and osiview can read theirs. |
| `cursor.rs` | The bounds-checked big-endian reader under every parser, and the hexdump |
| `base_level.rs` | The `Operate` trait each layer implements: summary line, field table, hexdump |
| `tls_vectors.rs` | RFC 8448 TLS 1.3 test vectors (tests only) |

## Platform

| | Linux | macOS / other |
|---|---|---|
| `read`, `follow`, `cert` | ✓ | ✓, no privileges needed |
| `resolve` | ✓ | ✓ |
| `capture`, `get` | ✓, needs root or `CAP_NET_RAW` | Run in Docker with `just` |

Live capture uses a Linux `AF_PACKET` socket. The justfile runs osiview
in a `rust:1` container with `NET_RAW`. Build output and the crate cache live
in Docker volumes, so they don't clash with the macOS `target/` directory.

```sh
just osiview capture -i eth0 -c 10   # any osiview command
just linux test                      # any cargo command
```

Two things to expect from captures:

- **Outgoing checksums show as bad.** Linux captures outgoing frames before
  the NIC fills in the TCP/UDP checksum (checksum offload). osiview says so
  under the output.
- **Loopback still has an Ethernet header.** On Linux, `lo` frames carry a
  zeroed 14-byte Ethernet header, so they decode like any other frame.

## Development

The repo includes a Nix dev shell: run `nix develop`, or use direnv.

```sh
just test         # cargo test
just lint         # clippy, warnings are errors
just fmt          # rustfmt
just fmt-check    # check formatting (CI)
just linux-check  # clippy and tests on Linux, where the capture code compiles
just e2e [url]    # end-to-end run in a Linux container
```

CI runs `fmt-check`, `lint` and `test` on Ubuntu in the Nix shell.

### Testing

Decoders are tested against known bytes, never against other tools' output:

- RFC examples: internet checksum (RFC 1071), DNS name compression
  (RFC 1035 §4.1.4), chunked encoding (RFC 9112 §7.1).
- The RFC 8448 TLS 1.3 handshake trace. osiview derives the same traffic keys
  and IVs from its traffic secrets, and decrypts its records to the published
  plaintext.
- Hand-built frames, segments and records, including truncated and malformed
  ones. Each must return an error rather than panic.
- A shuffle/duplicate/overlap test for TCP reassembly: the stream must come
  out the same whatever order the segments arrive in.

### Dependencies

osiview uses a few crates, and none of them parses packets:

| Crate | Used for |
|---|---|
| `clap` | Command-line parsing |
| `libc` | Packet sockets and ioctls |
| `sha2`, `hmac`, `hkdf` | Hashes and HKDF for the TLS 1.3 key schedule |
| `aes-gcm`, `chacha20poly1305` | The AEAD ciphers that TLS records use |
| `flate2` | gzip and deflate response bodies |
| `rustls`, `webpki-roots` | The TLS client for `https://` requests |

The cryptographic primitives come from crates, because hand-written crypto is
easy to get subtly wrong. The TLS logic around them is osiview's own: the key
schedule, nonces, AAD, record parsing, content-type recovery and state
machine. rustls makes the request and never reads the capture.

## Design rules

- **The RFC is the spec.** Each parser starts from the header diagram in its
  RFC, and each module cites the sections it implements.
- **No packet libraries.** That excludes libpcap, pnet, etherparse,
  tls-parser and the like, and tshark or Wireshark as decoders. Wireshark is
  used only to check that osiview's pcap files open.
- **Never panic on hostile input.** Parsers return `Option` or `Result`, and
  every bounds check goes through `Cursor`. DNS name decompression has a loop
  guard, and the DER reader rejects lengths that run past their parent.
- **Zero-copy views.** Parsed headers borrow the input slice instead of
  copying it.
- **One module per layer.** `get` only wires the layers together.

## Roadmap

Not built yet, roughly in order:

- **Userspace TCP over TUN.** osiview's own TCP state machine (RFC 9293),
  with retransmission (RFC 6298) and congestion control (RFC 5681), on a
  `/dev/net/tun` device. `get` would then send through it instead of the
  kernel's `TcpStream`. Packets osiview sends on a normal interface get reset
  by the kernel, which doesn't know the connection, so a TUN device is needed.
- **Session resumption in one run.** Make two requests sharing a rustls
  config, and show the second resuming from the first connection's ticket.
  `follow` already detects and links resumed sessions.
- **`ping` and `traceroute`** from hand-built ICMP Echo Requests, decoding the
  Time Exceeded replies.
- **DNS:** IPv6 (AAAA) lookups for `get`, and TCP fallback when an answer is
  truncated. The decoder handles both already; the resolver doesn't use them.
- **IPv4 fragment reassembly** (RFC 815). Fragments are detected but not
  reassembled.
- **Fuzzing** the parsers with `cargo fuzz`, starting with `Cursor`, DER and
  DNS.
- **HTTP/2** (RFC 9113) with HPACK (RFC 7541), so `get` can offer `h2`.
- **QUIC and HTTP/3.**
  - QUIC Initial packets can be decrypted without a keylog, using keys derived
    from the connection ID (RFC 9001 §5.2).
  - The rest needs RFC 9000, with HTTP/3 (RFC 9114) and QPACK (RFC 9204).
- **WebSocket** (RFC 6455): the upgrade handshake and frame unmasking.
- **Output:** `--json`, and a `--layer` flag to expand only chosen layers.

## Specs

Every RFC is free at rfc-editor.org. The plain-text versions are the easiest
to work from, because their ASCII header diagrams map directly onto structs.

| Protocol | Read | Later, or only if… |
|---|---|---|
| pcap | draft-ietf-opsawg-pcap | draft-ietf-opsawg-pcapng, for Wireshark's default format |
| Ethernet, VLAN | RFC 894; IEEE 802.1Q | — |
| ARP | RFC 826 | RFC 5227 (probes and announcements) |
| IPv4 | RFC 791 §3.1–3.2 | RFC 815 (reassembly); RFC 2474, RFC 3168 (DSCP, ECN) |
| Internet checksum | RFC 1071 | RFC 1624 |
| IPv6 | RFC 8200 §3–4; RFC 5952 (address text) | — |
| ICMP | RFC 792; RFC 4443; RFC 4861 §4 (ND) | RFC 1191, RFC 8201 (path MTU) |
| UDP | RFC 768 | — |
| TCP | RFC 9293 §3.1–3.6; RFC 7323; RFC 2018 | RFC 6298, RFC 5681 (userspace TCP) |
| DNS | RFC 1035 §3.2, §4; RFC 3596 | RFC 6891 §6 (OPT); RFC 7766 (TCP) |
| HTTP/1.1 | RFC 9112 §2–7; RFC 9110 §5–6, §8.4 | — |
| TLS 1.3 | RFC 8446 §4, §5, §7, App. A–B; RFC 6066 §3; RFC 7301 | RFC 8446 §8 (0-RTT) |
| TLS sessions | RFC 8446 §2.2, §4.2.11, §4.6.1 | — |
| Keylog | draft-ietf-tls-keylogfile | — |
| TLS test vectors | RFC 8448 | — |
| Key schedule crypto | RFC 2104; RFC 5869 | — |
| ASN.1 DER | ITU-T X.690 §8, §10 | X.680 |
| X.509 | RFC 5280 §4.1, §4.2.1.6 | RFC 5280 §6 (path validation) |
| gzip / DEFLATE | RFC 1952; RFC 1951 | RFC 1950 |
| HTTP/2 | RFC 9113 §4–6; RFC 7541 | — |
| QUIC, HTTP/3 | RFC 9001 §5; RFC 9000 §17, §19; RFC 9114 §7; RFC 9204 | RFC 9002 |
| WebSocket | RFC 6455 §4–5 | — |

### Further reading

- *TCP/IP Illustrated, Volume 1* (Fall and Stevens, 2nd ed.), a companion to
  the RFCs.
- *The Illustrated TLS 1.3 Connection* (tls13.xargs.org), every byte of a real
  handshake annotated.
- *A Warm Welcome to ASN.1 and DER* (letsencrypt.org), for certificates.
- *High Performance Browser Networking* (Ilya Grigorik, free online), on how
  TCP, TLS and HTTP/2 behave in practice.
- *Beej's Guide to Network Programming*, for the socket APIs.
- Jon Gjengset's "Implementing TCP in Rust" streams, a long build of a
  TUN-based TCP stack.
