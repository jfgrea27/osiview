//! The classic pcap capture file format (draft-ietf-opsawg-pcap), written and
//! read by hand. It's the format tcpdump writes and Wireshark opens.
//!
//! ```text
//! +------------------+------------------+------+------------------+------+-----
//! | file header (24) | record hdr (16)  | data | record hdr (16)  | data | …
//! +------------------+------------------+------+------------------+------+-----
//! ```
//!
//! File header:
//!
//! ```text
//! magic (4) | major (2) | minor (2) | reserved1 (4) | reserved2 (4) | snaplen (4) | link type (4)
//! ```
//!
//! Record header:
//!
//! ```text
//! seconds (4) | microseconds or nanoseconds (4) | captured length (4) | original length (4)
//! ```
//!
//! There's no fixed byte order. The writer uses its own machine's, and the
//! reader works out which from how the magic number reads. osiview always
//! writes little-endian, which is what almost every machine today would do.
//!
//! Wireshark saves *pcapng* by default, a different and more flexible format.
//! The reader detects it and says so rather than misreading it.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Magic number for files with microsecond timestamps (the original format).
pub const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
/// Magic number for files with nanosecond timestamps.
pub const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
/// The first 4 bytes of a pcapng file (a Section Header Block). It's the same in
/// both byte orders, so pcapng can tell a file apart from text even before it
/// knows the byte order.
const PCAPNG_MAGIC: u32 = 0x0a0d_0d0a;

/// Link type 1: Ethernet. Says what each record's data starts with. Others
/// include 0 (BSD loopback), 101 (raw IP) and 113 (Linux "cooked" capture).
pub const LINKTYPE_ETHERNET: u32 = 1;

/// The largest number of bytes saved per packet. 262144 is what tcpdump and
/// Wireshark use: big enough that nothing real gets truncated.
pub const DEFAULT_SNAPLEN: u32 = 262_144;

/// Readers refuse records claiming to be bigger than this, so a corrupt or
/// hostile file can't make osiview allocate gigabytes.
const MAX_RECORD_LEN: u32 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

/// A point in time as seconds and nanoseconds since the Unix epoch (UTC), the
/// same split the pcap record header uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub secs: u64,
    /// 0–999,999,999.
    pub nanos: u32,
}

impl Timestamp {
    /// The current wall-clock time. If the clock is set before 1970, this
    /// returns the epoch rather than failing.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only live capture uses it
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp {
            secs: d.as_secs(),
            nanos: d.subsec_nanos(),
        }
    }
}

impl Timestamp {
    /// Microseconds from `earlier` to `self` (negative if `self` is earlier).
    pub fn micros_since(&self, earlier: Timestamp) -> i64 {
        let us = |t: &Timestamp| i128::from(t.secs) * 1_000_000 + i128::from(t.nanos / 1000);
        i64::try_from(us(self) - us(&earlier)).unwrap_or(i64::MAX)
    }
}

/// Local time of day with microseconds, like tcpdump: `21:57:54.123456`.
/// The time zone comes from `localtime_r(3)`, so it follows `TZ` (a Docker
/// container is usually UTC).
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let micros = self.nanos / 1000;
        let Ok(secs) = libc::time_t::try_from(self.secs) else {
            return write!(f, "{}.{micros:06}", self.secs);
        };
        // SAFETY: tm is plain data; all-zero is a valid value.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are valid for the call. localtime_r is the
        // thread-safe version of localtime.
        if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
            return write!(f, "{}.{micros:06}", self.secs);
        }
        write!(
            f,
            "{:02}:{:02}:{:02}.{micros:06}",
            tm.tm_hour, tm.tm_min, tm.tm_sec
        )
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Writes a pcap file: the file header on creation, then one record per
/// [`Writer::write_packet`].
///
/// Wrap the file in a `BufWriter`, and call [`Writer::flush`] when the data needs
/// to be on disk, e.g. after each packet in a capture that might be stopped with
/// Ctrl-C.
pub struct Writer<W: Write> {
    out: W,
    snaplen: u32,
}

impl<W: Write> Writer<W> {
    /// Writes the 24-byte file header and returns the writer. Timestamps are
    /// stored in microseconds (magic `0xa1b2c3d4`), which every tool reads.
    pub fn new(mut out: W, snaplen: u32, link_type: u32) -> io::Result<Self> {
        let mut h = Vec::with_capacity(24);
        h.extend_from_slice(&MAGIC_MICROS.to_le_bytes());
        h.extend_from_slice(&2u16.to_le_bytes()); // major version
        h.extend_from_slice(&4u16.to_le_bytes()); // minor version
        h.extend_from_slice(&0u32.to_le_bytes()); // reserved1 (was "thiszone")
        h.extend_from_slice(&0u32.to_le_bytes()); // reserved2 (was "sigfigs")
        h.extend_from_slice(&snaplen.to_le_bytes());
        h.extend_from_slice(&link_type.to_le_bytes());
        out.write_all(&h)?;
        Ok(Writer { out, snaplen })
    }

    /// Writes one record. `data` is cut to the snaplen if it's longer;
    /// `orig_len` is the packet's real length and is stored as is, so a reader
    /// can tell when a packet was truncated.
    pub fn write_packet(
        &mut self,
        time: Timestamp,
        data: &[u8],
        orig_len: usize,
    ) -> io::Result<()> {
        let secs = u32::try_from(time.secs)
            .map_err(|_| invalid("timestamp after 2106 doesn't fit in a pcap record"))?;
        let incl = data.len().min(self.snaplen as usize);
        let mut rec = Vec::with_capacity(16);
        rec.extend_from_slice(&secs.to_le_bytes());
        rec.extend_from_slice(&(time.nanos / 1000).to_le_bytes());
        rec.extend_from_slice(&(incl as u32).to_le_bytes());
        rec.extend_from_slice(&u32::try_from(orig_len).unwrap_or(u32::MAX).to_le_bytes());
        self.out.write_all(&rec)?;
        self.out.write_all(data.get(..incl).unwrap_or(data))
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Returns the underlying writer (used by the tests to inspect the bytes).
    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.out
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// One record read from a pcap file. Borrows the reader's buffer, so use it
/// before reading the next one.
#[derive(Debug)]
pub struct Packet<'a> {
    pub time: Timestamp,
    /// The saved bytes (the "captured length").
    pub data: &'a [u8],
    /// The packet's length on the wire. Bigger than `data.len()` if it was cut
    /// to the snaplen.
    pub orig_len: u32,
}

/// Reads a pcap file of either byte order and either timestamp precision.
pub struct Reader<R: Read> {
    input: R,
    big_endian: bool,
    nanos: bool,
    link_type: u32,
    buf: Vec<u8>,
}

impl<R: Read> Reader<R> {
    /// Reads and checks the file header.
    pub fn new(mut input: R) -> io::Result<Self> {
        let mut h = [0u8; 24];
        input.read_exact(&mut h).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                invalid("file is shorter than a pcap header (24 bytes)")
            } else {
                e
            }
        })?;

        let magic = [h[0], h[1], h[2], h[3]];
        let (big_endian, nanos) = match (u32::from_le_bytes(magic), u32::from_be_bytes(magic)) {
            (MAGIC_MICROS, _) => (false, false),
            (MAGIC_NANOS, _) => (false, true),
            (_, MAGIC_MICROS) => (true, false),
            (_, MAGIC_NANOS) => (true, true),
            (PCAPNG_MAGIC, _) => {
                return Err(invalid(
                    "this is a pcapng file; osiview reads classic pcap \
                     (in Wireshark: File > Save As > Wireshark/tcpdump - pcap)",
                ));
            }
            _ => return Err(invalid("not a pcap file (unknown magic number)")),
        };

        let u16_at = |i: usize| {
            let b = [h[i], h[i + 1]];
            if big_endian {
                u16::from_be_bytes(b)
            } else {
                u16::from_le_bytes(b)
            }
        };
        let u32_at = |i: usize| field_u32(&[h[i], h[i + 1], h[i + 2], h[i + 3]], big_endian);

        let major = u16_at(4);
        let minor = u16_at(6);
        if major != 2 {
            return Err(invalid(format!("unsupported pcap version {major}.{minor}")));
        }
        Ok(Reader {
            input,
            big_endian,
            nanos,
            // The top 4 bits can carry FCS information; the link type is the rest.
            link_type: u32_at(20) & 0x0fff_ffff,
            buf: Vec::new(),
        })
    }

    /// What each record starts with. osiview only decodes [`LINKTYPE_ETHERNET`].
    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    /// Reads the next record. Returns `Ok(None)` at a clean end of file, and an
    /// error if the file ends partway through a record.
    pub fn next_packet(&mut self) -> io::Result<Option<Packet<'_>>> {
        let mut rec = [0u8; 16];
        if !read_full(&mut self.input, &mut rec)? {
            return Ok(None);
        }
        let be = self.big_endian;
        let secs = field_u32(&[rec[0], rec[1], rec[2], rec[3]], be);
        let frac = field_u32(&[rec[4], rec[5], rec[6], rec[7]], be);
        let incl = field_u32(&[rec[8], rec[9], rec[10], rec[11]], be);
        let orig = field_u32(&[rec[12], rec[13], rec[14], rec[15]], be);

        if incl > MAX_RECORD_LEN {
            return Err(invalid(format!(
                "record claims {incl} bytes; file is corrupt"
            )));
        }
        self.buf.resize(incl as usize, 0);
        self.input.read_exact(&mut self.buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                invalid("file ends in the middle of a packet")
            } else {
                e
            }
        })?;

        let nanos = if self.nanos {
            frac
        } else {
            frac.saturating_mul(1000)
        };
        Ok(Some(Packet {
            time: Timestamp {
                secs: u64::from(secs),
                nanos,
            },
            data: &self.buf,
            orig_len: orig,
        }))
    }
}

fn field_u32(b: &[u8; 4], big_endian: bool) -> u32 {
    if big_endian {
        u32::from_be_bytes(*b)
    } else {
        u32::from_le_bytes(*b)
    }
}

/// Fills `buf` completely. Returns `Ok(false)` if the input was already at end
/// of file, and an error if it ended partway.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(buf.get_mut(filled..).unwrap_or_default()) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    match filled {
        0 => Ok(false),
        n if n == buf.len() => Ok(true),
        _ => Err(invalid("file ends in the middle of a record header")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64, micros: u32) -> Timestamp {
        Timestamp {
            secs,
            nanos: micros * 1000,
        }
    }

    #[test]
    fn writes_the_expected_header() {
        let w = Writer::new(Vec::new(), DEFAULT_SNAPLEN, LINKTYPE_ETHERNET).unwrap();
        let bytes = w.into_inner();
        assert_eq!(
            bytes,
            [
                0xd4, 0xc3, 0xb2, 0xa1, // magic, little-endian
                0x02, 0x00, 0x04, 0x00, // version 2.4
                0, 0, 0, 0, 0, 0, 0, 0, // reserved
                0x00, 0x00, 0x04, 0x00, // snaplen 262144
                0x01, 0x00, 0x00, 0x00, // link type 1 (Ethernet)
            ]
        );
    }

    #[test]
    fn round_trips_packets() {
        let mut w = Writer::new(Vec::new(), DEFAULT_SNAPLEN, LINKTYPE_ETHERNET).unwrap();
        w.write_packet(ts(1_700_000_000, 123_456), &[1, 2, 3], 3)
            .unwrap();
        w.write_packet(ts(1_700_000_001, 0), &[4; 60], 60).unwrap();
        let bytes = w.into_inner();
        assert_eq!(bytes.len(), 24 + 16 + 3 + 16 + 60);

        let mut r = Reader::new(bytes.as_slice()).unwrap();
        assert_eq!(r.link_type(), LINKTYPE_ETHERNET);

        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(p.time, ts(1_700_000_000, 123_456));
        assert_eq!(p.data, &[1, 2, 3]);
        assert_eq!(p.orig_len, 3);

        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(p.data.len(), 60);

        assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn snaplen_truncates_but_keeps_original_length() {
        let mut w = Writer::new(Vec::new(), 4, LINKTYPE_ETHERNET).unwrap();
        w.write_packet(ts(1, 0), &[9; 10], 10).unwrap();
        let bytes = w.into_inner();
        let mut r = Reader::new(bytes.as_slice()).unwrap();
        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(p.data, &[9; 4]);
        assert_eq!(p.orig_len, 10);
    }

    #[test]
    fn reads_big_endian_nanosecond_files() {
        let mut f = Vec::new();
        f.extend_from_slice(&MAGIC_NANOS.to_be_bytes());
        f.extend_from_slice(&2u16.to_be_bytes());
        f.extend_from_slice(&4u16.to_be_bytes());
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&65535u32.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&5u32.to_be_bytes()); // secs
        f.extend_from_slice(&999u32.to_be_bytes()); // nanos
        f.extend_from_slice(&2u32.to_be_bytes()); // incl
        f.extend_from_slice(&2u32.to_be_bytes()); // orig
        f.extend_from_slice(&[0xab, 0xcd]);

        let mut r = Reader::new(f.as_slice()).unwrap();
        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(
            p.time,
            Timestamp {
                secs: 5,
                nanos: 999
            }
        );
        assert_eq!(p.data, &[0xab, 0xcd]);
    }

    #[test]
    fn rejects_pcapng_and_garbage() {
        let mut ng = vec![0x0a, 0x0d, 0x0d, 0x0a];
        ng.extend_from_slice(&[0; 20]);
        let err = Reader::new(ng.as_slice()).err().unwrap();
        assert!(err.to_string().contains("pcapng"));

        let err = Reader::new([0u8; 24].as_slice()).err().unwrap();
        assert!(err.to_string().contains("not a pcap file"));

        let err = Reader::new([0u8; 10].as_slice()).err().unwrap();
        assert!(err.to_string().contains("shorter than a pcap header"));
    }

    #[test]
    fn truncated_files_are_errors_not_panics() {
        let mut w = Writer::new(Vec::new(), DEFAULT_SNAPLEN, LINKTYPE_ETHERNET).unwrap();
        w.write_packet(ts(1, 0), &[7; 20], 20).unwrap();
        let bytes = w.into_inner();

        // Cut inside the record header.
        let mut r = Reader::new(&bytes[..30]).unwrap();
        assert!(r.next_packet().is_err());

        // Cut inside the packet data.
        let mut r = Reader::new(&bytes[..50]).unwrap();
        assert!(r.next_packet().is_err());
    }

    #[test]
    fn rejects_huge_records() {
        let mut w = Writer::new(Vec::new(), DEFAULT_SNAPLEN, LINKTYPE_ETHERNET).unwrap();
        w.write_packet(ts(1, 0), &[], 0).unwrap();
        let mut bytes = w.into_inner();
        bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes()); // incl_len
        let mut r = Reader::new(bytes.as_slice()).unwrap();
        assert!(r.next_packet().unwrap_err().to_string().contains("corrupt"));
    }
}
