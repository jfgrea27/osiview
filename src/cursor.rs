use std::fmt::{self, Write};

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    size: usize,
    curr_pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Cursor {
            data,
            size: data.len(),
            curr_pos: 0,
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.size - self.curr_pos
    }

    pub(crate) fn read_u8(&mut self) -> Option<u8> {
        let bytes = self.read_bytes(1)?;
        Some(u8::from_be_bytes(bytes.try_into().unwrap()))
    }
    pub(crate) fn read_u16_be(&mut self) -> Option<u16> {
        let bytes = self.read_bytes(2)?;
        Some(u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn read_u32_be(&mut self) -> Option<u32> {
        let bytes = self.read_bytes(4)?;
        Some(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            None
        } else {
            let bytes = &self.data[self.curr_pos..self.curr_pos + n];
            self.curr_pos += n;
            Some(bytes)
        }
    }
}

pub(crate) struct HexDump<'a>(pub(crate) &'a [u8]);

impl fmt::Display for HexDump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, chunk) in self.0.chunks(16).enumerate() {
            write!(f, "{:08x} ", i * 16)?;
            for j in 0..16 {
                if j % 8 == 0 {
                    f.write_char(' ')?;
                }
                match chunk.get(j) {
                    Some(b) => write!(f, "{b:02x} ")?,
                    None => f.write_str("   ")?,
                }
            }
            f.write_str(" |")?;
            for &b in chunk {
                let printable = b.is_ascii_graphic() || b == b' ';
                f.write_char(if printable { b as char } else { '.' })?;
            }
            f.write_str("|\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_beginning() {
        let c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.remaining(), 3);
    }

    #[test]
    fn new_empty_buffer() {
        let c = Cursor::new(&[]);
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn remaining_decreases_as_bytes_are_read() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        c.read_u8();
        assert_eq!(c.remaining(), 3);
        c.read_u16_be();
        assert_eq!(c.remaining(), 1);
        c.read_u8();
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn read_u8_reads_in_order() {
        let mut c = Cursor::new(&[0xAA, 0xBB]);
        assert_eq!(c.read_u8(), Some(0xAA));
        assert_eq!(c.read_u8(), Some(0xBB));
    }

    #[test]
    fn read_u8_at_end_returns_none() {
        let mut c = Cursor::new(&[0xAA]);
        c.read_u8();
        assert_eq!(c.read_u8(), None);
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn read_u16_be_is_big_endian() {
        let mut c = Cursor::new(&[0x12, 0x34]);
        assert_eq!(c.read_u16_be(), Some(0x1234));
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn read_u16_be_short_buffer_does_not_advance() {
        let mut c = Cursor::new(&[0x12]);
        assert_eq!(c.read_u16_be(), None);
        assert_eq!(c.remaining(), 1);
        // the byte is still readable after the failed read
        assert_eq!(c.read_u8(), Some(0x12));
    }

    #[test]
    fn read_u32_be_is_big_endian() {
        let mut c = Cursor::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(c.read_u32_be(), Some(0xDEADBEEF));
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn read_u32_be_short_buffer_does_not_advance() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.read_u32_be(), None);
        assert_eq!(c.remaining(), 3);
    }

    #[test]
    fn read_bytes_returns_slice_and_advances() {
        let mut c = Cursor::new(&[1, 2, 3, 4, 5]);
        assert_eq!(c.read_bytes(3), Some(&[1, 2, 3][..]));
        assert_eq!(c.read_bytes(2), Some(&[4, 5][..]));
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn read_bytes_zero_is_empty_slice() {
        let mut c = Cursor::new(&[]);
        assert_eq!(c.read_bytes(0), Some(&[][..]));
    }

    #[test]
    fn read_bytes_too_many_does_not_advance() {
        let mut c = Cursor::new(&[1, 2]);
        assert_eq!(c.read_bytes(3), None);
        assert_eq!(c.remaining(), 2);
    }

    #[test]
    fn read_bytes_slice_outlives_further_reads() {
        let data = [0xAA, 0xBB, 0x08, 0x00];
        let mut c = Cursor::new(&data);
        let mac = c.read_bytes(2).unwrap();
        let ethertype = c.read_u16_be().unwrap();
        assert_eq!(mac, &[0xAA, 0xBB]);
        assert_eq!(ethertype, 0x0800);
    }

    #[test]
    fn hexdump_empty_is_empty() {
        assert_eq!(HexDump(&[]).to_string(), "");
    }

    #[test]
    fn hexdump_full_line() {
        let data = b"E\x00\x00<\x1cF@\x00@\x06\xb1\xe6\xc0\xa8\x00h";
        assert_eq!(
            HexDump(data).to_string(),
            "00000000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 00 68  |E..<.F@.@......h|\n"
        );
    }

    #[test]
    fn hexdump_pads_short_last_line() {
        let data: Vec<u8> = (0..18).collect();
        assert_eq!(
            HexDump(&data).to_string(),
            "00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |................|\n\
             00000010  10 11                                             |..|\n"
        );
    }

    #[test]
    fn hexdump_exactly_16_bytes_is_one_line() {
        let data = [0u8; 16];
        assert_eq!(HexDump(&data).to_string().lines().count(), 1);
    }

    #[test]
    fn hexdump_17_bytes_starts_second_line() {
        let data = [0u8; 17];
        let out = HexDump(&data).to_string();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("00000010  00 "));
    }

    #[test]
    fn hexdump_short_line_keeps_ascii_column_aligned() {
        let full = HexDump(&[0u8; 16]).to_string();
        let short = HexDump(&[0u8; 1]).to_string();
        assert_eq!(full.find('|'), short.find('|'));
    }

    #[test]
    fn hexdump_offsets_count_in_hex() {
        let data = [0u8; 48];
        let out = HexDump(&data).to_string();
        let offsets: Vec<&str> = out.lines().map(|l| &l[..8]).collect();
        assert_eq!(offsets, ["00000000", "00000010", "00000020"]);
    }

    #[test]
    fn hexdump_ascii_column_printable_boundaries() {
        // 0x1f and 0x7f are control chars, 0x80+ is not ASCII; space and ~ are printable
        let data = [0x1f, b' ', b'A', b'~', 0x7f, 0x80, 0xff];
        let out = HexDump(&data).to_string();
        assert!(out.ends_with("|. A~...|\n"));
    }

    #[test]
    fn hexdump_uses_lowercase_two_digit_hex() {
        let out = HexDump(&[0x0a, 0xAB]).to_string();
        assert!(out.starts_with("00000000  0a ab "));
    }

    #[test]
    fn hexdump_works_with_format_macros() {
        let data = [0x41];
        let expected = HexDump(&data).to_string();
        assert_eq!(format!("{}", HexDump(&data)), expected);
        assert_eq!(
            format!("before\n{}", HexDump(&data)),
            format!("before\n{expected}")
        );
    }
}
