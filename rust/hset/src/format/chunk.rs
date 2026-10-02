//! Chunk framing and primitive readers/writers.

use crate::error::{Error, Result};

pub const MAGIC: &[u8; 8] = b"SetOHash";
/// Byte offset of the SHA-256 digest in the file.
pub const SHA_OFFSET: usize = 8;
/// Byte offset of the first chunk (the FTOC), and the start of the hashed region.
pub const FIRST_CHUNK_OFFSET: usize = 40;
/// Size of a chunk header (type + length).
pub const CHUNK_HEADER_LEN: usize = 12;
/// HDAT chunks are placed at offsets that are multiples of this.
pub const HDAT_ALIGN: usize = 4096;

pub const FTOC: u32 = 0x4654_4F43;
pub const FHDR: u32 = 0x4648_4452;
pub const RHDR: u32 = 0x5248_4452;
pub const RDAT: u32 = 0x5244_4154;
pub const HHDR: u32 = 0x4848_0000;
pub const HHDR_MASK: u32 = 0xFFFF_0000;
pub const HDAT: u32 = 0x4844_4154;
pub const HINT: u32 = 0x4849_4E54;
pub const FLTR: u32 = 0x464C_5452;
pub const RIDX: u32 = 0x5249_4458;
pub const FEND: u32 = 0x4645_4E44;

/// Is this an `HHnn` hash set header tag?
pub fn is_hhdr(ty: u32) -> bool {
    ty & HHDR_MASK == HHDR
}

/// Render a chunk tag for messages, escaping non-printable bytes.
pub fn printable(ty: u32) -> String {
    let mut s = String::new();
    for b in ty.to_be_bytes() {
        if b.is_ascii_graphic() || b == b' ' {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    s
}

/// A decoded chunk header pointing into the file buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    pub ty: u32,
    pub offset: usize,
    pub data: &'a [u8],
}

/// Decode the chunk whose header starts at `offset`.
pub fn read_chunk(buf: &[u8], offset: usize) -> Result<Chunk<'_>> {
    let mut c = Cursor::new(buf, offset)?;
    let ty = c.be_u32()?;
    let len = c.le_u64()?;
    let len = usize::try_from(len).map_err(|_| Error::format("chunk length overflows usize"))?;
    let data = c.bytes(len)?;
    Ok(Chunk { ty, offset, data })
}

/// Bounds-checked reader over a byte slice.
#[derive(Debug)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8], pos: usize) -> Result<Self> {
        if pos > buf.len() {
            return Err(Error::format(format!(
                "offset {pos} beyond end of data ({} bytes)",
                buf.len()
            )));
        }
        Ok(Cursor { buf, pos })
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::format(format!(
                "out of data reading {n} bytes at offset {}",
                self.pos
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub fn le_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn le_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn le_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn be_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn be_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// `u16 LE` length-prefixed UTF-8 string (invalid UTF-8 is replaced).
    pub fn pstring(&mut self) -> Result<String> {
        let len = usize::from(self.le_u16()?);
        let b = self.bytes(len)?;
        Ok(String::from_utf8_lossy(b).into_owned())
    }
}

/// Growable output buffer with little/big-endian helpers.
#[derive(Default, Debug)]
pub struct Out {
    pub buf: Vec<u8>,
}

impl Out {
    pub fn with_capacity(n: usize) -> Self {
        Out {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    pub fn le_u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn le_u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn le_u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn le_i32(&mut self, v: i32) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn le_i64(&mut self, v: i64) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn be_u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }

    pub fn be_u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }

    /// Write a pstring. Callers must have validated `s.len() <= u16::MAX`.
    pub fn pstring(&mut self, s: &str) {
        self.le_u16(s.len() as u16);
        self.bytes(s.as_bytes());
    }

    /// Pad with zeros so that the next write lands at a multiple of `align`.
    pub fn align(&mut self, align: usize) {
        let pad = (align - self.buf.len() % align) % align;
        self.zeros(pad);
    }

    /// Write a chunk: header, then `body` fills the data, then the length is
    /// patched. Returns the chunk's offset.
    pub fn chunk(&mut self, ty: u32, body: impl FnOnce(&mut Out)) -> usize {
        let start = self.buf.len();
        self.be_u32(ty);
        self.le_u64(0);
        body(self);
        let len = (self.buf.len() - start - CHUNK_HEADER_LEN) as u64;
        self.buf[start + 4..start + 12].copy_from_slice(&len.to_le_bytes());
        start
    }
}

/// Size of the pstring encoding of `s`.
pub fn pstring_len(s: &str) -> usize {
    2 + s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let mut o = Out::default();
        let off = o.chunk(FHDR, |w| {
            w.le_u64(2);
            w.pstring("name");
        });
        assert_eq!(off, 0);
        let c = read_chunk(&o.buf, 0).unwrap();
        assert_eq!(c.ty, FHDR);
        assert_eq!(c.data.len(), 8 + 2 + 4);
        let mut cur = Cursor::new(c.data, 0).unwrap();
        assert_eq!(cur.le_u64().unwrap(), 2);
        assert_eq!(cur.pstring().unwrap(), "name");
        assert!(cur.is_empty());
        assert!(cur.u8().is_err());
    }

    #[test]
    fn truncated_chunk_is_an_error() {
        let mut o = Out::default();
        o.chunk(HDAT, |w| w.zeros(100));
        assert!(read_chunk(&o.buf[..50], 0).is_err());
        assert!(read_chunk(&o.buf, 200).is_err());
    }

    #[test]
    fn printable_tags() {
        assert_eq!(printable(FTOC), "FTOC");
        assert_eq!(printable(HHDR | 1), "HH\\x00\\x01");
        assert!(is_hhdr(HHDR | 13));
        assert!(!is_hhdr(HDAT));
    }

    #[test]
    fn align_pads_to_boundary() {
        let mut o = Out::default();
        o.zeros(5);
        o.align(16);
        assert_eq!(o.len(), 16);
        o.align(16);
        assert_eq!(o.len(), 16);
    }
}
