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
/// TLSH inverted-file index; only after a TLSH section's `HDAT` / `RIDX`.
pub const TIVF: u32 = 0x5449_5646;
/// TLSH embedding vectors, written by older C++ builds; rejected.
pub const TVEC: u32 = 0x5456_4543;
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
    /// On error the position is unchanged, as for every other reader.
    pub fn pstring(&mut self) -> Result<String> {
        let start = self.pos;
        let len = usize::from(self.le_u16()?);
        let b = self.bytes(len).inspect_err(|_| self.pos = start)?;
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
    fn out_writers_emit_exact_bytes() {
        let o = Out::with_capacity(100);
        assert!(o.is_empty());
        assert!(o.buf.capacity() >= 100);
        let mut o = Out::default();
        o.le_i32(-2);
        o.le_i64(-3);
        assert!(!o.is_empty());
        assert_eq!(
            o.buf,
            [
                0xfe, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
        let mut o = Out::default();
        o.pstring("abc");
        assert_eq!(o.len(), pstring_len("abc"));
        assert_eq!(pstring_len("abc"), 5);
        assert_eq!(pstring_len(""), 2);
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Prim {
        U8(u8),
        LeU16(u16),
        LeU32(u32),
        LeU64(u64),
        BeU16(u16),
        BeU32(u32),
        Bytes(Vec<u8>),
        PString(String),
        Zeros(usize),
    }

    fn prim() -> impl Strategy<Value = Prim> {
        prop_oneof![
            any::<u8>().prop_map(Prim::U8),
            any::<u16>().prop_map(Prim::LeU16),
            any::<u32>().prop_map(Prim::LeU32),
            any::<u64>().prop_map(Prim::LeU64),
            any::<u16>().prop_map(Prim::BeU16),
            any::<u32>().prop_map(Prim::BeU32),
            vec(any::<u8>(), 0..=32).prop_map(Prim::Bytes),
            "\\PC{0,100}".prop_map(Prim::PString),
            (0usize..=16).prop_map(Prim::Zeros),
        ]
    }

    fn write(o: &mut Out, p: &Prim) {
        match p {
            // `Out` has no single-byte writer; one byte goes through `bytes`.
            Prim::U8(v) => o.bytes(&[*v]),
            Prim::LeU16(v) => o.le_u16(*v),
            Prim::LeU32(v) => o.le_u32(*v),
            Prim::LeU64(v) => o.le_u64(*v),
            Prim::BeU16(v) => o.be_u16(*v),
            Prim::BeU32(v) => o.be_u32(*v),
            Prim::Bytes(b) => o.bytes(b),
            Prim::PString(s) => o.pstring(s),
            Prim::Zeros(n) => o.zeros(*n),
        }
    }

    /// A reader op on a cursor.
    #[derive(Debug, Clone, Copy)]
    enum Read {
        U8,
        LeU16,
        LeU32,
        LeU64,
        BeU16,
        BeU32,
        PString,
        Bytes(usize),
    }

    fn apply(c: &mut Cursor<'_>, r: Read) -> Result<()> {
        match r {
            Read::U8 => c.u8().map(drop),
            Read::LeU16 => c.le_u16().map(drop),
            Read::LeU32 => c.le_u32().map(drop),
            Read::LeU64 => c.le_u64().map(drop),
            Read::BeU16 => c.be_u16().map(drop),
            Read::BeU32 => c.be_u32().map(drop),
            Read::PString => c.pstring().map(drop),
            Read::Bytes(n) => c.bytes(n).map(drop),
        }
    }

    /// Bytes `r` consumes at `pos` in `buf`, or `None` if it does not fit.
    /// Computed from the raw buffer, independently of `Cursor`; a pstring's
    /// width comes from its length prefix, not from the decoded (lossy) text.
    fn width(buf: &[u8], pos: usize, r: Read) -> Option<usize> {
        let w = match r {
            Read::U8 => 1,
            Read::LeU16 | Read::BeU16 => 2,
            Read::LeU32 | Read::BeU32 => 4,
            Read::LeU64 => 8,
            Read::Bytes(n) => n,
            Read::PString => {
                let p = buf.get(pos..pos.checked_add(2)?)?;
                2 + usize::from(u16::from_le_bytes([p[0], p[1]]))
            }
        };
        (w <= buf.len() - pos).then_some(w)
    }

    /// Shrunk case of `cursor_never_panics`: `pstring` read the length
    /// prefix (256), then failed on the body but left the cursor past the
    /// prefix. A failed read must not move the cursor.
    #[test]
    fn failed_pstring_leaves_position_unchanged() {
        let buf = [0u8, 0, 0, 1];
        let mut c = Cursor::new(&buf, 2).unwrap();
        assert!(c.pstring().is_err());
        assert_eq!(c.position(), 2);
    }

    proptest! {
        #[test]
        fn out_primitives_read_back(prims in vec(prim(), 0..=32)) {
            let mut o = Out::default();
            for p in &prims {
                write(&mut o, p);
            }
            let mut c = Cursor::new(&o.buf, 0).unwrap();
            for p in &prims {
                match p {
                    Prim::U8(v) => prop_assert_eq!(c.u8().unwrap(), *v),
                    Prim::LeU16(v) => prop_assert_eq!(c.le_u16().unwrap(), *v),
                    Prim::LeU32(v) => prop_assert_eq!(c.le_u32().unwrap(), *v),
                    Prim::LeU64(v) => prop_assert_eq!(c.le_u64().unwrap(), *v),
                    Prim::BeU16(v) => prop_assert_eq!(c.be_u16().unwrap(), *v),
                    Prim::BeU32(v) => prop_assert_eq!(c.be_u32().unwrap(), *v),
                    Prim::Bytes(b) => prop_assert_eq!(c.bytes(b.len()).unwrap(), b.as_slice()),
                    Prim::PString(s) => prop_assert_eq!(&c.pstring().unwrap(), s),
                    Prim::Zeros(n) => prop_assert!(c.bytes(*n).unwrap().iter().all(|&b| b == 0)),
                }
            }
            prop_assert!(c.is_empty());
        }

        // Kani harnesses for `Cursor` were attempted and dropped: the
        // `format!` on the symbolic error path does not converge
        // (`cursor_new_rejects_past_end` alone ran past 28 minutes; Ok-only
        // and Err-only halves each exceeded five). The coverage is this
        // proptest, `failed_pstring_leaves_position_unchanged` and the fuzz
        // `decode_bytes` target.
        #[test]
        fn cursor_never_panics(
            buf in vec(any::<u8>(), 0..=64),
            pos in prop_oneof![0usize..=70, any::<usize>()],
            n in 0usize..=70,
        ) {
            prop_assert_eq!(Cursor::new(&buf, pos).is_ok(), pos <= buf.len());
            if pos > buf.len() {
                return Ok(());
            }
            let reads = [
                Read::U8,
                Read::LeU16,
                Read::LeU32,
                Read::LeU64,
                Read::BeU16,
                Read::BeU32,
                Read::PString,
                Read::Bytes(n),
            ];
            // Each reader from a fresh cursor at `pos` ...
            for r in reads {
                let mut c = Cursor::new(&buf, pos).unwrap();
                let ok = apply(&mut c, r).is_ok();
                let w = width(&buf, pos, r);
                prop_assert_eq!(ok, w.is_some(), "{:?}", r);
                prop_assert_eq!(c.position(), pos + w.unwrap_or(0), "{:?}", r);
            }
            // ... and all of them in sequence on one cursor.
            let mut c = Cursor::new(&buf, pos).unwrap();
            for r in reads {
                let before = c.position();
                let ok = apply(&mut c, r).is_ok();
                let w = width(&buf, before, r);
                prop_assert_eq!(ok, w.is_some(), "{:?}", r);
                prop_assert_eq!(c.position(), before + w.unwrap_or(0), "{:?}", r);
            }
        }

        #[test]
        fn read_chunk_never_panics(
            buf in vec(any::<u8>(), 0..=64),
            off in prop_oneof![0usize..=70, any::<usize>()],
        ) {
            let expected = match off.checked_add(CHUNK_HEADER_LEN) {
                Some(end) if end <= buf.len() => {
                    let len = u64::from_le_bytes(buf[off + 4..end].try_into().unwrap());
                    len <= (buf.len() - end) as u64
                }
                _ => false,
            };
            prop_assert_eq!(read_chunk(&buf, off).is_ok(), expected);
        }

        #[test]
        fn pstring_roundtrip(s in "\\PC{0,300}") {
            let mut o = Out::default();
            o.pstring(&s);
            prop_assert_eq!(Cursor::new(&o.buf, 0).unwrap().pstring().unwrap(), s);
        }
    }
}
