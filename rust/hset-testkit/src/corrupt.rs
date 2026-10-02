//! A model of file corruption for the robustness property: structural
//! edits to the FTOC and chunk headers, byte overwrites and truncation.

use hset::format::decode;

/// Start of the FTOC's data: the 40-byte file header plus the FTOC's own
/// 12-byte chunk header.
const FTOC_DATA: usize = 52;
/// Bytes per FTOC entry: a u64 LE offset then a u32 BE type.
const FTOC_ENTRY: usize = 12;

/// A structural edit addressed by FTOC index (taken modulo the entry count).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkEdit {
    /// Rewrite FTOC entry `i`'s offset.
    Offset(usize, u64),
    /// Rewrite chunk `i`'s header length.
    Length(usize, u64),
    /// Rewrite chunk `i`'s header type, leaving its FTOC entry alone.
    Type(usize, u32),
}

/// A corruption of a file: chunk edits, then byte overwrites, then
/// truncation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Corruption {
    /// Truncate to `t % (len + 1)` bytes.
    pub truncate_to: Option<usize>,
    /// Set the byte at `pos % len` (skipped on an empty file).
    pub overwrites: Vec<(usize, u8)>,
    /// Structural edits, resolved through the original file's FTOC.
    pub chunk_edits: Vec<ChunkEdit>,
}

/// Copy `src` into `buf` at `at`, dropping whatever runs past the end.
fn write_clipped(buf: &mut [u8], at: usize, src: &[u8]) {
    if at < buf.len() {
        let n = src.len().min(buf.len() - at);
        buf[at..at + n].copy_from_slice(&src[..n]);
    }
}

impl Corruption {
    /// Chunk edits, then overwrites, then truncation. Chunk edits resolve
    /// through `hset::format::decode(bytes).toc`; `Offset(i, v)` rewrites FTOC
    /// entry `i % toc.len()`'s offset (bytes `52 + 12 * i ..+8`, LE); `Length(i, v)`
    /// rewrites the length field of chunk `i` (at `toc[i].0 + 4 ..+12`, LE);
    /// `Type(i, v)` rewrites the chunk's own header type (`toc[i].0 ..+4`, BE)
    /// leaving the FTOC entry alone. If the file does not decode, each edit
    /// falls back to writing its value's LE bytes at `i % len`. Overwrites
    /// land at `pos % len`; `truncate_to` truncates to `t % (len + 1)`.
    /// Every chunk index `i` is taken modulo `toc.len()`, and every write is
    /// clipped at the end of the buffer.
    pub fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        let mut m = bytes.to_vec();
        let toc: Vec<usize> = decode(bytes)
            .map(|f| {
                f.toc
                    .iter()
                    .map(|&(off, _)| usize::try_from(off).unwrap_or(usize::MAX))
                    .collect()
            })
            .unwrap_or_default();
        for e in &self.chunk_edits {
            if toc.is_empty() {
                if m.is_empty() {
                    continue;
                }
                let (i, v) = match *e {
                    ChunkEdit::Offset(i, v) | ChunkEdit::Length(i, v) => {
                        (i, v.to_le_bytes().to_vec())
                    }
                    ChunkEdit::Type(i, v) => (i, v.to_le_bytes().to_vec()),
                };
                let at = i % m.len();
                write_clipped(&mut m, at, &v);
                continue;
            }
            match *e {
                ChunkEdit::Offset(i, v) => {
                    let at = FTOC_DATA + FTOC_ENTRY * (i % toc.len());
                    write_clipped(&mut m, at, &v.to_le_bytes());
                }
                ChunkEdit::Length(i, v) => {
                    let at = toc[i % toc.len()].saturating_add(4);
                    write_clipped(&mut m, at, &v.to_le_bytes());
                }
                ChunkEdit::Type(i, v) => {
                    write_clipped(&mut m, toc[i % toc.len()], &v.to_be_bytes());
                }
            }
        }
        if !m.is_empty() {
            for &(pos, b) in &self.overwrites {
                let at = pos % m.len();
                m[at] = b;
            }
        }
        if let Some(t) = self.truncate_to {
            m.truncate(t % (m.len() + 1));
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::tests::two_field_doc;
    use hset::Hashset;
    use hset::format::decode;

    #[test]
    fn apply_identity() {
        let b = two_field_doc().build().unwrap();
        assert_eq!(Corruption::default().apply(&b), b);
    }

    #[test]
    fn truncate_is_modulo_len_plus_one() {
        let b = b"0123456789";
        let t = |n| {
            Corruption {
                truncate_to: Some(n),
                ..Corruption::default()
            }
            .apply(b)
        };
        assert_eq!(t(10), b.to_vec());
        assert_eq!(t(11), Vec::<u8>::new());
        assert_eq!(t(3), b"012".to_vec());
    }

    #[test]
    fn offset_edit_hits_the_toc_entry() {
        let b = two_field_doc().build().unwrap();
        let m = Corruption {
            chunk_edits: vec![ChunkEdit::Offset(1, 7)],
            ..Corruption::default()
        }
        .apply(&b);
        // Entry 1 sits at 52 + 12 * 1 (entry 0, at 52..60, is the FTOC's
        // own entry, offset 40).
        assert_eq!(m.len(), b.len());
        assert_eq!(m[64..72], 7u64.to_le_bytes());
        assert_eq!(m[..64], b[..64]);
        assert_eq!(m[72..], b[72..]);
    }

    #[test]
    fn length_edit_hits_the_chunk_header() {
        let b = two_field_doc().build().unwrap();
        let off = usize::try_from(decode(&b).unwrap().toc[2].0).unwrap();
        let m = Corruption {
            chunk_edits: vec![ChunkEdit::Length(2, 5)],
            ..Corruption::default()
        }
        .apply(&b);
        assert_eq!(m[off + 4..off + 12], 5u64.to_le_bytes());
        assert_eq!(m[..off + 4], b[..off + 4]);
        assert_eq!(m[off + 12..], b[off + 12..]);
    }

    #[test]
    fn type_edit_leaves_toc_alone() {
        let b = two_field_doc().build().unwrap();
        let off = usize::try_from(decode(&b).unwrap().toc[1].0).unwrap();
        let m = Corruption {
            chunk_edits: vec![ChunkEdit::Type(1, 0x4645_4E44)],
            ..Corruption::default()
        }
        .apply(&b);
        assert_eq!(&m[off..off + 4], b"FEND");
        // FTOC entry 1's type (after its 8-byte offset) is untouched.
        let entry = 52 + 12;
        assert_eq!(m[entry..entry + 12], b[entry..entry + 12]);
        assert_eq!(m[off + 4..], b[off + 4..]);
        assert_eq!(m[..off], b[..off]);
        let Err(err) = Hashset::load(&m) else {
            panic!("load must fail");
        };
        assert!(err.to_string().contains("FTOC says"), "{err}");
    }

    #[test]
    fn falls_back_to_raw_on_garbage() {
        let b = b"not a file";
        let m = Corruption {
            chunk_edits: vec![ChunkEdit::Offset(3, 1)],
            ..Corruption::default()
        }
        .apply(b);
        assert_eq!(m.len(), b.len());
        assert_eq!(m[..3], b[..3]);
        assert_eq!(m[3..], 1u64.to_le_bytes()[..7]);
    }
}
