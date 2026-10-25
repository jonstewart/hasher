//! Decoded views of the format's chunks.

use crate::hash_type::HashType;

/// Current file format version written by this crate.
pub const FORMAT_VERSION: u64 = 2;

/// Contents of the `FHDR` chunk plus the file digest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileHeader {
    pub version: u64,
    pub name: String,
    pub time: String,
    pub desc: String,
    pub sha2_256: [u8; 32],
}

/// One field of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub htype: HashType,
    pub name: String,
    pub length: u64,
}

impl FieldDescriptor {
    /// The canonical descriptor for a storable hash type.
    pub fn for_type(t: HashType) -> Option<FieldDescriptor> {
        Some(FieldDescriptor {
            htype: t,
            name: t.field_name().to_string(),
            length: t.length()? as u64,
        })
    }

    /// Bytes this field occupies in a record: presence byte plus value.
    pub fn stride(&self) -> usize {
        1 + self.length as usize
    }
}

/// Contents of the `RHDR` chunk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordHeader {
    pub record_length: u64,
    pub record_count: u64,
    pub fields: Vec<FieldDescriptor>,
}

impl RecordHeader {
    /// Byte offset of the field of type `t` within a record (its presence
    /// byte), or `None` if the record has no such field.
    pub fn field_offset(&self, t: HashType) -> Option<usize> {
        let mut off = 0usize;
        for f in &self.fields {
            if f.htype == t {
                return Some(off);
            }
            off += f.stride();
        }
        None
    }

    /// Record length implied by the field descriptors.
    pub fn computed_record_length(&self) -> usize {
        self.fields.iter().map(FieldDescriptor::stride).sum()
    }
}

/// Contents of an `HHnn` chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashsetHeader {
    pub htype: HashType,
    pub name: String,
    pub hash_length: u64,
    pub hash_count: u64,
}

/// Hint type tag of the legacy flat 8-bit block table (`'b'`, 8).
pub const HINT_BLOCK8_LEGACY: u16 = 0x6208;

/// Hint type tag for a flat min/max block table over the top `bits` bits.
pub const fn hint_tag_block(bits: u8) -> u16 {
    0x6200 | bits as u16
}

/// Hint type tag for a convex-hull fitted block table over the top `bits` bits.
pub const fn hint_tag_hull(bits: u8) -> u16 {
    0x6800 | bits as u16
}

/// Hint type tag of the TLSH cell index ([`crate::tlsh::CELL_HINT_TAG`]).
pub const HINT_TLSH_CELLS: u16 = crate::tlsh::CELL_HINT_TAG;

/// Bytes per entry of a flat block table (`min i64`, `max i64`).
pub const BLOCK_ENTRY_LEN: usize = 16;
/// Bytes per entry of a hull table (`slope u32`, `rmin i32`, `rmax i32`).
pub const HULL_ENTRY_LEN: usize = 12;

/// Largest block-bit count any hint may use.
pub const MAX_HINT_BITS: u8 = 24;

/// A decoded `HINT` chunk, borrowing its table from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint<'a> {
    /// Flat per-block `[min, max]` deviation from the expected index.
    Block { bits: u8, table: &'a [u8] },
    /// Per-block fixed-point line fitted via convex hull with exact residual bounds.
    Hull { bits: u8, table: &'a [u8] },
    /// The TLSH cell index (tag `0x7400`): [`crate::tlsh::cells::CELL_INDEX_LEN`]
    /// little-endian `u64` row offsets, one per (L, Q) cell plus the row
    /// count. The decoder has checked it with
    /// [`crate::tlsh::cells::CellIndex::parse`].
    TlshCells { table: &'a [u8] },
    /// A hint this crate does not understand (ignored; lookups fall back to binary search).
    Unknown { tag: u16, data: &'a [u8] },
}

impl Hint<'_> {
    /// The on-disk hint type tag.
    pub fn tag(&self) -> u16 {
        match self {
            Hint::Block { bits, .. } => hint_tag_block(*bits),
            Hint::Hull { bits, .. } => hint_tag_hull(*bits),
            Hint::TlshCells { .. } => HINT_TLSH_CELLS,
            Hint::Unknown { tag, .. } => *tag,
        }
    }

    /// Short human-readable description.
    pub fn describe(&self) -> String {
        match self {
            Hint::Block { bits, .. } => {
                format!("block{bits} (flat min/max, {} entries)", 1usize << bits)
            }
            Hint::Hull { bits, .. } => {
                format!("hull{bits} (convex-hull lines, {} entries)", 1usize << bits)
            }
            Hint::TlshCells { table } => {
                format!("tlsh cells (cell index, {} offsets)", table.len() / 8)
            }
            Hint::Unknown { tag, data } => format!("unknown 0x{tag:04x} ({} bytes)", data.len()),
        }
    }

    /// Size in bytes of the hint data including the 2-byte tag.
    pub fn byte_len(&self) -> usize {
        2 + match self {
            Hint::Block { table, .. } | Hint::Hull { table, .. } | Hint::TlshCells { table } => {
                table.len()
            }
            Hint::Unknown { data, .. } => data.len(),
        }
    }
}

/// One hash set section: header, optional hint, sorted hashes, optional record index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section<'a> {
    pub header: HashsetHeader,
    pub hint: Option<Hint<'a>>,
    /// `hash_count * hash_length` bytes of sorted hashes.
    pub data: &'a [u8],
    /// `hash_count` little-endian `u64` record indices, if present.
    pub ridx: Option<&'a [u8]>,
    /// The raw payload of a TLSH section's `TIVF` index chunk, if present;
    /// [`crate::tlsh::ivf`] parses it.
    pub tivf: Option<&'a [u8]>,
}

impl<'a> Section<'a> {
    pub fn hash_length(&self) -> usize {
        self.header.hash_length as usize
    }

    pub fn len(&self) -> usize {
        self.header.hash_count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `i`th hash.
    pub fn hash(&self, i: usize) -> &'a [u8] {
        let l = self.hash_length();
        &self.data[i * l..(i + 1) * l]
    }

    /// Record index of the `i`th hash, if the section has a record index.
    pub fn record_index(&self, i: usize) -> Option<u64> {
        let r = self.ridx?;
        Some(u64::from_le_bytes(r[i * 8..i * 8 + 8].try_into().unwrap()))
    }
}

/// A fully decoded `.hset` file, borrowing the underlying bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsetFile<'a> {
    pub fhdr: FileHeader,
    pub rhdr: Option<RecordHeader>,
    /// `record_count * record_length` bytes of sorted records.
    pub rdat: Option<&'a [u8]>,
    pub sections: Vec<Section<'a>>,
    /// Table of contents as `(offset, chunk type)`.
    pub toc: Vec<(u64, u32)>,
}

impl<'a> HsetFile<'a> {
    /// Index of the section holding hashes of type `t`.
    pub fn section_for(&self, t: HashType) -> Option<usize> {
        self.sections.iter().position(|s| s.header.htype == t)
    }

    /// Number of records (0 if there are none).
    pub fn record_count(&self) -> usize {
        self.rhdr.as_ref().map_or(0, |r| r.record_count as usize)
    }

    /// The `i`th record, if records are present.
    pub fn record(&self, i: usize) -> Option<&'a [u8]> {
        let rhdr = self.rhdr.as_ref()?;
        let rl = usize::try_from(rhdr.record_length).ok()?;
        let start = i.checked_mul(rl)?;
        let end = start.checked_add(rl)?;
        self.rdat?.get(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_lengths() {
        let rh = RecordHeader {
            record_length: 0,
            record_count: 0,
            fields: vec![
                FieldDescriptor::for_type(HashType::Md5).unwrap(),
                FieldDescriptor::for_type(HashType::Size).unwrap(),
            ],
        };
        assert_eq!(rh.computed_record_length(), 17 + 9);
        assert_eq!(RecordHeader::default().computed_record_length(), 0);

        let table = [0u8; 24];
        assert_eq!(
            Hint::Block {
                bits: 1,
                table: &table
            }
            .byte_len(),
            26
        );
        assert_eq!(
            Hint::Hull {
                bits: 1,
                table: &table[..12]
            }
            .byte_len(),
            14
        );
        assert_eq!(Hint::Unknown { tag: 0, data: &[] }.byte_len(), 2);

        let header = |hash_count| HashsetHeader {
            htype: HashType::Md5,
            name: String::new(),
            hash_length: 16,
            hash_count,
        };
        let section = |hash_count| Section {
            header: header(hash_count),
            hint: None,
            data: &[],
            ridx: None,
            tivf: None,
        };
        assert!(section(0).is_empty());
        assert!(!section(1).is_empty());
    }
}
