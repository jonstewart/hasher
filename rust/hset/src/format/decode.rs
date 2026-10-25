//! Decoding an `.hset` byte buffer into an [`HsetFile`] view.

use super::chunk::{self, Chunk, Cursor, read_chunk};
use super::structs::*;
use crate::error::{Error, Result};
use crate::hash_type::HashType;
use crate::tlsh::DIGEST_LENGTH;
use crate::tlsh::cells::CellIndex;

fn parse_fhdr(ch: &Chunk<'_>) -> Result<FileHeader> {
    let mut c = Cursor::new(ch.data, 0)?;
    let version = c.le_u64()?;
    let name = c.pstring()?;
    let time = c.pstring()?;
    let desc = c.pstring()?;
    Ok(FileHeader {
        version,
        name,
        time,
        desc,
        sha2_256: [0; 32],
    })
}

fn parse_rhdr(ch: &Chunk<'_>) -> Result<RecordHeader> {
    let mut c = Cursor::new(ch.data, 0)?;
    let record_length = c.le_u64()?;
    let record_count = c.le_u64()?;
    let mut fields = Vec::new();
    let mut total = 0u64;
    while !c.is_empty() {
        let log2 = c.le_u16()?;
        let htype = HashType::from_log2(log2)
            .ok_or_else(|| Error::format(format!("unknown record field type 2^{log2}")))?;
        let name = c.pstring()?;
        let length = c.le_u64()?;
        if length >= 1 << 32 {
            return Err(Error::format(format!(
                "record field '{name}' has absurd length {length}"
            )));
        }
        total = total
            .checked_add(1 + length)
            .ok_or_else(|| Error::format("record length overflows"))?;
        fields.push(FieldDescriptor {
            htype,
            name,
            length,
        });
    }
    if total != record_length {
        return Err(Error::format(format!(
            "RHDR record length {record_length} does not match fields ({total})"
        )));
    }
    Ok(RecordHeader {
        record_length,
        record_count,
        fields,
    })
}

fn parse_hhdr(ch: &Chunk<'_>) -> Result<HashsetHeader> {
    let log2 = (ch.ty & !chunk::HHDR_MASK) as u16;
    let htype = HashType::from_log2(log2)
        .ok_or_else(|| Error::format(format!("unknown hash set type 2^{log2}")))?;
    let mut c = Cursor::new(ch.data, 0)?;
    let name = c.pstring()?;
    let hash_length = c.le_u64()?;
    let hash_count = c.le_u64()?;
    if hash_length == 0 {
        return Err(Error::format("hash length is zero"));
    }
    hash_count
        .checked_mul(hash_length)
        .ok_or_else(|| Error::format("hash set size overflows"))?;
    Ok(HashsetHeader {
        htype,
        name,
        hash_length,
        hash_count,
    })
}

/// Decode a HINT chunk of the section `header`. Block and hull tables of
/// the wrong size decode as [`Hint::Unknown`]; a TLSH cell index must be
/// valid, and only on a TLSH section (C++ checks the length and offsets
/// when it builds the lookup strategy, and the hash length; Rust also
/// requires the type).
fn parse_hint<'a>(ch: &Chunk<'a>, header: &HashsetHeader) -> Result<Hint<'a>> {
    let mut c = Cursor::new(ch.data, 0)?;
    let tag = c.be_u16()?;
    let rest = c.bytes(c.remaining())?;
    if tag == HINT_TLSH_CELLS {
        if header.htype != HashType::Tlsh || header.hash_length != DIGEST_LENGTH as u64 {
            return Err(Error::format(format!(
                "TLSH cell index hint on the {} hash set '{}' of hash length {}",
                header.htype, header.name, header.hash_length
            )));
        }
        let n = usize::try_from(header.hash_count)
            .map_err(|_| Error::format("hash count overflows usize"))?;
        CellIndex::parse(rest, n)?;
        return Ok(Hint::TlshCells { table: rest });
    }
    let family = (tag >> 8) as u8;
    let bits = (tag & 0xff) as u8;
    let hint = match family {
        b'b' if (1..=MAX_HINT_BITS).contains(&bits) && rest.len() == BLOCK_ENTRY_LEN << bits => {
            Hint::Block { bits, table: rest }
        }
        b'h' if bits <= MAX_HINT_BITS && rest.len() == HULL_ENTRY_LEN << bits => {
            Hint::Hull { bits, table: rest }
        }
        _ => Hint::Unknown { tag, data: rest },
    };
    Ok(hint)
}

fn expect_len(ch: &Chunk<'_>, expected: u64) -> Result<()> {
    if ch.data.len() as u64 != expected {
        return Err(Error::format(format!(
            "expected {expected} bytes in {}, found {}",
            chunk::printable(ch.ty),
            ch.data.len()
        )));
    }
    Ok(())
}

/// Decode a complete `.hset` file held in memory.
///
/// The returned structure borrows `buf`; hash data is not copied. The file's
/// SHA-256 is read but not verified (see [`crate::Hashset::verify_digest`]).
pub fn decode(buf: &[u8]) -> Result<HsetFile<'_>> {
    if buf.len() < chunk::FIRST_CHUNK_OFFSET {
        return Err(Error::format("file too short"));
    }
    if &buf[..8] != chunk::MAGIC {
        return Err(Error::format("bad magic"));
    }
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&buf[chunk::SHA_OFFSET..chunk::FIRST_CHUNK_OFFSET]);

    let ftoc = read_chunk(buf, chunk::FIRST_CHUNK_OFFSET);
    let ftoc = match ftoc {
        Ok(c) if c.ty == chunk::FTOC => c,
        other => {
            // Version 1 files have a fixed header with the version at offset 8.
            if buf[8..16] == 1u64.to_le_bytes() {
                return Err(Error::format(
                    "version 1 hash set files (fixed header, no chunks) are not supported",
                ));
            }
            return match other {
                Ok(c) => Err(Error::format(format!(
                    "expected FTOC, found {}",
                    chunk::printable(c.ty)
                ))),
                Err(e) => Err(e),
            };
        }
    };
    let mut toc = Vec::new();
    {
        let mut c = Cursor::new(ftoc.data, 0)?;
        while !c.is_empty() {
            let off = c.le_u64()?;
            let ty = c.be_u32()?;
            toc.push((off, ty));
        }
    }

    let mut fhdr: Option<FileHeader> = None;
    let mut rhdr: Option<RecordHeader> = None;
    let mut rdat: Option<&[u8]> = None;
    let mut sections: Vec<Section<'_>> = Vec::new();
    // A section is "open" until its HDAT has been seen.
    let mut open = false;
    let mut ended = false;

    for (i, &(off, ty)) in toc.iter().enumerate() {
        if ended {
            return Err(Error::format("chunks listed after FEND"));
        }
        let off =
            usize::try_from(off).map_err(|_| Error::format("chunk offset overflows usize"))?;
        let ch = read_chunk(buf, off)?;
        if ch.ty != ty {
            return Err(Error::format(format!(
                "FTOC says {} at offset {off}, found {}",
                chunk::printable(ty),
                chunk::printable(ch.ty)
            )));
        }
        let unexpected = |what: &str| {
            Error::format(format!(
                "unexpected {} chunk ({what})",
                chunk::printable(ty)
            ))
        };

        match ty {
            chunk::FTOC => {
                if i != 0 {
                    return Err(unexpected("FTOC must be the first chunk"));
                }
            }
            chunk::FHDR => {
                if fhdr.is_some() {
                    return Err(unexpected("duplicate FHDR"));
                }
                fhdr = Some(parse_fhdr(&ch)?);
            }
            chunk::RHDR => {
                if rhdr.is_some() {
                    return Err(unexpected("duplicate RHDR"));
                }
                if open {
                    return Err(unexpected("inside a hash set section"));
                }
                rhdr = Some(parse_rhdr(&ch)?);
            }
            chunk::RDAT => {
                let Some(r) = rhdr.as_ref() else {
                    return Err(unexpected("RDAT without RHDR"));
                };
                if rdat.is_some() {
                    return Err(unexpected("duplicate RDAT"));
                }
                let expected = r
                    .record_count
                    .checked_mul(r.record_length)
                    .ok_or_else(|| Error::format("record data size overflows"))?;
                expect_len(&ch, expected)?;
                rdat = Some(ch.data);
            }
            t if chunk::is_hhdr(t) => {
                if open {
                    return Err(unexpected("previous hash set has no HDAT"));
                }
                let header = parse_hhdr(&ch)?;
                sections.push(Section {
                    header,
                    hint: None,
                    data: &[],
                    ridx: None,
                    tivf: None,
                });
                open = true;
            }
            chunk::HINT => {
                let Some(s) = sections.last_mut().filter(|_| open) else {
                    return Err(unexpected("HINT outside a hash set section"));
                };
                if s.hint.is_some() {
                    return Err(unexpected("duplicate HINT"));
                }
                s.hint = Some(parse_hint(&ch, &s.header)?);
            }
            chunk::FLTR => {
                if !open {
                    return Err(unexpected("FLTR outside a hash set section"));
                }
                // Filters are not used by this implementation.
            }
            chunk::HDAT => {
                let Some(s) = sections.last_mut().filter(|_| open) else {
                    return Err(unexpected("HDAT outside a hash set section"));
                };
                expect_len(&ch, s.header.hash_count * s.header.hash_length)?;
                s.data = ch.data;
                open = false;
            }
            chunk::RIDX => {
                let Some(s) = sections.last_mut().filter(|_| !open) else {
                    return Err(unexpected("RIDX must follow HDAT"));
                };
                if s.ridx.is_some() {
                    return Err(unexpected("duplicate RIDX"));
                }
                if s.tivf.is_some() {
                    return Err(unexpected("RIDX must precede TIVF"));
                }
                let expected = s
                    .header
                    .hash_count
                    .checked_mul(8)
                    .ok_or_else(|| Error::format("record index size overflows"))?;
                expect_len(&ch, expected)?;
                s.ridx = Some(ch.data);
            }
            chunk::TIVF => {
                // HDAT [RIDX] [TIVF]: the chunk before is this section's
                // HDAT or RIDX.
                let follows_data = i > 0 && matches!(toc[i - 1].1, chunk::HDAT | chunk::RIDX);
                let Some(s) = sections.last_mut().filter(|_| follows_data) else {
                    return Err(unexpected("TIVF must follow HDAT or RIDX"));
                };
                if s.header.htype != HashType::Tlsh {
                    return Err(unexpected(&format!(
                        "TIVF in the {} hash set '{}'",
                        s.header.htype, s.header.name
                    )));
                }
                s.tivf = Some(ch.data);
            }
            chunk::TVEC => {
                return Err(Error::format(
                    "TVEC chunk (TLSH embedding vectors) is no longer part of the \
                     format and is not read; rebuild the file without it",
                ));
            }
            chunk::FEND => {
                if open {
                    return Err(unexpected("hash set has no HDAT"));
                }
                ended = true;
            }
            other => {
                return Err(Error::format(format!(
                    "unknown chunk type {}",
                    chunk::printable(other)
                )));
            }
        }
    }

    if !ended {
        return Err(Error::format("missing FEND chunk"));
    }
    let mut fhdr = fhdr.ok_or_else(|| Error::format("missing FHDR chunk"))?;
    fhdr.sha2_256 = sha;
    if rhdr.is_some() && rdat.is_none() {
        return Err(Error::format("RHDR without RDAT"));
    }

    Ok(HsetFile {
        fhdr,
        rhdr,
        rdat,
        sections,
        toc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(matches!(decode(b"12345"), Err(Error::Format(_))));
        let mut junk = vec![0u8; 64];
        junk[..8].copy_from_slice(b"SetOHash");
        assert!(decode(&junk).is_err());
        let mut bad_magic = vec![0u8; 64];
        bad_magic[..8].copy_from_slice(b"NotAHash");
        assert!(decode(&bad_magic).is_err());
    }

    #[test]
    fn a_short_buffer_is_too_short_only_below_the_first_chunk() {
        let mut buf = vec![0u8; chunk::FIRST_CHUNK_OFFSET];
        buf[..8].copy_from_slice(chunk::MAGIC);
        let short = decode(&buf[..chunk::FIRST_CHUNK_OFFSET - 1]).unwrap_err();
        assert!(short.to_string().contains("file too short"), "{short}");
        // 40 bytes hold the whole preamble; what is missing is the FTOC.
        let e = decode(&buf).unwrap_err();
        assert!(!e.to_string().contains("file too short"), "{e}");
    }

    /// A one-section file whose hint chunk is `tag` followed by `table`.
    fn with_hint(tag: u16, table: &[u8]) -> Vec<u8> {
        let hashes = [0u8; 32];
        super::super::encode(&super::super::Document {
            version: FORMAT_VERSION,
            name: "",
            desc: "",
            time: "",
            records: None,
            hashsets: vec![super::super::HashsetIn {
                htype: HashType::Md5,
                name: "md5",
                hash_length: 16,
                data: &hashes,
                hint: Some((tag, table)),
                ridx: None,
                tivf: None,
            }],
        })
        .unwrap()
    }

    #[test]
    fn hints_with_bad_bits_or_table_length_decode_as_unknown() {
        let table = [7u8; 3 * 16];
        let hint = |tag, len| {
            let buf = with_hint(tag, &table[..len]);
            let f = decode(&buf).unwrap();
            f.sections[0]
                .hint
                .map(|h| (h.tag(), matches!(h, Hint::Unknown { .. })))
        };
        // Block: 1..=24 bits and 16 << bits table bytes.
        assert_eq!(hint(hint_tag_block(1), 32), Some((0x6201, false)));
        assert_eq!(hint(hint_tag_block(1), 31), Some((0x6201, true)));
        assert_eq!(hint(hint_tag_block(0), 16), Some((0x6200, true)));
        assert_eq!(hint(hint_tag_block(25), 0), Some((0x6219, true)));
        // Hull: 0..=24 bits and 12 << bits table bytes.
        assert_eq!(hint(hint_tag_hull(1), 24), Some((0x6801, false)));
        assert_eq!(hint(hint_tag_hull(0), 12), Some((0x6800, false)));
        assert_eq!(hint(hint_tag_hull(1), 23), Some((0x6801, true)));
        assert_eq!(hint(hint_tag_hull(25), 0), Some((0x6819, true)));
    }

    /// FTOC, FHDR, then `body` chunks, then FEND, with the FTOC filled in.
    fn assemble(body: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let n = body.len() + 3;
        let mut o = chunk::Out::default();
        o.bytes(chunk::MAGIC);
        o.zeros(32);
        let mut toc = vec![(o.chunk(chunk::FTOC, |w| w.zeros(12 * n)), chunk::FTOC)];
        let fhdr = o.chunk(chunk::FHDR, |w| {
            w.le_u64(FORMAT_VERSION);
            w.pstring("n");
            w.pstring("t");
            w.pstring("d");
        });
        toc.push((fhdr, chunk::FHDR));
        for (ty, data) in body {
            toc.push((o.chunk(*ty, |w| w.bytes(data)), *ty));
        }
        toc.push((o.chunk(chunk::FEND, |_| {}), chunk::FEND));
        let mut p = toc[0].0 + chunk::CHUNK_HEADER_LEN;
        for (off, ty) in toc {
            o.buf[p..p + 8].copy_from_slice(&(off as u64).to_le_bytes());
            o.buf[p + 8..p + 12].copy_from_slice(&ty.to_be_bytes());
            p += 12;
        }
        o.buf
    }

    #[test]
    fn filters_are_skipped_inside_a_section_and_rejected_outside() {
        let mut hhdr = chunk::Out::default();
        hhdr.pstring("md5");
        hhdr.le_u64(16);
        hhdr.le_u64(1);
        let hhdr = (chunk::HHDR | u32::from(HashType::Md5.log2()), hhdr.buf);
        let hdat = (chunk::HDAT, vec![0x5a; 16]);
        let fltr = (chunk::FLTR, vec![1, 2, 3]);

        let inside = assemble(&[hhdr.clone(), fltr.clone(), hdat.clone()]);
        let f = decode(&inside).unwrap();
        assert_eq!(f.sections.len(), 1);
        assert_eq!(f.sections[0].data, &[0x5a; 16]);

        let outside = assemble(&[fltr, hhdr, hdat]);
        let e = decode(&outside).unwrap_err();
        assert!(e.to_string().contains("FLTR outside"), "{e}");
    }

    #[test]
    fn version_1_is_reported_clearly() {
        let mut v1 = vec![0u8; 4096];
        v1[..8].copy_from_slice(b"SetOHash");
        v1[8] = 1;
        let err = decode(&v1).unwrap_err().to_string();
        assert!(err.contains("version 1"), "{err}");
    }

    // TLSH sections: the 0x7400 cell hint, TIVF placement, TVEC rejection.

    type Chunks = Vec<(u32, Vec<u8>)>;

    fn hhdr(htype: HashType, hash_length: u64, count: u64) -> (u32, Vec<u8>) {
        let mut o = chunk::Out::default();
        o.pstring(htype.field_name());
        o.le_u64(hash_length);
        o.le_u64(count);
        (chunk::HHDR | u32::from(htype.log2()), o.buf)
    }

    /// The HINT chunk of a cell index whose rows all sit in cell 0.
    fn cells_hint(n: u64) -> (u32, Vec<u8>) {
        let mut cells = vec![n; crate::tlsh::cells::CELL_INDEX_LEN];
        cells[0] = 0;
        let mut data = HINT_TLSH_CELLS.to_be_bytes().to_vec();
        data.extend(crate::tlsh::cells::cell_table(&cells));
        (chunk::HINT, data)
    }

    /// One TLSH section of two all-zero rows (cell 0).
    fn tlsh_section() -> Chunks {
        vec![
            hhdr(HashType::Tlsh, 36, 2),
            cells_hint(2),
            (chunk::HDAT, vec![0; 72]),
        ]
    }

    fn with(mut chunks: Chunks, more: &[(u32, Vec<u8>)]) -> Chunks {
        chunks.extend_from_slice(more);
        chunks
    }

    fn ridx() -> (u32, Vec<u8>) {
        (chunk::RIDX, vec![0; 16])
    }

    fn tivf() -> (u32, Vec<u8>) {
        (chunk::TIVF, b"tivf".to_vec())
    }

    fn decode_err(chunks: &[(u32, Vec<u8>)]) -> String {
        match decode(&assemble(chunks)) {
            Err(e @ Error::Format(_)) => e.to_string(),
            Err(e) => panic!("expected a format error, got {e}"),
            Ok(f) => panic!("expected a format error, decoded {:?}", f.toc),
        }
    }

    #[test]
    fn a_hand_built_tlsh_section_decodes() {
        for tail in [vec![], vec![tivf()], vec![ridx(), tivf()]] {
            let buf = assemble(&with(tlsh_section(), &tail));
            let f = decode(&buf).unwrap();
            let s = &f.sections[0];
            assert!(matches!(s.hint, Some(Hint::TlshCells { table }) if table.len() == 524296));
            assert_eq!(s.tivf.is_some(), !tail.is_empty());
            assert_eq!(s.ridx.is_some(), tail.len() == 2);
        }
    }

    #[test]
    fn a_cell_hint_outside_a_36_byte_tlsh_section_is_rejected() {
        let md5 = [
            hhdr(HashType::Md5, 16, 2),
            cells_hint(2),
            (chunk::HDAT, vec![0; 32]),
        ];
        let e = decode_err(&md5);
        assert!(e.contains("TLSH cell index hint on the MD5"), "{e}");
        let short = [
            hhdr(HashType::Tlsh, 35, 2),
            cells_hint(2),
            (chunk::HDAT, vec![0; 70]),
        ];
        let e = decode_err(&short);
        assert!(e.contains("hash length 35"), "{e}");
    }

    #[test]
    fn a_bad_cell_index_is_rejected() {
        let mut wrong_n = tlsh_section();
        wrong_n[1] = cells_hint(3);
        let e = decode_err(&wrong_n);
        assert!(e.contains("last offset is 3, expected 2"), "{e}");
        let mut short = tlsh_section();
        short[1].1.pop();
        let e = decode_err(&short);
        assert!(e.contains("bad TLSH cell index"), "{e}");
    }

    #[test]
    fn tivf_outside_a_tlsh_section_is_rejected() {
        let md5 = [
            hhdr(HashType::Md5, 16, 1),
            (chunk::HDAT, vec![0; 16]),
            tivf(),
        ];
        let e = decode_err(&md5);
        assert!(e.contains("TIVF in the MD5 hash set 'md5'"), "{e}");
    }

    #[test]
    fn tivf_must_follow_the_sections_hdat_or_ridx() {
        // Before HDAT.
        let mut before = tlsh_section();
        before.insert(2, tivf());
        let e = decode_err(&before);
        assert!(e.contains("TIVF must follow HDAT or RIDX"), "{e}");
        // Twice.
        let e = decode_err(&with(tlsh_section(), &[tivf(), tivf()]));
        assert!(e.contains("TIVF must follow HDAT or RIDX"), "{e}");
        // After records that follow a closed section.
        let mut rhdr = chunk::Out::default();
        rhdr.le_u64(0);
        rhdr.le_u64(0);
        let records = [(chunk::RHDR, rhdr.buf), (chunk::RDAT, vec![])];
        let e = decode_err(&with(with(tlsh_section(), &records), &[tivf()]));
        assert!(e.contains("TIVF must follow HDAT or RIDX"), "{e}");
        // As the first chunk after the FHDR.
        let e = decode_err(&[tivf()]);
        assert!(e.contains("TIVF must follow HDAT or RIDX"), "{e}");
    }

    #[test]
    fn ridx_after_tivf_is_rejected() {
        let e = decode_err(&with(tlsh_section(), &[tivf(), ridx()]));
        assert!(e.contains("RIDX must precede TIVF"), "{e}");
    }

    #[test]
    fn tvec_is_rejected_by_name() {
        let tvec = (chunk::TVEC, vec![0; 32]);
        for chunks in [
            with(tlsh_section(), std::slice::from_ref(&tvec)),
            with(tlsh_section(), &[ridx(), tvec.clone(), tivf()]),
            vec![tvec.clone()],
        ] {
            let e = decode_err(&chunks);
            assert!(e.contains("TVEC chunk"), "{e}");
            assert!(!e.contains("unknown chunk"), "{e}");
        }
    }
}
