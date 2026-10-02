//! Decoding an `.hset` byte buffer into an [`HsetFile`] view.

use super::chunk::{self, Chunk, Cursor, read_chunk};
use super::structs::*;
use crate::error::{Error, Result};
use crate::hash_type::HashType;

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

fn parse_hint<'a>(ch: &Chunk<'a>) -> Result<Hint<'a>> {
    let mut c = Cursor::new(ch.data, 0)?;
    let tag = c.be_u16()?;
    let rest = c.bytes(c.remaining())?;
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
                s.hint = Some(parse_hint(&ch)?);
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
                let expected = s
                    .header
                    .hash_count
                    .checked_mul(8)
                    .ok_or_else(|| Error::format("record index size overflows"))?;
                expect_len(&ch, expected)?;
                s.ridx = Some(ch.data);
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
    fn version_1_is_reported_clearly() {
        let mut v1 = vec![0u8; 4096];
        v1[..8].copy_from_slice(b"SetOHash");
        v1[8] = 1;
        let err = decode(&v1).unwrap_err().to_string();
        assert!(err.contains("version 1"), "{err}");
    }
}
