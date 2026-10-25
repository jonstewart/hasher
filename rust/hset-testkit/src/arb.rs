//! Hand-written `arbitrary::Arbitrary` impls for the fuzz targets, with the
//! same caps as the proptest strategies in [`crate::strategies`]. Reads past
//! the end of the input yield defaults, so these never fail for lack of data.

use arbitrary::{Arbitrary, Result, Unstructured};
use hset::HashType;
use hset::lookup::{BitsPolicy, HintSpec, SearchConfig};
use hset::synth::{adversarial_hashes, sort_unique_rows};

use crate::corrupt::{ChunkEdit, Corruption};
use crate::doc::{Doc, Field, Opts, STORABLE_TYPES};
use crate::strategies::{
    BATCH_MODES, BUDGETS, DENSE_BYTES, LookupCase, SINGLE_MODES, SUPPORTED_LENGTHS, TIMESTAMPS,
    TLSH_COALESCE, TLSH_LIST_SIZES, TLSH_MERGE_POLICIES, UNSUPPORTED_LENGTH, queries,
    with_duplicates,
};
use crate::tlsh::{DOC_FAMILIES, DOC_VALUE_KINDS, doc_value};

/// Field-name characters of the ASCII class of `strategies::field`.
const NAME_ASCII: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ -";
/// Field-name characters of the non-ASCII class of `strategies::field`.
const NAME_LATIN: &str = "abcdefghijklmnopqrstuvwxyzé";

fn string_of(u: &mut Unstructured<'_>, chars: &[char], max_len: usize) -> Result<String> {
    let len = u.int_in_range(0..=max_len)?;
    (0..len).map(|_| u.choose(chars).copied()).collect()
}

/// A field name of at most 32 bytes, as `strategies::field` draws them.
fn field_name(u: &mut Unstructured<'_>, htype: HashType) -> Result<String> {
    Ok(match u.int_in_range(0..=2u8)? {
        0 => htype.field_name().to_string(),
        1 => {
            let chars: Vec<char> = NAME_ASCII.iter().map(|&b| b as char).collect();
            string_of(u, &chars, 32)?
        }
        _ => {
            let chars: Vec<char> = NAME_LATIN.chars().collect();
            string_of(u, &chars, 16)?
        }
    })
}

fn value(u: &mut Unstructured<'_>, htype: HashType) -> Result<Vec<u8>> {
    Ok(match htype {
        HashType::Tlsh => {
            let kind = u.int_in_range(0..=DOC_VALUE_KINDS - 1)?;
            let family = u.int_in_range(0..=DOC_FAMILIES - 1)?;
            doc_value(kind, family, u64::arbitrary(u)?).0.to_vec()
        }
        HashType::Size => u64::arbitrary(u)?.to_le_bytes().to_vec(),
        HashType::Entropy => {
            let v = f64::arbitrary(u)?;
            let v = if v.is_finite() { v } else { 0.0 };
            v.to_le_bytes().to_vec()
        }
        _ => {
            let mut v = vec![0u8; htype.length().expect("storable type")];
            if bool::arbitrary(u)? {
                u.fill_buffer(&mut v)?;
            } else {
                for b in &mut v {
                    *b = *u.choose(&DENSE_BYTES)?;
                }
            }
            v
        }
    })
}

/// A hint as `strategies::hint_specs(hlen)` draws it.
fn hint(u: &mut Unstructured<'_>, hlen: usize) -> Result<HintSpec> {
    if hlen == UNSUPPORTED_LENGTH {
        return Ok(HintSpec::None);
    }
    let block_ok = hlen >= 4;
    Ok(match u.int_in_range(0..=2u8)? {
        0 => HintSpec::None,
        1 if block_ok => HintSpec::Block {
            bits: u.int_in_range(1..=12)?,
        },
        _ => HintSpec::Hull {
            bits: u.int_in_range(0..=12)?,
        },
    })
}

fn opts(u: &mut Unstructured<'_>) -> Result<Opts> {
    let printable: Vec<char> = (b' '..=b'~').map(char::from).collect();
    let name = string_of(u, &printable, 32)?;
    let desc = string_of(u, &printable, 32)?;
    let timestamp = u.choose(&TIMESTAMPS)?.to_string();
    let with_records = bool::arbitrary(u)?;
    let mut with_hashsets = bool::arbitrary(u)?;
    if !with_records && !with_hashsets {
        with_hashsets = true;
    }
    let hint = match u.int_in_range(0..=2u8)? {
        0 => hint(u, 8)?,
        1 => HintSpec::Hull { bits: u8::MAX },
        _ => HintSpec::Block { bits: 0 },
    };
    let budget = *u.choose(&BUDGETS)?;
    let min_bits = u.int_in_range(0..=4)?;
    let max_bits = u.int_in_range(min_bits..=12)?;
    let tlsh_index = u.ratio(3u8, 4)?;
    let tlsh_merge = *u.choose(&TLSH_MERGE_POLICIES)?;
    let tlsh_list_size = *u.choose(&TLSH_LIST_SIZES)?;
    let tlsh_coalesce = *u.choose(&TLSH_COALESCE)?;
    Ok(Opts {
        name,
        desc,
        timestamp,
        with_records,
        with_hashsets,
        hint,
        bits_policy: BitsPolicy {
            budget,
            min_bits,
            max_bits,
        },
        tlsh_index,
        tlsh_merge,
        tlsh_list_size,
        tlsh_coalesce,
    })
}

/// At most 4 fields of distinct types, 64 records, names of at most 32
/// bytes, finite entropies, and never both records and hash sets off.
impl<'a> Arbitrary<'a> for Doc {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut types = STORABLE_TYPES.to_vec();
        let k = u.int_in_range(1..=4usize)?;
        for i in 0..k {
            let j = u.int_in_range(i..=types.len() - 1)?;
            types.swap(i, j);
        }
        let fields = types[..k]
            .iter()
            .map(|&htype| {
                Ok(Field {
                    htype,
                    name: field_name(u, htype)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let n = u.int_in_range(0..=64usize)?;
        let mut records = Vec::with_capacity(n);
        for _ in 0..n {
            let mut r = Vec::with_capacity(k);
            for f in &fields {
                r.push(if u.ratio(3u8, 4)? {
                    Some(value(u, f.htype)?)
                } else {
                    None
                });
            }
            records.push(r);
        }
        Ok(Doc {
            fields,
            records,
            opts: opts(u)?,
        })
    }
}

/// As `strategies::lookup_case`: rows (taken last, from the rest of the
/// input, or adversarial from a seed) are sorted and unique before the
/// duplicate mask applies.
impl<'a> Arbitrary<'a> for LookupCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let i = u.int_in_range(0..=SUPPORTED_LENGTHS.len())?;
        let hlen = SUPPORTED_LENGTHS
            .get(i)
            .copied()
            .unwrap_or(UNSUPPORTED_LENGTH);
        let hint = hint(u, hlen)?;
        let passes_sub_batch = match u.int_in_range(0..=257usize)? {
            0 => 0,
            257 => 1000,
            k => k,
        };
        let cfg = SearchConfig {
            single: *u.choose(&SINGLE_MODES)?,
            batch: *u.choose(&BATCH_MODES)?,
            window_prefetch_bytes: u.int_in_range(1..=4096)?,
            region_bytes: u.int_in_range(1..=4096)?,
            passes_sub_batch,
        };
        let mask_len = u.int_in_range(0..=8usize)?;
        let mask = (0..mask_len)
            .map(|_| bool::arbitrary(u))
            .collect::<Result<Vec<_>>>()?;
        let seed = u64::arbitrary(u)?;
        let m = u.int_in_range(0..=300usize)?;
        let set = if bool::arbitrary(u)? {
            let count = u.int_in_range(0..=2000usize)?;
            adversarial_hashes(count, hlen, u64::arbitrary(u)?)
        } else {
            let n = (u.len() / hlen).min(2000);
            let mut data = u.bytes(n * hlen)?.to_vec();
            sort_unique_rows(&mut data, hlen);
            data
        };
        Ok(LookupCase {
            hlen,
            queries: queries(&set, hlen, seed, m),
            data: with_duplicates(set, hlen, &mask),
            hint,
            cfg,
        })
    }
}

/// A chunk-edit value as `strategies::corruption` draws it: anything, 0,
/// `u64::MAX`, 1, or at most 8192.
fn edit_value(u: &mut Unstructured<'_>) -> Result<u64> {
    Ok(match u.int_in_range(0..=4u8)? {
        0 => u64::arbitrary(u)?,
        1 => 0,
        2 => u64::MAX,
        3 => 1,
        _ => u.int_in_range(0..=8192)?,
    })
}

/// As `strategies::corruption`: any truncation, at most 16 overwrites and
/// at most 4 chunk edits (a `Type` edit keeps the value's low 32 bits).
impl<'a> Arbitrary<'a> for Corruption {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let truncate_to = Option::<usize>::arbitrary(u)?;
        let n = u.int_in_range(0..=16usize)?;
        let overwrites = (0..n)
            .map(|_| Ok((usize::arbitrary(u)?, u8::arbitrary(u)?)))
            .collect::<Result<Vec<_>>>()?;
        let k = u.int_in_range(0..=4usize)?;
        let chunk_edits = (0..k)
            .map(|_| {
                let kind = u.int_in_range(0..=2u8)?;
                let i = usize::arbitrary(u)?;
                let v = edit_value(u)?;
                Ok(match kind {
                    0 => ChunkEdit::Offset(i, v),
                    1 => ChunkEdit::Length(i, v),
                    _ => ChunkEdit::Type(i, v as u32),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Corruption {
            truncate_to,
            overwrites,
            chunk_edits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hset::synth::SplitMix64;
    use std::collections::BTreeSet;

    fn seed_bytes(seed: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        SplitMix64::new(seed).fill(&mut buf);
        buf
    }

    #[test]
    fn arbitrary_doc_respects_caps() {
        for seed in 0..200 {
            let buf = seed_bytes(seed);
            let d = Doc::arbitrary_take_rest(Unstructured::new(&buf)).unwrap();
            assert!((1..=4).contains(&d.fields.len()), "seed {seed}");
            let types: BTreeSet<HashType> = d.fields.iter().map(|f| f.htype).collect();
            assert_eq!(types.len(), d.fields.len(), "seed {seed}: duplicate types");
            assert!(d.records.len() <= 64, "seed {seed}");
            for f in &d.fields {
                assert!(f.name.len() <= 32, "seed {seed}: name {:?}", f.name);
            }
            for r in &d.records {
                assert_eq!(r.len(), d.fields.len(), "seed {seed}");
                for (f, v) in d.fields.iter().zip(r) {
                    if let Some(v) = v {
                        assert_eq!(v.len(), f.length(), "seed {seed}");
                        if f.htype == HashType::Tlsh {
                            let d = hset::tlsh::TlshDigest::from_bytes(v[..].try_into().unwrap());
                            assert!(d.is_ok_and(|d| !d.is_null()), "seed {seed}: {v:02x?}");
                        }
                    }
                }
            }
            assert!(d.opts.with_records || d.opts.with_hashsets, "seed {seed}");
        }
    }

    #[test]
    fn arbitrary_lookup_case_is_well_formed() {
        for seed in 0..200 {
            let buf = seed_bytes(seed);
            let c = LookupCase::arbitrary_take_rest(Unstructured::new(&buf)).unwrap();
            assert_eq!(c.data.len() % c.hlen, 0, "seed {seed}");
            let rows: Vec<&[u8]> = c.data.chunks_exact(c.hlen).collect();
            assert!(rows.is_sorted(), "seed {seed}: rows not sorted");
            match c.hint {
                HintSpec::None => {}
                HintSpec::Block { bits } | HintSpec::Hull { bits } => {
                    assert_ne!(c.hlen, UNSUPPORTED_LENGTH, "seed {seed}");
                    assert!(bits <= 12, "seed {seed}");
                }
            }
            assert_eq!(c.queries.len() % c.hlen, 0, "seed {seed}");
        }
    }
}
