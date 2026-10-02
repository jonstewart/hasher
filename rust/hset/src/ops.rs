//! Set operations on record-bearing hash sets.
//!
//! Both operands must carry the same set of field types. Records are
//! rewritten into a common layout (fields in ascending type order), sorted and
//! de-duplicated, and merged. The result is returned as a [`Builder`] so the
//! caller chooses the output options.

use std::collections::BTreeSet;

use crate::builder::Builder;
use crate::error::{Error, Result};
use crate::format::{FieldDescriptor, HsetFile};
use crate::hash_type::HashType;

/// A binary set operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOp {
    Union,
    Intersect,
    /// Left minus right.
    Subtract,
}

impl SetOp {
    pub fn name(self) -> &'static str {
        match self {
            SetOp::Union => "union",
            SetOp::Intersect => "intersection",
            SetOp::Subtract => "difference",
        }
    }
}

/// The records of `f` as fixed-width rows, or, for a file without records
/// that has exactly one hash section, each hash wrapped as a one-field record.
fn records_of(f: &HsetFile<'_>) -> Result<(Vec<FieldDescriptor>, Vec<u8>)> {
    if let (Some(rhdr), Some(rdat)) = (&f.rhdr, f.rdat) {
        return Ok((rhdr.fields.clone(), rdat.to_vec()));
    }
    match f.sections.as_slice() {
        [s] => {
            let fd = FieldDescriptor {
                htype: s.header.htype,
                name: s.header.name.clone(),
                length: s.header.hash_length,
            };
            let hl = s.hash_length();
            let mut rows = Vec::with_capacity(s.len() * (hl + 1));
            for i in 0..s.len() {
                rows.push(1);
                rows.extend_from_slice(s.hash(i));
            }
            Ok((vec![fd], rows))
        }
        [] => Err(Error::input(format!(
            "'{}' has no records and no hashes",
            f.fhdr.name
        ))),
        _ => Err(Error::input(format!(
            "'{}' has several hash sections but no records; set operations need records",
            f.fhdr.name
        ))),
    }
}

/// Rewrite rows with layout `from` into layout `to` (fields matched by type).
fn relayout(from: &[FieldDescriptor], rows: &[u8], to: &[FieldDescriptor]) -> Vec<u8> {
    let from_len: usize = from.iter().map(FieldDescriptor::stride).sum();
    let to_len: usize = to.iter().map(FieldDescriptor::stride).sum();
    let mut src_off: Vec<Option<usize>> = Vec::with_capacity(to.len());
    for tf in to {
        let mut off = 0usize;
        let mut found = None;
        for ff in from {
            if ff.htype == tf.htype {
                found = Some(off);
                break;
            }
            off += ff.stride();
        }
        src_off.push(found);
    }
    let mut out = Vec::with_capacity((rows.len() / from_len.max(1)) * to_len);
    for r in rows.chunks_exact(from_len) {
        for (tf, so) in to.iter().zip(&src_off) {
            match so {
                Some(o) => out.extend_from_slice(&r[*o..*o + tf.stride()]),
                None => out.resize(out.len() + tf.stride(), 0),
            }
        }
    }
    out
}

fn row(d: &[u8], k: usize, width: usize) -> &[u8] {
    &d[k * width..(k + 1) * width]
}

/// Merge two sorted, unique row sets.
fn merge(op: SetOp, a: &[u8], b: &[u8], width: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len().max(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    let (na, nb) = (a.len() / width, b.len() / width);
    while i < na && j < nb {
        match row(a, i, width).cmp(row(b, j, width)) {
            std::cmp::Ordering::Less => {
                if matches!(op, SetOp::Union | SetOp::Subtract) {
                    out.extend_from_slice(row(a, i, width));
                }
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                if op == SetOp::Union {
                    out.extend_from_slice(row(b, j, width));
                }
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if matches!(op, SetOp::Union | SetOp::Intersect) {
                    out.extend_from_slice(row(a, i, width));
                }
                i += 1;
                j += 1;
            }
        }
    }
    if matches!(op, SetOp::Union | SetOp::Subtract) {
        out.extend_from_slice(&a[i * width..]);
    }
    if op == SetOp::Union {
        out.extend_from_slice(&b[j * width..]);
    }
    out
}

/// Apply `op` to the records of `a` and `b`.
pub fn apply(op: SetOp, a: &HsetFile<'_>, b: &HsetFile<'_>) -> Result<Builder> {
    let (af, arows) = records_of(a)?;
    let (bf, brows) = records_of(b)?;
    let atypes: BTreeSet<(HashType, u64)> = af.iter().map(|f| (f.htype, f.length)).collect();
    let btypes: BTreeSet<(HashType, u64)> = bf.iter().map(|f| (f.htype, f.length)).collect();
    if atypes != btypes {
        return Err(Error::input(
            "hash type mismatch between left and right operands",
        ));
    }
    let out_fields: Vec<FieldDescriptor> = atypes
        .iter()
        .map(|&(t, len)| {
            let name = af
                .iter()
                .find(|f| f.htype == t)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| t.field_name().to_string());
            FieldDescriptor {
                htype: t,
                name,
                length: len,
            }
        })
        .collect();
    let width: usize = out_fields.iter().map(FieldDescriptor::stride).sum();
    let a2 = crate::builder::sorted_rows(&relayout(&af, &arows, &out_fields), width, true);
    let b2 = crate::builder::sorted_rows(&relayout(&bf, &brows, &out_fields), width, true);
    let merged = merge(op, &a2, &b2, width);
    let mut builder = Builder::with_fields(out_fields);
    for r in merged.chunks_exact(width) {
        builder.add_raw_record(r)?;
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::BuildOptions;
    use crate::format::decode;

    fn make(types: &[HashType], lines: &[&str]) -> Vec<u8> {
        let mut b = Builder::new(types).unwrap();
        for l in lines {
            b.add_text_line(l).unwrap();
        }
        b.build(&BuildOptions::new("t", "t")).unwrap()
    }

    const M1: &str = "081d3d40b257d8bbc5858345ad186beb";
    const M2: &str = "19875d9651a319fdb8f7332b660c432d";
    const M3: &str = "297da3f7f9c7a38fcb8872193cf3b609";
    const S1: &str = "0af8e028c7048ad772ddec2200ec7e0e4d58b0c3";
    const S2: &str = "1127ceb2c2d789c1d7615b12082ca30222f3c612";
    const S3: &str = "3e909896b309492e00444212bb2b270b5809a0cf";

    fn run(op: SetOp, a: &[u8], b: &[u8]) -> Vec<String> {
        let fa = decode(a).unwrap();
        let fb = decode(b).unwrap();
        let out = apply(op, &fa, &fb)
            .unwrap()
            .build(&BuildOptions::new("o", "o"))
            .unwrap();
        let hs = crate::Hashset::load(&out).unwrap();
        hs.records()
            .map(|r| {
                hs.record_fields(r)
                    .iter()
                    .map(|(f, v)| {
                        v.map(|v| crate::builder::format_value(f, v))
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    #[test]
    fn union_intersect_subtract() {
        let a = make(
            &[HashType::Md5, HashType::Sha1],
            &[&format!("{M1} {S1}"), &format!("{M2} {S2}")],
        );
        // Same types, opposite field order: must be reconciled.
        let b = make(
            &[HashType::Sha1, HashType::Md5],
            &[&format!("{S2} {M2}"), &format!("{S3} {M3}")],
        );
        let u = run(SetOp::Union, &a, &b);
        assert_eq!(
            u,
            vec![
                format!("{M1} {S1}"),
                format!("{M2} {S2}"),
                format!("{M3} {S3}")
            ]
        );
        let i = run(SetOp::Intersect, &a, &b);
        assert_eq!(i, vec![format!("{M2} {S2}")]);
        let d = run(SetOp::Subtract, &a, &b);
        assert_eq!(d, vec![format!("{M1} {S1}")]);
        let d = run(SetOp::Subtract, &b, &a);
        assert_eq!(d, vec![format!("{M3} {S3}")]);
    }

    #[test]
    fn hashes_only_single_section_works() {
        let mut ba = Builder::new(&[HashType::Md5]).unwrap();
        ba.add_text_line(M1).unwrap();
        ba.add_text_line(M2).unwrap();
        let a = ba
            .build(&BuildOptions::new("a", "a").records(false))
            .unwrap();
        let mut bb = Builder::new(&[HashType::Md5]).unwrap();
        bb.add_text_line(M2).unwrap();
        let b = bb
            .build(&BuildOptions::new("b", "b").records(false))
            .unwrap();
        assert_eq!(run(SetOp::Intersect, &a, &b), vec![M2.to_string()]);
        assert_eq!(run(SetOp::Subtract, &a, &b), vec![M1.to_string()]);
    }

    #[test]
    fn type_mismatch_is_an_error() {
        let a = make(&[HashType::Md5], &[M1]);
        let b = make(&[HashType::Sha1], &[S1]);
        let fa = decode(&a).unwrap();
        let fb = decode(&b).unwrap();
        assert!(apply(SetOp::Union, &fa, &fb).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::{btree_set, vec};
    use proptest::prelude::*;

    /// A row width and two sets of rows of exactly that width.
    fn width_and_sets() -> impl Strategy<Value = (usize, BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>)> {
        (1usize..=8).prop_flat_map(|width| {
            (
                Just(width),
                btree_set(vec(any::<u8>(), width), 0..=40),
                btree_set(vec(any::<u8>(), width), 0..=40),
            )
        })
    }

    fn concat<'a>(rows: impl Iterator<Item = &'a Vec<u8>>) -> Vec<u8> {
        rows.flat_map(|r| r.iter().copied()).collect()
    }

    proptest! {
        #[test]
        fn merge_matches_btreeset((width, a, b) in width_and_sets()) {
            let a_bytes = concat(a.iter());
            let b_bytes = concat(b.iter());
            for op in [SetOp::Union, SetOp::Intersect, SetOp::Subtract] {
                let expected = match op {
                    SetOp::Union => concat(a.union(&b)),
                    SetOp::Intersect => concat(a.intersection(&b)),
                    SetOp::Subtract => concat(a.difference(&b)),
                };
                prop_assert_eq!(merge(op, &a_bytes, &b_bytes, width), expected, "{:?}", op);
            }
        }
    }
}
