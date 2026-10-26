#![no_main]

//! TIVF payloads into `TivfView::parse`, `knn_ivf`, `merge_tlsh_ivf` and
//! `check_index`.
//!
//! A TIVF payload is at least 262 KiB (the 65,537-entry `cell_lists`), far
//! past libFuzzer's input lengths, so most cases are structured: a small
//! sorted row set, a partition of each cell's rows into lists chosen by the
//! input, medoids and radii, encoded with `TlshIvf::to_bytes` and then
//! mutated byte by byte in a chosen region. A raw case pads the input
//! with zeros to the length its own header claims (when that is small).
//!
//! Nothing validates an index before use, so parsing, `check_index`, the
//! search and the merge must each survive any payload: none panics; the
//! search of a parsed view, and of whatever its identity merge makes,
//! returns matches or a format error. A parsed view copies back to the
//! same payload, but for the ignored flags and reserved header fields. An unmutated, well-formed case passes `check_index`. On
//! an index that passes, `knn_ivf` equals `knn_brute`, and the identity
//! merge (with an empty other side) passes `check_index`, holds the
//! coalescing invariant and searches the same.

#[path = "common/tlsh.rs"]
mod common;

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use common::{MAX_QUERIES, QuerySpec, Row, RowSpec, check_knn, sorted_rows};
use hset::tlsh::ivf::merge::merge_tlsh_ivf;
use hset::tlsh::ivf::{TIVF_HEADER_LENGTH, check_index, check_invariant, knn_ivf, tivf_len};
use hset::tlsh::{BodyQuery, CELL_COUNT, DIGEST_LENGTH, IvfIndex, TivfView, TlshDigest, TlshIvf};
use libfuzzer_sys::fuzz_target;

/// Most mutations applied to a structured payload.
const MAX_MUTATIONS: usize = 8;

/// A raw payload is padded only up to this many lists and rows.
const MAX_RAW_LISTS: u32 = 1024;
const MAX_RAW_ROWS: u64 = 4096;

#[derive(Arbitrary, Debug)]
enum Medoid {
    /// The member at this position (modulo the list's length).
    Member(u8),
    /// Any digest; the radius is measured from it, so still valid.
    Other(RowSpec),
}

#[derive(Arbitrary, Debug)]
enum Region {
    Header,
    CellLists,
    Medoids,
    Radius2,
    ListStart,
    Ids,
    Anywhere,
    Truncate,
    Append,
}

#[derive(Arbitrary, Debug)]
struct Mutation {
    region: Region,
    at: u32,
    value: u8,
}

#[derive(Arbitrary, Debug)]
struct Built {
    /// Row i of a cell goes to the list labelled `labels[i] % 4` (0 when
    /// missing); a cell's lists are its labels in ascending order.
    labels: Vec<u8>,
    medoids: Vec<Medoid>,
    /// Added to each list's exact radius; 255 instead takes one off, which
    /// is too tight unless the radius was 0.
    slack: Vec<u8>,
    mutations: Vec<Mutation>,
}

#[derive(Arbitrary, Debug)]
enum Payload {
    Raw(Vec<u8>),
    Built(Built),
}

#[derive(Arbitrary, Debug)]
struct TivfCase {
    rows: Vec<RowSpec>,
    payload: Payload,
    coalesce: u8,
    queries: Vec<QuerySpec>,
}

fn cell_of(r: &Row) -> usize {
    usize::from(TlshDigest(*r).cell())
}

/// The index `built` describes over `rows`, and whether it is well formed
/// (every radius covers its list).
fn build_index(rows: &[Row], built: &Built) -> (TlshIvf, bool) {
    let mut ivf = TlshIvf::empty();
    ivf.n = rows.len() as u64;
    let mut well_formed = true;
    let mut start = 0;
    let mut lists = 0;
    while start < rows.len() {
        let c = cell_of(&rows[start]);
        let end = start + rows[start..].iter().take_while(|r| cell_of(r) == c).count();
        let mut by_label: BTreeMap<u8, Vec<u32>> = BTreeMap::new();
        for i in start..end {
            let label = built.labels.get(i - start).map_or(0, |l| l % 4);
            by_label.entry(label).or_default().push(i as u32);
        }
        // a count for now; summed into offsets below
        ivf.cell_lists[c + 1] = by_label.len() as u32;
        for ids in by_label.into_values() {
            let medoid = match built.medoids.get(lists) {
                Some(Medoid::Member(m)) => {
                    TlshDigest(rows[ids[usize::from(*m) % ids.len()] as usize])
                }
                Some(Medoid::Other(spec)) => TlshDigest(spec.row()),
                None => TlshDigest(rows[ids[0] as usize]),
            };
            let body = BodyQuery::new(&medoid);
            let exact = ids
                .iter()
                .map(|&i| body.emb_body(&rows[i as usize]))
                .max()
                .unwrap_or(0);
            let radius2 = match built.slack.get(lists).copied().unwrap_or(0) {
                255 => {
                    well_formed &= exact == 0;
                    exact.saturating_sub(1)
                }
                s => exact + u32::from(s),
            };
            ivf.medoids.push(medoid);
            ivf.radius2.push(radius2);
            ivf.ids.extend_from_slice(&ids);
            ivf.list_start.push(ivf.ids.len() as u64);
            lists += 1;
        }
        start = end;
    }
    for c in 1..=CELL_COUNT {
        ivf.cell_lists[c] += ivf.cell_lists[c - 1];
    }
    (ivf, well_formed)
}

/// Apply `m` to `payload`, an encoding of `ivf` over rows in `cells`.
fn mutate(payload: &mut Vec<u8>, ivf: &TlshIvf, cells: &[usize], m: &Mutation) {
    let at = m.at as usize;
    let lists = ivf.lists();
    let cell_lists = TIVF_HEADER_LENGTH;
    let medoids = cell_lists + 4 * (CELL_COUNT + 1);
    let radius2 = medoids + DIGEST_LENGTH * lists;
    let list_start = radius2 + 4 * lists;
    let ids = list_start + 8 * (lists + 1);
    let in_region = |base: usize, len: usize| (len > 0).then(|| base + at % len);
    let offset = match m.region {
        Region::Header => Some(at % TIVF_HEADER_LENGTH),
        Region::CellLists => {
            // An entry at or just after a cell that has rows, or either end.
            let entry = match cells.get((at >> 8) % (cells.len() + 2)) {
                Some(&c) => c + (at >> 16) % 2,
                None if at & 0x80 == 0 => 0,
                None => CELL_COUNT,
            };
            Some(cell_lists + 4 * entry + at % 4)
        }
        Region::Medoids => in_region(medoids, DIGEST_LENGTH * lists),
        Region::Radius2 => in_region(radius2, 4 * lists),
        Region::ListStart => in_region(list_start, 8 * (lists + 1)),
        Region::Ids => in_region(ids, payload.len().saturating_sub(ids)),
        Region::Anywhere => in_region(0, payload.len()),
        Region::Truncate => {
            payload.truncate(payload.len().saturating_sub(1 + at % 64));
            None
        }
        Region::Append => {
            payload.push(m.value);
            None
        }
    };
    if let Some(o) = offset.filter(|&o| o < payload.len()) {
        payload[o] = m.value;
    }
}

/// The raw input, zero-padded to the length its header claims when that
/// is small (so the arrays exist and parse looks at them).
fn padded(raw: &[u8]) -> Vec<u8> {
    let mut payload = raw.to_vec();
    if let Some(header) = raw.first_chunk::<TIVF_HEADER_LENGTH>() {
        let lists = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let n = u64::from_le_bytes(header[16..24].try_into().unwrap());
        if lists <= MAX_RAW_LISTS && n <= MAX_RAW_ROWS {
            let len = tivf_len(lists, n) as usize;
            if payload.len() < len {
                payload.resize(len, 0);
            }
        }
    }
    payload
}

/// The searches and merges of a parsed view, `valid` its `check_index`.
fn check_view(
    view: &TivfView<'_>,
    valid: Result<(), hset::Error>,
    rows: &[Row],
    coalesce: u32,
    queries: &[QuerySpec],
) {
    let identity: Vec<u32> = (0..rows.len() as u32).collect();
    let none: Option<(&TlshIvf, &[u32])> = None;
    let merged = merge_tlsh_ivf(Some((view, &identity[..])), none, rows, coalesce);
    if valid.is_err() {
        // Not a sound index: the search and the merge read it unvalidated,
        // bounds-checked. Any answer, a format error at a read out of
        // bounds, never a panic; the same for whatever the merge made.
        search_unsound(view, rows, queries);
        if let Ok(merged) = merged {
            search_unsound(&merged, rows, queries);
        }
        return;
    }
    check_knn(view, rows, queries);
    let merged = merged.expect("identity merge of a valid index");
    let empty = TlshIvf::empty();
    let two_sided = merge_tlsh_ivf(
        Some((view, &identity[..])),
        Some((&empty, &[][..])),
        rows,
        coalesce,
    )
    .expect("merge with an empty side");
    assert_eq!(two_sided, merged, "an empty side changed the merge");
    assert!(check_invariant(&merged, coalesce), "coalescing invariant");
    check_index(&merged, rows).expect("the merge of a valid index passes check_index");
    check_knn(&merged, rows, queries);
}

/// `knn_ivf` over an index that may be corrupt returns, with matches or a
/// format error, for the first queries and for an unbounded search (which
/// reads every list).
fn search_unsound<I: IvfIndex + ?Sized>(ivf: &I, rows: &[Row], queries: &[QuerySpec]) {
    let unbounded = rows
        .first()
        .map(|r| (TlshDigest(*r), usize::MAX, u32::MAX, true));
    let given = queries.iter().take(MAX_QUERIES).map(|spec| {
        let (k, max_distance, include_length) = spec.params();
        (spec.query(rows), k, max_distance, include_length)
    });
    for (q, k, max_distance, include_length) in unbounded.into_iter().chain(given) {
        match knn_ivf(ivf, rows, &q, k, max_distance, include_length, None) {
            Ok(m) => assert!(m.len() <= rows.len(), "{} matches", m.len()),
            Err(e) => assert!(matches!(e, hset::Error::Format(_)), "{e}"),
        }
    }
}

fuzz_target!(|case: TivfCase| {
    let rows = sorted_rows(&case.rows);
    let coalesce = u32::from(case.coalesce);
    let mut cells: Vec<usize> = rows.iter().map(cell_of).collect();
    cells.dedup();

    let (payload, expect_valid) = match &case.payload {
        Payload::Raw(raw) => (padded(raw), false),
        Payload::Built(built) => {
            let (ivf, well_formed) = build_index(&rows, built);
            let mut payload = ivf.to_bytes();
            for m in built.mutations.iter().take(MAX_MUTATIONS) {
                mutate(&mut payload, &ivf, &cells, m);
            }
            (payload, well_formed && built.mutations.is_empty())
        }
    };

    let Ok(view) = TivfView::parse(&payload, rows.len() as u64) else {
        assert!(!expect_valid, "an unmutated payload failed to parse");
        return;
    };
    // parse ignores the flags and reserved fields; to_bytes writes zeros
    let mut canonical = payload.clone();
    for ignored in [2..4, 12..16, 24..32] {
        canonical[ignored].fill(0);
    }
    assert_eq!(TlshIvf::from_index(&view).to_bytes(), canonical);
    let _ = check_invariant(&view, coalesce);
    let valid = check_index(&view, &rows);
    if expect_valid {
        assert!(valid.is_ok(), "an unmutated, well-formed index: {valid:?}");
    }
    check_view(&view, valid, &rows, coalesce, &case.queries);
});
