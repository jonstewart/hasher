//! `hset::tlsh::ivf` model and TIVF payload format, ported from
//! `test/test_tlsh_ivf.cpp` (serialization round trip, truncation),
//! `test/test_hset_tlsh_vectors.cpp` (lengths, decode rejections) and
//! `test/test_hset_merge_incremental.cpp` (structural validity, the
//! coalescing invariant on a hand-built cell).

use hset::Error;
use hset::tlsh::TlshDigest;
use hset::tlsh::ivf::{IvfIndex, TivfView, TlshIvf, tivf_len};

// Layout (HASHSET_FORMAT, tlsh_ivf.cpp length_tivf_data): 32-byte header,
// u32 cell_lists[65537], 36-byte medoids[C], u32 radius2[C],
// u64 list_start[C + 1], u32 ids[n].
const HEADER: u64 = 32;
const CELL_LISTS: u64 = 65537 * 4;
const CELLS: usize = 65536;
/// Offset of medoids[0].
const MEDOIDS: usize = 32 + 65537 * 4;

//
// hand-built cells (test_hset_merge_incremental.cpp)
//

const CELL_L: u8 = 100;
const CELL_Q1: u8 = 5;
const CELL_Q2: u8 = 7;
/// (L << 8) | (Q1 << 4) | Q2
const CELL: usize = 0x6457;

/// A digest of the test cell whose buckets in `ones` have code 1 and in
/// `twos` code 2, the rest 0.
fn digest(ones: &[usize], twos: &[usize]) -> TlshDigest {
    let mut codes = [0u8; 128];
    for &b in ones {
        codes[b] = 1;
    }
    for &b in twos {
        codes[b] = 2;
    }
    TlshDigest::from_parts(CELL_L, CELL_Q1, CELL_Q2, 1, &codes)
}

struct ListSpec {
    medoid: TlshDigest,
    radius2: u32,
    members: Vec<TlshDigest>,
}

fn spec(medoid: TlshDigest, radius2: u32, members: &[TlshDigest]) -> ListSpec {
    ListSpec {
        medoid,
        radius2,
        members: members.to_vec(),
    }
}

/// Sorted rows of the lists, and an index with one cell (`CELL`) holding
/// the lists in the given order; ids ascending within a list.
struct HandCell {
    rows: Vec<[u8; 36]>,
    ivf: TlshIvf,
}

fn hand_cell(lists: &[ListSpec]) -> HandCell {
    let mut rows: Vec<TlshDigest> = lists.iter().flat_map(|l| l.members.clone()).collect();
    rows.sort();
    assert!(rows.windows(2).all(|w| w[0] < w[1]), "rows must be distinct");

    let mut ivf = TlshIvf::empty();
    ivf.n = rows.len() as u64;
    for l in lists {
        let mut li: Vec<u32> = l
            .members
            .iter()
            .map(|m| rows.binary_search(m).unwrap() as u32)
            .collect();
        li.sort();
        ivf.medoids.push(l.medoid);
        ivf.radius2.push(l.radius2);
        ivf.ids.extend(li);
        ivf.list_start.push(ivf.ids.len() as u64);
    }
    for c in &mut ivf.cell_lists[CELL + 1..] {
        *c = lists.len() as u32;
    }
    HandCell {
        rows: rows.iter().map(|d| d.0).collect(),
        ivf,
    }
}

/// The two lists of `tlsh_ivf_check_invariant_hand_built`, with radii 1
/// and 2 so their order shows in the payload. Sorted rows:
/// 0 = {}, 1 = {50}, 2 = {50, 51}, 3 = {50, 52}, 4 = {0}, 5 = {1}
/// (the lo plane's byte 0 decides {0} and {1}, byte 6 the 50s).
fn two_lists() -> HandCell {
    hand_cell(&[
        spec(
            digest(&[], &[]),
            1,
            &[digest(&[], &[]), digest(&[0], &[]), digest(&[1], &[])],
        ),
        spec(
            digest(&[50], &[]),
            2,
            &[
                digest(&[50], &[]),
                digest(&[50, 51], &[]),
                digest(&[50, 52], &[]),
            ],
        ),
    ])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[test]
fn tivf_len_of_an_empty_index_is_header_cells_and_one_offset() {
    assert_eq!(tivf_len(0, 0), HEADER + CELL_LISTS + 8);
    assert_eq!(tivf_len(0, 0), 262_188);
}

#[test]
fn tivf_len_counts_48_bytes_per_list_and_4_per_row() {
    // test_hset_tlsh_vectors.cpp: length_tivf(3, 100) == 12 + length_tivf_data(3, 100);
    // by hand: 32 + 262148 + 3 * (36 + 4 + 8) + 8 + 100 * 4
    assert_eq!(tivf_len(3, 100), 262_732);
    assert_eq!(tivf_len(1, 0), 262_188 + 48);
    assert_eq!(tivf_len(0, 1), 262_188 + 4);
}

#[test]
fn tivf_len_saturates_instead_of_wrapping() {
    // a header read from a corrupt file must not wrap to a plausible length
    assert_eq!(tivf_len(u32::MAX, u64::MAX), u64::MAX);
    assert_eq!(tivf_len(0, u64::MAX / 4 + 1), u64::MAX);
}

//
// writing (write_tivf_data)
//

#[test]
fn empty_index_payload_is_the_header_zero_cells_and_one_zero_offset() {
    let b = TlshIvf::empty().to_bytes();
    assert_eq!(b.len(), 262_188);
    // version 3, flags 0, dims 256, lists 0, reserved 0, n 0, reserved 0
    let mut header = [0u8; 32];
    header[0] = 3;
    header[5] = 1;
    assert_eq!(b[..32], header);
    assert!(b[32..].iter().all(|&x| x == 0));
}

#[test]
fn hand_built_payload_has_each_array_at_its_offset() {
    let h = two_lists();
    assert_eq!(h.ivf.ids, [0, 4, 5, 1, 2, 3]);
    let b = h.ivf.to_bytes();
    assert_eq!(b.len(), 262_188 + 2 * 48 + 6 * 4);

    // header: version 3, flags 0, dims 256, lists 2, reserved, n 6, reserved
    assert_eq!(b[0..2], [3, 0]);
    assert_eq!(b[2..4], [0, 0]);
    assert_eq!(u32_at(&b, 4), 256);
    assert_eq!(u32_at(&b, 8), 2);
    assert_eq!(u32_at(&b, 12), 0);
    assert_eq!(u64_at(&b, 16), 6);
    assert_eq!(u64_at(&b, 24), 0);

    // cell_lists: 0 up to and including CELL, 2 after it
    assert_eq!(u32_at(&b, 32), 0);
    assert_eq!(u32_at(&b, 32 + 4 * CELL), 0);
    assert_eq!(u32_at(&b, 32 + 4 * (CELL + 1)), 2);
    assert_eq!(u32_at(&b, 32 + 4 * CELLS), 2);

    // medoids, radius2, list_start, ids
    assert_eq!(b[MEDOIDS..MEDOIDS + 36], digest(&[], &[]).0);
    assert_eq!(b[MEDOIDS + 36..MEDOIDS + 72], digest(&[50], &[]).0);
    let radius2 = MEDOIDS + 72;
    assert_eq!(b[radius2..radius2 + 8], [1, 0, 0, 0, 2, 0, 0, 0]);
    let list_start = radius2 + 8;
    assert_eq!(
        [0, 1, 2].map(|i| u64_at(&b, list_start + 8 * i)),
        [0, 3, 6]
    );
    let ids = list_start + 24;
    assert_eq!(
        [0, 1, 2, 3, 4, 5].map(|i| u32_at(&b, ids + 4 * i)),
        [0, 4, 5, 1, 2, 3]
    );
    assert_eq!(ids + 24, b.len());
}

//
// parsing (parse_tivf_data)
//

/// Every array of `a` and `b`, entry by entry, through the trait.
fn assert_same_index(a: &impl IvfIndex, b: &impl IvfIndex) {
    assert_eq!(a.n(), b.n());
    assert_eq!(a.lists(), b.lists());
    for c in 0..=CELLS {
        assert_eq!(a.cell_lists(c), b.cell_lists(c), "cell_lists[{c}]");
    }
    for l in 0..a.lists() {
        assert_eq!(a.medoid(l), b.medoid(l), "medoids[{l}]");
        assert_eq!(a.radius2(l), b.radius2(l), "radius2[{l}]");
    }
    for l in 0..=a.lists() {
        assert_eq!(a.list_start(l), b.list_start(l), "list_start[{l}]");
    }
    for i in 0..a.n() as usize {
        assert_eq!(a.id(i), b.id(i), "ids[{i}]");
    }
}

#[test]
fn a_written_payload_parses_back_to_the_same_index() {
    // tlsh_ivf_serialization_round_trip
    let ivf = two_lists().ivf;
    let b = ivf.to_bytes();
    let v = TivfView::parse(&b, 6).unwrap();
    assert_same_index(&v, &ivf);
    assert_eq!(v.lists(), 2);
    assert_eq!(v.medoid(1), digest(&[50], &[]));
    assert_eq!(v.radius2(1), 2);
    assert_eq!(v.list_start(1), 3);
    assert_eq!(v.id(1), 4);
    assert_eq!(TlshIvf::from_index(&v), ivf);
}

#[test]
fn the_empty_index_round_trips() {
    let b = TlshIvf::empty().to_bytes();
    let v = TivfView::parse(&b, 0).unwrap();
    assert_eq!(v.n(), 0);
    assert_eq!(v.lists(), 0);
    assert_eq!(TlshIvf::from_index(&v), TlshIvf::empty());
}

#[test]
fn parsing_does_not_rely_on_the_payload_alignment() {
    // the format only promises 4-byte alignment, and a copy may have none
    let ivf = two_lists().ivf;
    let mut buf = vec![0x7F];
    buf.extend(ivf.to_bytes());
    let v = TivfView::parse(&buf[1..], 6).unwrap();
    assert_eq!(TlshIvf::from_index(&v), ivf);
}

/// `parse` fails with a format error mentioning `needle`.
#[track_caller]
fn assert_rejected(payload: &[u8], expected_n: u64, needle: &str) {
    match TivfView::parse(payload, expected_n) {
        Err(Error::Format(msg)) => assert!(msg.contains(needle), "{msg:?} lacks {needle:?}"),
        other => panic!("expected a format error mentioning {needle:?}, got {other:?}"),
    }
}

/// The `two_lists` payload with `patch` applied.
fn patched(patch: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut b = two_lists().ivf.to_bytes();
    patch(&mut b);
    b
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Offset of list_start[0] in the `two_lists` payload.
const TWO_LISTS_START: usize = MEDOIDS + 2 * 36 + 2 * 4;

#[test]
fn a_payload_shorter_than_the_header_is_rejected() {
    let b = two_lists().ivf.to_bytes();
    assert_rejected(&[], 0, "header");
    assert_rejected(&b[..31], 6, "header");
}

#[test]
fn a_payload_of_the_wrong_length_is_rejected() {
    // tlsh_ivf_serialization_round_trip: truncated by one byte
    let b = two_lists().ivf.to_bytes();
    assert_rejected(&b[..b.len() - 1], 6, "expected 262308");
    assert_rejected(&patched(|b| b.push(0)), 6, "expected 262308");
    // the header's counts no longer describe the bytes
    assert_rejected(&patched(|b| put_u32(b, 8, 3)), 6, "expected 262356");
    assert_rejected(&patched(|b| put_u64(b, 16, 7)), 6, "expected 262312");
    assert_rejected(
        &patched(|b| put_u32(b, 8, u32::MAX)),
        6,
        "4294967295 lists",
    );
}

#[test]
fn unknown_header_values_are_rejected() {
    // hset_tlsh_index_decode_rejects_corruption: version and dims
    assert_rejected(&patched(|b| b[0] = 9), 6, "version 9");
    assert_rejected(&patched(|b| b[4] = 7), 6, "dims 263");
    // Rust only: flags and reserved fields C++ ignores must be zero
    assert_rejected(&patched(|b| b[2] = 1), 6, "flags");
    assert_rejected(&patched(|b| b[15] = 1), 6, "reserved");
    assert_rejected(&patched(|b| b[24] = 1), 6, "reserved");
}

#[test]
fn a_row_count_other_than_the_sections_is_rejected() {
    // handle_tivf: "TIVF has n rows, expected hash_count"
    let b = two_lists().ivf.to_bytes();
    assert_rejected(&b, 7, "6 rows, expected 7");
    assert_rejected(&b, 5, "6 rows, expected 5");
}

#[test]
fn cell_lists_must_start_at_0_and_end_at_the_list_count() {
    assert_rejected(&patched(|b| put_u32(b, 32, 1)), 6, "cell_lists");
    assert_rejected(
        &patched(|b| put_u32(b, 32 + 4 * CELLS, 1)),
        6,
        "cell_lists",
    );
}

#[test]
fn list_start_must_cover_the_rows_without_decreasing() {
    assert_rejected(
        &patched(|b| put_u64(b, TWO_LISTS_START, 1)),
        6,
        "do not cover the rows",
    );
    assert_rejected(
        &patched(|b| put_u64(b, TWO_LISTS_START + 16, 5)),
        6,
        "do not cover the rows",
    );
    // list_start = [0, 7, 6]: in range at both ends, decreasing between
    assert_rejected(
        &patched(|b| put_u64(b, TWO_LISTS_START + 8, 7)),
        6,
        "nondecreasing",
    );
}

//
// validation (ruling 5; check_index_valid in test_hset_merge_incremental.cpp)
//

#[test]
fn a_hand_built_index_validates_owned_and_borrowed() {
    let h = two_lists();
    let valid = (&h.ivf).validate(&h.rows).unwrap();
    assert_same_index(&valid, &h.ivf);
    assert_eq!(valid.rows(), &h.rows[..]);

    let b = h.ivf.to_bytes();
    let view = TivfView::parse(&b, 6).unwrap();
    let valid = view.validate(&h.rows).unwrap();
    assert_same_index(&valid, &h.ivf);
    assert_eq!(TlshIvf::from_index(valid.index()), h.ivf);
}

#[test]
fn the_empty_index_validates_over_no_rows() {
    assert!(TlshIvf::empty().validate(&[]).is_ok());
}

#[test]
fn a_medoid_need_not_be_a_member() {
    // merge_tlsh_ivf keeps the medoid of a list that lost it; the format
    // only needs every member within radius2 of the medoid. {2} is 1 from
    // {} and 2 from {0} and {1}.
    let h = hand_cell(&[spec(
        digest(&[2], &[]),
        2,
        &[digest(&[], &[]), digest(&[0], &[]), digest(&[1], &[])],
    )]);
    assert!(h.ivf.validate(&h.rows).is_ok());
}

/// `validate` fails with a format error mentioning `needle`.
#[track_caller]
fn assert_invalid(ivf: &impl IvfIndex, rows: &[[u8; 36]], needle: &str) {
    match ivf.validate(rows) {
        Err(Error::Format(msg)) => assert!(msg.contains(needle), "{msg:?} lacks {needle:?}"),
        Err(e) => panic!("expected a format error mentioning {needle:?}, got {e:?}"),
        Ok(_) => panic!("expected a format error mentioning {needle:?}, got a valid index"),
    }
}

/// `two_lists` with its index patched.
fn broken(patch: impl FnOnce(&mut TlshIvf, &mut Vec<[u8; 36]>)) -> (TlshIvf, Vec<[u8; 36]>) {
    let h = two_lists();
    let (mut ivf, mut rows) = (h.ivf, h.rows);
    patch(&mut ivf, &mut rows);
    (ivf, rows)
}

#[test]
fn the_rows_must_be_the_indexed_rows() {
    let h = two_lists();
    assert_invalid(&h.ivf, &h.rows[..5], "6 rows, the section has 5");
}

#[test]
fn an_owned_index_with_arrays_of_the_wrong_length_is_invalid() {
    let (ivf, rows) = broken(|ivf, _| {
        ivf.medoids.pop();
    });
    assert_invalid(&ivf, &rows, "medoids has 1 entries, expected 2");
    let (ivf, rows) = broken(|ivf, _| {
        ivf.ids.pop();
    });
    assert_invalid(&ivf, &rows, "ids has 5 entries");
    let (ivf, rows) = broken(|ivf, _| {
        ivf.cell_lists.pop();
    });
    assert_invalid(&ivf, &rows, "cell_lists has 65536 entries");
}

#[test]
fn an_owned_index_gets_the_checks_parse_makes() {
    let (ivf, rows) = broken(|ivf, _| ivf.cell_lists[CELLS] = 1);
    assert_invalid(&ivf, &rows, "cell_lists");
    let (ivf, rows) = broken(|ivf, _| ivf.list_start[2] = 5);
    assert_invalid(&ivf, &rows, "do not cover the rows");
}

#[test]
fn cell_lists_must_not_decrease() {
    // parse checks only the ends; validate checks every step
    let b = patched(|b| put_u32(b, 32 + 4 * (CELL + 5), 1));
    let view = TivfView::parse(&b, 6).unwrap();
    assert_invalid(&view, &two_lists().rows, "cell_lists decreases");
}

#[test]
fn a_list_must_not_be_empty() {
    // lists A, an empty one, B
    let (ivf, rows) = broken(|ivf, _| {
        ivf.medoids.insert(1, digest(&[], &[]));
        ivf.radius2.insert(1, 0);
        ivf.list_start = vec![0, 3, 3, 6];
        for c in &mut ivf.cell_lists[CELL + 1..] {
            *c = 3;
        }
    });
    assert_invalid(&ivf, &rows, "list 1 is empty");
}

#[test]
fn ids_must_be_rows() {
    let (ivf, rows) = broken(|ivf, _| ivf.ids[5] = 6);
    assert_invalid(&ivf, &rows, "id 6 out of range");
}

#[test]
fn ids_must_ascend_within_a_list() {
    // list A [0, 4, 5] -> [4, 0, 5]
    let (ivf, rows) = broken(|ivf, _| ivf.ids.swap(0, 1));
    assert_invalid(&ivf, &rows, "not ascending");
}

#[test]
fn every_row_is_in_exactly_one_list() {
    // list B [1, 2, 3] -> [0, 2, 3]: row 0 twice, row 1 never; {} is 1
    // from B's medoid {50}, inside its radius 2
    let (ivf, rows) = broken(|ivf, _| ivf.ids[3] = 0);
    assert_invalid(&ivf, &rows, "row 0 is in two lists");
}

#[test]
fn every_id_is_in_its_lists_cell() {
    // row 5 ({1}, the last row) moved to the next L: still sorted by cell
    let (ivf, rows) = broken(|_, rows| rows[5][0] = CELL_L + 1);
    assert_invalid(&ivf, &rows, "row 5 of cell 0x6557 is in a list of cell 0x6457");
}

#[test]
fn the_rows_must_be_sorted_by_cell() {
    // a cell's rows must be contiguous for the search's single-list path
    let (ivf, rows) = broken(|_, rows| rows[0][0] = CELL_L + 1);
    assert_invalid(&ivf, &rows, "not sorted");
}

#[test]
fn every_member_lies_within_its_lists_radius() {
    // check_index_valid: tight <= radius2. {0} and {1} are 1 from {}.
    let (ivf, rows) = broken(|ivf, _| ivf.radius2[0] = 0);
    assert_invalid(&ivf, &rows, "row 4 is 1 from the medoid of list 0, beyond radius2 0");
}

#[test]
#[should_panic(expected = "medoids")]
fn to_bytes_refuses_an_index_whose_arrays_disagree() {
    // a payload written from it would not parse back
    let mut ivf = two_lists().ivf;
    ivf.medoids.pop();
    ivf.to_bytes();
}
