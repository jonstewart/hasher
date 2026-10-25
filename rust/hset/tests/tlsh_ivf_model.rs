//! `hset::tlsh::ivf` model and TIVF payload format, ported from
//! `test/test_tlsh_ivf.cpp` (serialization round trip, truncation),
//! `test/test_hset_tlsh_vectors.cpp` (lengths, decode rejections) and
//! `test/test_hset_merge_incremental.cpp` (structural validity, the
//! coalescing invariant on a hand-built cell).

use hset::tlsh::TlshDigest;
use hset::tlsh::ivf::{TlshIvf, tivf_len};

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

#[test]
#[should_panic(expected = "medoids")]
fn to_bytes_refuses_an_index_whose_arrays_disagree() {
    // a payload written from it would not parse back
    let mut ivf = two_lists().ivf;
    ivf.medoids.pop();
    ivf.to_bytes();
}
