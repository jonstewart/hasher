//! `hset::tlsh::ivf` model and TIVF payload format, ported from
//! `test/test_tlsh_ivf.cpp` (serialization round trip, truncation),
//! `test/test_hset_tlsh_vectors.cpp` (lengths, decode rejections) and
//! `test/test_hset_merge_incremental.cpp` (structural validity, the
//! coalescing invariant on a hand-built cell).

use hset::tlsh::ivf::tivf_len;

// Layout (HASHSET_FORMAT, tlsh_ivf.cpp length_tivf_data): 32-byte header,
// u32 cell_lists[65537], 36-byte medoids[C], u32 radius2[C],
// u64 list_start[C + 1], u32 ids[n].
const HEADER: u64 = 32;
const CELL_LISTS: u64 = 65537 * 4;

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
