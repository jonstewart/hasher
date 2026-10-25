//! `hset::tlsh::ivf::merge`: carrying TIVF lists through a merge and
//! coalescing small lists, ported from `test/test_hset_merge_incremental.cpp`
//! (hand-built cells, incremental unions) and `test/test_hset_merge.cpp`
//! (`merge_tlsh_ivf_remaps_and_drops`).

use hset::tlsh::ivf::merge::merge_tlsh_ivf;
use hset::tlsh::ivf::{DEFAULT_COALESCE, DROPPED, IvfIndex, TlshIvf, check_invariant};
use hset::tlsh::{TlshDigest, emb_body_dist2};

/// No index on either side.
const NONE: Option<(&TlshIvf, &[u32])> = None;

#[test]
fn merging_nothing_gives_the_empty_index() {
    let m = merge_tlsh_ivf(NONE, NONE, &[], 64).unwrap();
    assert_eq!(m, TlshIvf::empty());
    assert_eq!(m.lists(), 0);
    assert_eq!(m.n(), 0);
}

//
// hand-built cells (test_hset_merge_incremental.cpp)
//

const CELL_L: u8 = 100;
const CELL_Q1: u8 = 5;
const CELL_Q2: u8 = 7;
/// (L << 8) | (Q1 << 4) | Q2
const CELL: usize = 0x6457;

/// A digest of the test cell whose buckets in `ones` have code 1 and in
/// `twos` code 2, the rest 0, with checksum `cs`.
fn digest_cs(ones: &[usize], twos: &[usize], cs: u8) -> TlshDigest {
    let mut codes = [0u8; 128];
    for &b in ones {
        codes[b] = 1;
    }
    for &b in twos {
        codes[b] = 2;
    }
    TlshDigest::from_parts(CELL_L, CELL_Q1, CELL_Q2, cs, &codes)
}

/// [`digest_cs`] with checksum 1.
fn digest(ones: &[usize], twos: &[usize]) -> TlshDigest {
    digest_cs(ones, twos, 1)
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
    digests: Vec<TlshDigest>,
    rows: Vec<[u8; 36]>,
    ivf: TlshIvf,
    /// The ids of each list.
    ids: Vec<Vec<u32>>,
}

impl HandCell {
    fn new(lists: &[ListSpec]) -> Self {
        let mut digests: Vec<TlshDigest> = lists.iter().flat_map(|l| l.members.clone()).collect();
        digests.sort();
        assert!(
            digests.windows(2).all(|w| w[0] < w[1]),
            "rows must be distinct"
        );
        let mut ivf = TlshIvf::empty();
        ivf.n = digests.len() as u64;
        let mut ids = Vec::new();
        for l in lists {
            let mut li: Vec<u32> = l
                .members
                .iter()
                .map(|m| digests.binary_search(m).unwrap() as u32)
                .collect();
            li.sort();
            ivf.medoids.push(l.medoid);
            ivf.radius2.push(l.radius2);
            ivf.ids.extend(&li);
            ivf.list_start.push(ivf.ids.len() as u64);
            ids.push(li);
        }
        for c in &mut ivf.cell_lists[CELL + 1..] {
            *c = lists.len() as u32;
        }
        let rows = digests.iter().map(|d| d.0).collect();
        Self {
            digests,
            rows,
            ivf,
            ids,
        }
    }

    fn identity(&self) -> Vec<u32> {
        (0..self.rows.len() as u32).collect()
    }

    /// The index merged alone, through the identity map, at threshold `c`.
    fn merged(&self, c: u32) -> TlshIvf {
        let map = self.identity();
        let m = merge_tlsh_ivf(Some((&self.ivf, &map[..])), NONE, &self.rows, c).unwrap();
        (&m).validate(&self.rows)
            .expect("a merge gives a valid index");
        m
    }

    fn radius_about(&self, m: &TlshDigest, ids: &[u32]) -> u32 {
        ids.iter()
            .map(|&id| emb_body_dist2(m, &self.digests[id as usize]))
            .max()
            .unwrap_or(0)
    }

    /// The map keeping every row but `dropped`, renumbered densely, and
    /// the kept rows.
    fn without(&self, dropped: &[u32]) -> (Vec<u32>, Vec<[u8; 36]>) {
        let mut next = 0;
        let mut kept = Vec::new();
        let map = (0..self.rows.len() as u32)
            .map(|i| {
                if dropped.contains(&i) {
                    DROPPED
                } else {
                    kept.push(self.rows[i as usize]);
                    next += 1;
                    next - 1
                }
            })
            .collect();
        (map, kept)
    }
}

fn list_ids(ivf: &TlshIvf, l: usize) -> Vec<u32> {
    ivf.list_ids(l).collect()
}

fn sorted_union(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut u = [a, b].concat();
    u.sort();
    u
}

/// The cell of `tlsh_ivf_coalesce_small_lists`: lists A and B of three
/// rows ten buckets apart and a list D of 40 rows of one body, far from
/// both, in that order. Returns the cell and mA, mB, d[0].
fn small_lists_cell() -> (HandCell, [TlshDigest; 3]) {
    // A: medoid at the origin, two members a bucket away
    let m_a = digest(&[], &[]);
    let a1 = digest(&[0], &[]);
    let a2 = digest(&[1], &[]);
    // B: medoid 10 buckets from mA, members 1 and 2 more buckets further
    let ten: Vec<usize> = (50..60).collect();
    let m_b = digest(&ten, &[]);
    let b1 = digest(&[&ten[..], &[60]].concat(), &[]);
    let b2 = digest(&[&ten[..], &[60, 61]].concat(), &[]);
    // D: 40 rows with the same body (distinct checksums), far from A and B
    let twos: Vec<usize> = (100..110).collect();
    let d: Vec<TlshDigest> = (0..40).map(|cs| digest_cs(&[], &twos, cs)).collect();

    assert_eq!(emb_body_dist2(&m_a, &m_b), 10);
    assert_eq!(emb_body_dist2(&m_a, &b2), 12);
    assert_eq!(emb_body_dist2(&m_b, &a1), 11);

    let h = HandCell::new(&[
        spec(m_a, 1, &[m_a, a1, a2]),
        spec(m_b, 2, &[m_b, b1, b2]),
        spec(d[0], 0, &d),
    ]);
    (h, [m_a, m_b, d[0]])
}

#[test]
fn the_identity_map_with_coalescing_off_reproduces_the_index() {
    let (h, _) = small_lists_cell();
    assert_eq!(h.merged(0), h.ivf);
}

#[test]
fn coalescing_off_keeps_every_list_and_breaks_the_default_invariant() {
    let (h, _) = small_lists_cell();
    let m = h.merged(0);
    assert_eq!(m.lists(), 3);
    assert!(!check_invariant(&m, DEFAULT_COALESCE));
    assert!(check_invariant(&m, 0));
}

#[test]
fn c_6_leaves_lists_of_3_verbatim() {
    // no list is below 3, nothing coalesces
    let (h, _) = small_lists_cell();
    let m = h.merged(6);
    assert_eq!(m.lists(), 3);
    for l in 0..3 {
        assert_eq!(list_ids(&m, l), h.ids[l]);
        assert_eq!(m.medoids[l], h.ivf.medoids[l]);
        assert_eq!(m.radius2[l], h.ivf.radius2[l]);
    }
}

#[test]
fn a_list_that_loses_members_gets_its_radius_recomputed() {
    // one list with members 1, 5 and 9 away from the medoid, stored radius
    // 9; another with a loose stored radius that loses nothing
    let m1 = digest(&[], &[]);
    let far = digest(&[0, 1, 2, 3, 4, 5, 6, 7, 8], &[]);
    let mid = digest(&[0, 1, 2, 3, 4], &[]);
    let near = digest(&[0], &[]);
    let m2 = digest(&[], &[100]);
    let m2a = digest(&[], &[100, 101]);
    let h = HandCell::new(&[
        spec(m1, 9, &[m1, near, mid, far]),
        spec(m2, 100, &[m2, m2a]),
    ]);
    assert_eq!(emb_body_dist2(&m1, &far), 9);
    assert_eq!(emb_body_dist2(&m1, &mid), 5);

    // drop `far`; the kept rows are renumbered densely
    let far_id = h.digests.binary_search(&far).unwrap() as u32;
    let (map, kept) = h.without(&[far_id]);

    let m = merge_tlsh_ivf(Some((&h.ivf, &map[..])), NONE, &kept, 0).unwrap();
    assert_eq!(m.lists(), 2);
    assert_eq!(m.medoids[0], m1);
    assert_eq!(m.radius2[0], 5);
    assert_eq!(list_ids(&m, 0).len(), 3);
    // untouched: medoid and radius verbatim, loose or not
    assert_eq!(m.medoids[1], m2);
    assert_eq!(m.radius2[1], 100);
    assert_eq!(list_ids(&m, 1).len(), 2);
    (&m).validate(&kept).unwrap();
}

#[test]
fn a_list_whose_members_all_drop_is_omitted() {
    let (h, [_, _, d0]) = small_lists_cell();
    // drop every row of D, keep A and B
    let (map, kept) = h.without(&h.ids[2]);
    let m = merge_tlsh_ivf(Some((&h.ivf, &map[..])), NONE, &kept, 0).unwrap();
    assert_eq!(m.lists(), 2);
    assert!(!m.medoids.contains(&d0));
    assert_eq!(m.radius2, h.ivf.radius2[..2]);
    assert_eq!(m.cell_lists[CELL], 0);
    assert_eq!(m.cell_lists[CELL + 1], 2);
    (&m).validate(&kept).unwrap();
}

#[test]
fn default_threshold_coalesces_the_two_small_lists_about_the_better_medoid() {
    let (h, [_, m_b, d0]) = small_lists_cell();
    let ab = sorted_union(&h.ids[0], &h.ids[1]);
    let m = h.merged(DEFAULT_COALESCE);
    assert_eq!(m.lists(), 2);
    assert_eq!(m.cell_lists[CELL], 0);
    assert_eq!(m.cell_lists[CELL + 1], 2);
    assert_eq!(list_ids(&m, 0), ab);
    // mB gives radius 11 (to a1, a2), mA would give 12 (to b2)
    assert_eq!(m.medoids[0], m_b);
    assert_eq!(m.radius2[0], 11);
    let [m_a, m_b] = [h.ivf.medoids[0], h.ivf.medoids[1]];
    assert_eq!(
        m.radius2[0],
        h.radius_about(&m_a, &ab).min(h.radius_about(&m_b, &ab))
    );
    assert_eq!(list_ids(&m, 1), h.ids[2]);
    assert_eq!(m.medoids[1], d0);
    assert_eq!(m.radius2[1], 0);
    assert!(check_invariant(&m, DEFAULT_COALESCE));
}

#[test]
fn c_8_coalesces_two_lists_of_3_into_one_of_6() {
    // both lists of 3 are below 4, their union of 6 is not
    let (h, _) = small_lists_cell();
    let m = h.merged(8);
    assert_eq!(m.lists(), 2);
    assert_eq!(list_ids(&m, 0), sorted_union(&h.ids[0], &h.ids[1]));
    assert!(check_invariant(&m, 8));
}

/// The cell of `tlsh_ivf_coalesce_greedy_order`: P and Q are close, R is
/// far from both; three lists of three. Returns the cell and mP, mQ, mR.
fn greedy_cell() -> (HandCell, [TlshDigest; 3]) {
    let m_p = digest(&[], &[]);
    let m_q = digest(&[0, 1], &[]);
    let twos: Vec<usize> = (10..20).collect();
    let m_r = digest(&[], &twos);
    let h = HandCell::new(&[
        spec(m_p, 1, &[m_p, digest(&[2], &[]), digest(&[3], &[])]),
        spec(
            m_q,
            1,
            &[m_q, digest(&[0, 1, 4], &[]), digest(&[0, 1, 5], &[])],
        ),
        spec(
            m_r,
            2,
            &[m_r, digest(&[30], &twos), digest(&[30, 31], &twos)],
        ),
    ]);
    (h, [m_p, m_q, m_r])
}

#[test]
fn c_10_coalesces_the_closest_pair_and_stops_once_it_is_large() {
    // P and Q coalesce to 6 >= 5 and stop, R stays small alone
    let (h, [m_p, m_q, _]) = greedy_cell();
    let m = h.merged(10);
    assert_eq!(m.lists(), 2);
    let pq = list_ids(&m, 0);
    assert_eq!(pq, sorted_union(&h.ids[0], &h.ids[1]));
    assert!(m.medoids[0] == m_p || m.medoids[0] == m_q);
    assert_eq!(m.radius2[0], h.radius_about(&m.medoids[0], &pq));
    assert_eq!(
        m.radius2[0],
        h.radius_about(&m_p, &pq).min(h.radius_about(&m_q, &pq))
    );
    assert_eq!(list_ids(&m, 1), h.ids[2]);
    assert!(check_invariant(&m, 10));
}

#[test]
fn c_14_coalesces_the_closest_pair_first_then_the_far_list_joins() {
    // P and Q first (6 < 7), then R joins
    let (h, [m_p, m_q, m_r]) = greedy_cell();
    let m = h.merged(14);
    assert_eq!(m.lists(), 1);
    let all: Vec<u32> = h.identity();
    assert_eq!(list_ids(&m, 0), all);
    assert!([m_p, m_q, m_r].contains(&m.medoids[0]));
    assert_eq!(m.radius2[0], h.radius_about(&m.medoids[0], &all));
    assert!(check_invariant(&m, 14));
}

#[test]
fn a_cell_lists_the_left_sides_lists_then_the_right_sides() {
    // the lists of small_lists_cell split over two sides: A and D on the
    // left, B on the right, each side's rows renumbered densely
    let (h, [m_a, m_b, d0]) = small_lists_cell();
    let side = |lists: &[usize]| {
        let specs: Vec<ListSpec> = lists
            .iter()
            .map(|&l| {
                let members: Vec<TlshDigest> =
                    h.ids[l].iter().map(|&i| h.digests[i as usize]).collect();
                spec(h.ivf.medoids[l], h.ivf.radius2[l], &members)
            })
            .collect();
        let s = HandCell::new(&specs);
        let map: Vec<u32> = s
            .digests
            .iter()
            .map(|d| h.digests.binary_search(d).unwrap() as u32)
            .collect();
        (s, map)
    };
    let (left, lmap) = side(&[0, 2]);
    let (right, rmap) = side(&[1]);
    let m = merge_tlsh_ivf(
        Some((&left.ivf, &lmap[..])),
        Some((&right.ivf, &rmap[..])),
        &h.rows,
        0,
    )
    .unwrap();
    assert_eq!(m.medoids, [m_a, d0, m_b]);
    assert_eq!(list_ids(&m, 0), h.ids[0]);
    assert_eq!(list_ids(&m, 1), h.ids[2]);
    assert_eq!(list_ids(&m, 2), h.ids[1]);
    (&m).validate(&h.rows).unwrap();

    // coalescing pairs the small lists across the sides
    let m = merge_tlsh_ivf(
        Some((&left.ivf, &lmap[..])),
        Some((&right.ivf, &rmap[..])),
        &h.rows,
        DEFAULT_COALESCE,
    )
    .unwrap();
    assert_eq!(m.medoids, [m_b, d0]);
    assert_eq!(m.radius2, [11, 0]);
    assert_eq!(list_ids(&m, 0), sorted_union(&h.ids[0], &h.ids[1]));
}

//
// rejected inputs (merge_tlsh_ivf_remaps_and_drops)
//

fn assert_rejected(r: hset::Result<TlshIvf>, needle: &str) {
    match r {
        Err(e) => assert!(e.to_string().contains(needle), "{e} lacks {needle:?}"),
        Ok(_) => panic!("merge accepted, expected an error with {needle:?}"),
    }
}

#[test]
fn a_map_that_disagrees_with_the_index_row_count_is_an_error() {
    let (h, _) = small_lists_cell();
    let mut map = h.identity();
    map.pop();
    assert_rejected(
        merge_tlsh_ivf(Some((&h.ivf, &map[..])), NONE, &h.rows, 0),
        "row map",
    );
    let map = (0..=h.rows.len() as u32).collect::<Vec<_>>();
    assert_rejected(
        merge_tlsh_ivf(NONE, Some((&h.ivf, &map[..])), &h.rows, 0),
        "row map",
    );
}

#[test]
fn a_map_not_increasing_within_a_list_is_an_error() {
    // swap the outputs of the first two members of list A
    let (h, _) = small_lists_cell();
    let mut map = h.identity();
    map.swap(h.ids[0][0] as usize, h.ids[0][1] as usize);
    assert_rejected(
        merge_tlsh_ivf(Some((&h.ivf, &map[..])), NONE, &h.rows, 0),
        "not increasing",
    );
}

#[test]
fn more_output_rows_than_mapped_ids_is_an_error() {
    let (h, _) = small_lists_cell();
    let map = h.identity();
    let mut rows = h.rows.clone();
    rows.push(rows[rows.len() - 1]);
    assert_rejected(
        merge_tlsh_ivf(Some((&h.ivf, &map[..])), NONE, &rows, 0),
        "expected",
    );
}

#[test]
fn a_mapped_id_past_the_output_rows_is_an_error() {
    let (h, _) = small_lists_cell();
    let mut map = h.identity();
    let last = map.len() - 1;
    map[last] = last as u32 + 1;
    assert_rejected(
        merge_tlsh_ivf(Some((&h.ivf, &map[..])), NONE, &h.rows, DEFAULT_COALESCE),
        "past",
    );
}

#[test]
fn an_index_id_past_its_rows_is_an_error_not_a_panic() {
    let (h, _) = small_lists_cell();
    let mut ivf = h.ivf.clone();
    let last = ivf.ids.len() - 1;
    ivf.ids[last] = 1000;
    let map = h.identity();
    assert_rejected(
        merge_tlsh_ivf(Some((&ivf, &map[..])), NONE, &h.rows, 0),
        "out of range",
    );
}

#[test]
fn an_owned_index_with_arrays_of_the_wrong_length_is_an_error_not_a_panic() {
    let (h, _) = small_lists_cell();
    let mut ivf = h.ivf.clone();
    ivf.medoids.pop();
    let map = h.identity();
    assert_rejected(
        merge_tlsh_ivf(Some((&ivf, &map[..])), NONE, &h.rows, 0),
        "medoids",
    );
}
