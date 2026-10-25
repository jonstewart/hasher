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
