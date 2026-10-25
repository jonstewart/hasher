//! `hset::tlsh::ivf::merge`: carrying TIVF lists through a merge and
//! coalescing small lists, ported from `test/test_hset_merge_incremental.cpp`
//! (hand-built cells, incremental unions) and `test/test_hset_merge.cpp`
//! (`merge_tlsh_ivf_remaps_and_drops`).

use hset::SetOp;
use hset::merge::{RowMerge, RowMode, merge_rows};
use hset::synth::SplitMix64;
use hset::tlsh::ivf::merge::merge_tlsh_ivf;
use hset::tlsh::ivf::{DEFAULT_COALESCE, DROPPED, IvfIndex, TivfView, TlshIvf, check_invariant};
use hset::tlsh::{BodyQuery, TlshDigest, emb_body_dist2};
use hset_testkit::tlsh::{
    Perturbation, cell_corpus, naive_cell_index, perturb_corpus, sorted_rows,
};
use proptest::prelude::*;

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
// generated indexes and merges
//

/// Rows over a few cells: `n` digests in families of near bodies spread
/// over `cells` headers. Unsorted, duplicates possible.
fn pool(seed: u64, n: usize, cells: usize, flip: f64) -> Vec<TlshDigest> {
    let mut rng = SplitMix64::new(seed);
    let headers: Vec<(u8, u8, u8)> = (0..cells)
        .map(|_| {
            let h = rng.next_u64();
            (h as u8, (h >> 8) as u8 & 0x0F, (h >> 12) as u8 & 0x0F)
        })
        .collect();
    let per = n.div_ceil(cells.max(1));
    let mut v: Vec<TlshDigest> = headers
        .iter()
        .enumerate()
        .flat_map(|(k, &h)| cell_corpus(seed ^ (k as u64 + 1), per, h, 1 + per / 12, flip))
        .collect();
    v.truncate(n);
    v
}

fn sorted_unique(digests: &[TlshDigest]) -> Vec<[u8; 36]> {
    let mut rows = sorted_rows(digests);
    rows.dedup();
    rows
}

/// A valid index over sorted `rows` that is not a clustering: each cell's
/// rows shuffled and cut into lists of 1 to `max_list` members, each list
/// with a random member as medoid and its exact radius.
fn random_index(rows: &[[u8; 36]], seed: u64, max_list: usize) -> TlshIvf {
    let mut rng = SplitMix64::new(seed);
    let mut ivf = TlshIvf::empty();
    ivf.n = rows.len() as u64;
    let cell = |r: &[u8; 36]| TlshDigest(*r).cell() as usize;
    let mut start = 0;
    for c in 0..CELLS {
        ivf.cell_lists[c] = ivf.lists() as u32;
        let end = start + rows[start..].iter().take_while(|r| cell(r) == c).count();
        let mut ids: Vec<u32> = (start as u32..end as u32).collect();
        for i in (1..ids.len()).rev() {
            ids.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let mut rest = &mut ids[..];
        while !rest.is_empty() {
            let len = 1 + rng.below(max_list.min(rest.len()) as u64) as usize;
            let (list, tail) = rest.split_at_mut(len);
            list.sort();
            let medoid = TlshDigest(rows[list[rng.below(len as u64) as usize] as usize]);
            let q = BodyQuery::new(&medoid);
            ivf.medoids.push(medoid);
            ivf.radius2.push(
                list.iter()
                    .map(|&i| q.emb_body(&rows[i as usize]))
                    .max()
                    .unwrap(),
            );
            ivf.ids.extend_from_slice(list);
            ivf.list_start.push(ivf.ids.len() as u64);
            rest = tail;
        }
        start = end;
    }
    ivf.cell_lists[CELLS] = ivf.lists() as u32;
    (&ivf)
        .validate(rows)
        .expect("random_index builds valid indexes");
    ivf
}

/// One side of a merge: its sorted rows and index.
struct Side {
    rows: Vec<[u8; 36]>,
    ivf: TlshIvf,
}

/// The rows a set operation outputs and the row maps, by the file merge's
/// own row merge.
fn merge_sides(op: SetOp, l: &Side, r: &Side) -> (Vec<[u8; 36]>, RowMerge) {
    let m = merge_rows(
        l.rows.as_flattened(),
        r.rows.as_flattened(),
        36,
        RowMode::Set(op),
    )
    .unwrap();
    let out = m
        .gather_rows(l.rows.as_flattened(), r.rows.as_flattened(), 36)
        .unwrap();
    (out.as_chunks::<36>().0.to_vec(), m)
}

fn merge_ivf(l: &Side, r: &Side, out: &[[u8; 36]], m: &RowMerge, c: u32) -> TlshIvf {
    merge_tlsh_ivf(
        Some((&l.ivf, &m.lmap[..])),
        Some((&r.ivf, &m.rmap[..])),
        out,
        c,
    )
    .unwrap()
}

/// Everything a merged index promises: valid over its rows, every radius
/// exact (the inputs' radii are, and the merge keeps them so), the
/// coalescing invariant at `c`, and so at most `m / (c / 2) + 1` lists
/// in a cell of `m` rows.
fn check_merged(m: &TlshIvf, rows: &[[u8; 36]], c: u32) {
    let v = m.validate(rows).expect("a merged index is valid");
    for l in 0..v.lists() {
        let q = BodyQuery::new(&v.medoid(l));
        let exact = v.list_ids(l).map(|i| q.emb_body(&rows[i as usize])).max();
        assert_eq!(exact, Some(v.radius2(l)), "list {l} radius is not exact");
    }
    assert!(check_invariant(&v, c), "coalescing invariant at C = {c}");
    if c / 2 > 0 {
        let half = (c / 2) as usize;
        let cells = naive_cell_index(rows);
        for cell in 0..CELLS {
            let rows_in = (cells[cell + 1] - cells[cell]) as usize;
            let lists = v.cell_range(cell).len();
            if rows_in > 0 {
                assert!(
                    lists <= rows_in / half + 1,
                    "cell {cell:04x}: {lists} lists"
                );
            }
        }
    }
}

const CELLS: usize = 65536;

fn set_op() -> impl Strategy<Value = SetOp> {
    prop_oneof![
        Just(SetOp::Union),
        Just(SetOp::Intersect),
        Just(SetOp::Subtract)
    ]
}

proptest! {
    // Every case walks all 65,536 cells a few times.
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn a_merge_of_any_two_indexes_is_valid_exact_and_coalesced(
        seed in any::<u64>(),
        n in 0usize..400,
        cells in 1usize..6,
        max_list in 1usize..20,
        c in prop_oneof![Just(0u32), Just(1), Just(2), Just(5), Just(10), Just(64)],
        op in set_op(),
    ) {
        // two overlapping samples of one pool, so the operations drop rows
        let all = pool(seed, n, cells, 0.04);
        let mut rng = SplitMix64::new(seed ^ 0x5eed);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for d in &all {
            match rng.below(3) {
                0 => a.push(*d),
                1 => b.push(*d),
                _ => { a.push(*d); b.push(*d); }
            }
        }
        let l = { let rows = sorted_unique(&a); let ivf = random_index(&rows, seed ^ 1, max_list); Side { rows, ivf } };
        let r = { let rows = sorted_unique(&b); let ivf = random_index(&rows, seed ^ 2, max_list); Side { rows, ivf } };
        let (out, m) = merge_sides(op, &l, &r);
        let merged = merge_ivf(&l, &r, &out, &m, c);
        check_merged(&merged, &out, c);

        // the same merge from the parsed payloads gives the same bytes
        let (lp, rp) = (l.ivf.to_bytes(), r.ivf.to_bytes());
        let (lv, rv) = (
            TivfView::parse(&lp, l.rows.len() as u64).unwrap(),
            TivfView::parse(&rp, r.rows.len() as u64).unwrap(),
        );
        let from_views = merge_tlsh_ivf(Some((&lv, &m.lmap[..])), Some((&rv, &m.rmap[..])), &out, c).unwrap();
        prop_assert_eq!(from_views.to_bytes(), merged.to_bytes());
    }

    #[test]
    fn the_identity_map_without_coalescing_reproduces_any_index(
        seed in any::<u64>(),
        n in 0usize..300,
        cells in 1usize..6,
        max_list in 1usize..20,
    ) {
        let rows = sorted_unique(&pool(seed, n, cells, 0.04));
        let ivf = random_index(&rows, seed, max_list);
        let map: Vec<u32> = (0..rows.len() as u32).collect();
        prop_assert_eq!(&merge_tlsh_ivf(Some((&ivf, &map[..])), NONE, &rows, 0).unwrap(), &ivf);
        prop_assert_eq!(&merge_tlsh_ivf(NONE, Some((&ivf, &map[..])), &rows, 0).unwrap(), &ivf);
        // and coalescing a valid index keeps its rows and only joins lists
        let c = merge_tlsh_ivf(Some((&ivf, &map[..])), NONE, &rows, DEFAULT_COALESCE).unwrap();
        check_merged(&c, &rows, DEFAULT_COALESCE);
        prop_assert!(c.lists() <= ivf.lists());
    }
}

#[test]
fn incremental_unions_keep_the_invariant_and_the_list_bound() {
    // hset_merge_incremental_unions, scaled down: a master absorbs batches,
    // half near copies of master rows, half new families, each batch with
    // an index of small random lists
    const MASTER: usize = 3000;
    const STEPS: u64 = 12;
    const HALF_BATCH: usize = 150;
    let master_corpus = pool(101, MASTER, 8, 0.04);
    let batches: Vec<Vec<TlshDigest>> = (0..STEPS)
        .map(|i| {
            let mut b = pool(1000 + i, HALF_BATCH, 8, 0.04);
            let p = Perturbation::body_only(0.03);
            b.extend(perturb_corpus(2000 + i, &master_corpus, HALF_BATCH, &p));
            b
        })
        .collect();

    for c in [2 * 32, 32, 0] {
        let rows = sorted_unique(&master_corpus);
        let ivf = random_index(&rows, 7, 32);
        let mut master = Side { rows, ivf };
        for (step, batch) in batches.iter().enumerate() {
            let rows = sorted_unique(batch);
            let ivf = random_index(&rows, 8 + step as u64, 8);
            let batch = Side { rows, ivf };
            let (out, m) = merge_sides(SetOp::Union, &master, &batch);

            let mut expected = master.rows.clone();
            expected.extend_from_slice(&batch.rows);
            expected.sort();
            expected.dedup();
            assert_eq!(out, expected);

            let ivf = merge_ivf(&master, &batch, &out, &m, c);
            check_merged(&ivf, &out, c);
            master = Side { rows: out, ivf };
        }
    }
}

//
// parity with the C++ merge
//

/// A merge whose output payload the C++ `merge_tlsh_ivf` was run on.
struct Golden {
    name: &'static str,
    a: Option<(TlshIvf, Vec<u32>)>,
    b: Option<(TlshIvf, Vec<u32>)>,
    rows: Vec<[u8; 36]>,
    c: u32,
}

impl Golden {
    /// Two overlapping samples of `pool(seed, n, cells, flip)`, indexed by
    /// [`random_index`] with lists of up to `max_list`, merged by `op`.
    fn two_sides(
        name: &'static str,
        op: SetOp,
        (seed, n, cells, flip): (u64, usize, usize, f64),
        max_list: usize,
        c: u32,
    ) -> Self {
        let all = pool(seed, n, cells, flip);
        let mut rng = SplitMix64::new(seed ^ 0x5eed);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for d in &all {
            match rng.below(3) {
                0 => a.push(*d),
                1 => b.push(*d),
                _ => {
                    a.push(*d);
                    b.push(*d);
                }
            }
        }
        let side = |d: &[TlshDigest], s| {
            let rows = sorted_unique(d);
            let ivf = random_index(&rows, s, max_list);
            Side { rows, ivf }
        };
        let (l, r) = (side(&a, seed ^ 1), side(&b, seed ^ 2));
        let (rows, m) = merge_sides(op, &l, &r);
        Self {
            name,
            a: Some((l.ivf, m.lmap)),
            b: Some((r.ivf, m.rmap)),
            rows,
            c,
        }
    }

    /// One side alone, keeping the rows `keep` selects (`left` says which
    /// side it is passed as).
    fn one_side(
        name: &'static str,
        (seed, n, cells, flip): (u64, usize, usize, f64),
        max_list: usize,
        keep: impl Fn(usize) -> bool,
        left: bool,
        c: u32,
    ) -> Self {
        let rows = sorted_unique(&pool(seed, n, cells, flip));
        let ivf = random_index(&rows, seed ^ 3, max_list);
        let mut out = Vec::new();
        let map = (0..rows.len())
            .map(|i| {
                if keep(i) {
                    out.push(rows[i]);
                    out.len() as u32 - 1
                } else {
                    DROPPED
                }
            })
            .collect();
        let side = Some((ivf, map));
        let (a, b) = if left { (side, None) } else { (None, side) };
        Self {
            name,
            a,
            b,
            rows: out,
            c,
        }
    }

    fn merged(&self) -> TlshIvf {
        fn side(s: &Option<(TlshIvf, Vec<u32>)>) -> Option<(&TlshIvf, &[u32])> {
            s.as_ref().map(|(i, m)| (i, &m[..]))
        }
        merge_tlsh_ivf(side(&self.a), side(&self.b), &self.rows, self.c).unwrap()
    }
}

fn golden_merges() -> Vec<Golden> {
    vec![
        Golden::two_sides("union64", SetOp::Union, (11, 600, 3, 0.04), 6, 64),
        Golden::two_sides("intersect64", SetOp::Intersect, (11, 600, 3, 0.04), 6, 64),
        Golden::two_sides("subtract64", SetOp::Subtract, (11, 600, 3, 0.04), 6, 64),
        // near-identical bodies: many equal radii, so the ties decide
        Golden::two_sides("ties10", SetOp::Union, (12, 500, 2, 0.004), 3, 10),
        Golden::two_sides("ties64", SetOp::Union, (13, 400, 1, 0.0), 2, 64),
        Golden::two_sides("union5", SetOp::Union, (14, 500, 4, 0.05), 4, 5),
        Golden::two_sides("union0", SetOp::Union, (15, 300, 3, 0.05), 4, 0),
        // one cell of many small lists
        Golden::two_sides("onecell", SetOp::Union, (16, 1200, 1, 0.03), 2, 64),
        Golden::one_side(
            "left_drops",
            (17, 500, 3, 0.04),
            7,
            |i| i % 3 != 1,
            true,
            64,
        ),
        Golden::one_side(
            "right_drops",
            (18, 500, 3, 0.04),
            7,
            |i| i % 4 != 0,
            false,
            32,
        ),
    ]
}

/// SHA-256 of the C++ `merge_tlsh_ivf` payload (`write_tivf_data`) for
/// each [`golden_merges`] input, from the harness run on the inputs
/// [`dump_golden_merge_inputs`] writes (the harness linked libhasher's
/// `tlsh_ivf.o` built from `tlsh_ivf.cpp` as of 961c340; list counts in
/// and out: union64 114 + 111 -> 17, onecell 534 + 530 -> 33 in one cell,
/// union0 76 + 82 -> 140).
const GOLDEN_SHA256: &[(&str, &str)] = &[
    (
        "union64",
        "6ae83e4d837ccc0d31e34eb02cb41e3692753bfae7fa4f76f3493fd226b6702e",
    ),
    (
        "intersect64",
        "19e95fd9919c21df25be19ae94da85d1ce929c93aa72df31c22bcccd29153379",
    ),
    (
        "subtract64",
        "578e8cac8ad43ff82bad67ec9723be14c0d51b44bbc8dff65f8e2ed1372944eb",
    ),
    (
        "ties10",
        "0d405c58ba88c4b87bcba4e7734bd3bd94edce401608abf9d899dffe250d3007",
    ),
    (
        "ties64",
        "b17216884e334dcc88cc08f8f12d0203fa1a0fb7c88b6177f11284ddeeeb2f5b",
    ),
    (
        "union5",
        "f18d2ed46185e865a9bac06fe3bcc3b38d646b8c1db91bc7d3851cd42ebe52d2",
    ),
    (
        "union0",
        "2e4e53a26839a7f06f38aa27849ede360aebf36ce3bac78106ee3a3c97f3e21c",
    ),
    (
        "onecell",
        "b94f09402043d4e433c18237d698b7904425fe131b6e8ae030424d45df45318a",
    ),
    (
        "left_drops",
        "2841b84781fb15860c9e9c21139ec16730d4ee393e85830575defb607593cf77",
    ),
    (
        "right_drops",
        "c995b2d48bbb0b1fafe1707a73acbf61e5589bb3d9661fb962cabd2b1d193454",
    ),
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn merges_equal_the_cpp_payloads_byte_for_byte() {
    let golden = golden_merges();
    assert_eq!(golden.len(), GOLDEN_SHA256.len());
    for (g, (name, sha)) in golden.iter().zip(GOLDEN_SHA256) {
        assert_eq!(g.name, *name);
        let m = g.merged();
        check_merged(&m, &g.rows, g.c);
        assert_eq!(sha256_hex(&m.to_bytes()), *sha, "{name}");
    }
}

/// Writes each [`golden_merges`] input for the C++ harness to
/// `$HSET_IVF_MERGE_DUMP/<name>.{rows,c,a.tivf,a.map,b.tivf,b.map}`, and
/// the Rust payload to `<name>.rust.tivf`. The harness (a `main` around
/// `parse_tivf_data`, `merge_tlsh_ivf` and `write_tivf_data`) writes
/// `<name>.cpp.tivf`.
#[test]
#[ignore = "writes the C++ parity inputs; set HSET_IVF_MERGE_DUMP"]
fn dump_golden_merge_inputs() {
    let dir = std::path::PathBuf::from(std::env::var("HSET_IVF_MERGE_DUMP").unwrap());
    let u32s = |v: &[u32]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    for g in golden_merges() {
        let path = |ext: &str| dir.join(format!("{}.{ext}", g.name));
        std::fs::write(path("rows"), g.rows.as_flattened()).unwrap();
        std::fs::write(path("c"), g.c.to_le_bytes()).unwrap();
        for (side, s) in [("a", &g.a), ("b", &g.b)] {
            if let Some((ivf, map)) = s {
                std::fs::write(path(&format!("{side}.tivf")), ivf.to_bytes()).unwrap();
                std::fs::write(path(&format!("{side}.map")), u32s(map)).unwrap();
            }
        }
        std::fs::write(path("rust.tivf"), g.merged().to_bytes()).unwrap();
        println!("{} {}", g.name, sha256_hex(&g.merged().to_bytes()));
    }
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
