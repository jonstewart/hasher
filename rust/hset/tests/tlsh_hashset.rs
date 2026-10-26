//! TLSH kNN through a loaded [`Hashset`] (C `sfhash_hashset_tlsh_knn`,
//! `_knn_with`, `_knn_strategies`; `test/test_hset_tlsh_vectors.cpp`):
//! the strategies a section offers, the index and brute force agreeing
//! with the naive specification, the errors Rust returns where C returns
//! 0, load-time rejection of a corrupt TIVF header, no validation of the
//! rest (a search fails at an access out of bounds, `verify` reports
//! every structural problem, brute force still works), and the C++
//! fixtures.
//!
//! Debug builds are slow: only one test builds an index over 5000 rows.

use hset::format::{Document, FORMAT_VERSION, HashsetIn, Hint, encode};
use hset::hashset::{IndexReport, KnnStrategies, KnnStrategy, TlshReport};
use hset::tlsh::{IvfIndex, KnnStats, TlshDigest, TlshMatch, knn_brute};
use hset::{BuildOptions, Builder, Error, HashType, Hashset};
use hset_testkit::tlsh::{Perturbation, corpus, fake_md5, naive_knn, perturb_corpus};

const BOTH: KnnStrategies = KnnStrategies {
    brute: true,
    index: true,
};

const BRUTE_ONLY: KnnStrategies = KnnStrategies {
    brute: true,
    index: false,
};

fn opts() -> BuildOptions {
    BuildOptions::new("TLSH index test", "synthetic TLSH corpus").timestamp("2024-01-01T00:00:00Z")
}

/// A `md5 tlsh` records file of `digests`, one record each, with the
/// options `o`.
fn md5_tlsh_file(digests: &[TlshDigest], o: &BuildOptions) -> Vec<u8> {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    for (i, d) in digests.iter().enumerate() {
        b.add_text_line(&format!("{} {}", fake_md5(i as u64), d.to_hex()))
            .unwrap();
    }
    b.build(o).unwrap()
}

/// The TLSH section index of `hs`.
fn tidx(hs: &Hashset) -> usize {
    hs.index_for_type(HashType::Tlsh).unwrap()
}

/// The naive kNN for every `(k, max_distance)` from one sorted list of
/// all matches: those within `max_distance`, the first `k`.
fn expected(all: &[TlshMatch], k: usize, max_distance: u32) -> Vec<TlshMatch> {
    all.iter()
        .copied()
        .filter(|m| m.distance <= max_distance)
        .take(k)
        .collect()
}

/// test_hset_tlsh_vectors.cpp hset_tlsh_knn_index_matches_brute: over a
/// 5000-row file, the index, brute force and the default choice all
/// return the naive kNN, for every k, threshold and length mode.
#[test]
fn index_and_brute_equal_the_naive_knn_through_the_hashset_api() {
    let digests = corpus(21, 5000);
    let bytes = md5_tlsh_file(&digests, &opts());
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let rows = hs.tlsh_rows(t).unwrap();
    assert_eq!(rows.len(), 5000);
    assert_eq!(hs.tlsh_knn_strategies(t).unwrap(), BOTH);
    assert!(hs.tlsh_index(t).unwrap().is_some());

    let queries = perturb_corpus(7, &digests, 8, &Perturbation::default());
    for q in &queries {
        for incl in [true, false] {
            let all = naive_knn(rows, q, usize::MAX, u32::MAX, incl);
            for k in [1, 10, 50] {
                for maxd in [30, 100, 144] {
                    let want = expected(&all, k, maxd);
                    let brute = hs
                        .tlsh_knn_with(t, q, k, maxd, incl, KnnStrategy::Brute, None)
                        .unwrap();
                    let index = hs
                        .tlsh_knn_with(t, q, k, maxd, incl, KnnStrategy::Index, None)
                        .unwrap();
                    let chosen = hs.tlsh_knn(t, q, k, maxd, incl).unwrap();
                    assert_eq!(brute, want, "{q} {k} {maxd} {incl}");
                    assert_eq!(index, want, "{q} {k} {maxd} {incl}");
                    assert_eq!(chosen, want, "{q} {k} {maxd} {incl}");
                }
            }
        }
    }

    // a member is found at distance 0
    let q = TlshDigest(rows[1234]);
    let r = hs.tlsh_knn(t, &q, 1, 0, true).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].distance, 0);
    assert_eq!(rows[r[0].index as usize], rows[1234]);
}

/// The index search adds its work to the stats it is given; it visits
/// fewer rows than there are. Brute force leaves them alone.
#[test]
fn the_index_search_counts_its_work_and_brute_force_does_not() {
    let digests = corpus(3, 1500);
    let bytes = md5_tlsh_file(&digests, &opts());
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let q = perturb_corpus(4, &digests, 1, &Perturbation::default())[0];

    let mut stats = KnnStats::default();
    let r = hs
        .tlsh_knn_with(t, &q, 5, 100, true, KnnStrategy::Index, Some(&mut stats))
        .unwrap();
    assert!(!r.is_empty());
    assert!(stats.cells > 0, "{stats:?}");
    assert!(stats.rows > 0 && stats.rows < 1500, "{stats:?}");
    // stats accumulate
    let before = stats;
    hs.tlsh_knn_with(t, &q, 5, 100, true, KnnStrategy::Index, Some(&mut stats))
        .unwrap();
    assert_eq!(stats.rows, 2 * before.rows);
    assert_eq!(stats.cells, 2 * before.cells);
    assert_eq!(stats.lists, 2 * before.lists);

    let mut untouched = KnnStats::default();
    hs.tlsh_knn_with(
        t,
        &q,
        5,
        100,
        true,
        KnnStrategy::Brute,
        Some(&mut untouched),
    )
    .unwrap();
    assert_eq!(untouched, KnnStats::default());
}

/// hset_tlsh_knn_without_index_is_brute: a file built without the index
/// offers brute force only, which is what the default choice runs, and
/// asking for the index is an error.
#[test]
fn without_an_index_only_brute_force_is_offered() {
    let digests = corpus(8, 1000);
    let bytes = md5_tlsh_file(&digests, &opts().tlsh_index(false));
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let rows = hs.tlsh_rows(t).unwrap();
    assert_eq!(hs.tlsh_knn_strategies(t).unwrap(), BRUTE_ONLY);
    assert!(hs.tlsh_index(t).unwrap().is_none());

    for q in perturb_corpus(8, &digests, 3, &Perturbation::default()) {
        for maxd in [50, 200] {
            for incl in [true, false] {
                let want = naive_knn(rows, &q, 8, maxd, incl);
                assert_eq!(hs.tlsh_knn(t, &q, 8, maxd, incl).unwrap(), want);
                assert_eq!(
                    hs.tlsh_knn_with(t, &q, 8, maxd, incl, KnnStrategy::Brute, None)
                        .unwrap(),
                    want
                );
                let e = hs
                    .tlsh_knn_with(t, &q, 8, maxd, incl, KnnStrategy::Index, None)
                    .unwrap_err();
                assert!(matches!(e, Error::Input(_)), "{e}");
            }
        }
    }
}

/// Where C returns 0 matches (or strategies 0) for a section that is not
/// TLSH or does not exist, Rust returns an input error; a null query or
/// k = 0 is an empty result, as in C.
#[test]
fn a_section_that_is_not_tlsh_is_an_error_and_degenerate_queries_are_empty() {
    let digests = corpus(5, 200);
    let bytes = md5_tlsh_file(&digests, &opts());
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let m = hs.index_for_type(HashType::Md5).unwrap();
    let q = digests[0];

    for idx in [m, 2, 99] {
        let input = |e: Error| assert!(matches!(e, Error::Input(_)), "{idx}: {e}");
        input(hs.tlsh_rows(idx).unwrap_err());
        input(hs.tlsh_index(idx).unwrap_err());
        input(hs.tlsh_knn_strategies(idx).unwrap_err());
        input(hs.tlsh_knn(idx, &q, 4, 100, true).unwrap_err());
        for s in [KnnStrategy::Brute, KnnStrategy::Index] {
            input(
                hs.tlsh_knn_with(idx, &q, 4, 100, true, s, None)
                    .unwrap_err(),
            );
        }
    }

    for s in [KnnStrategy::Brute, KnnStrategy::Index] {
        let none = hs
            .tlsh_knn_with(t, &TlshDigest::NULL, 4, 100, true, s, None)
            .unwrap();
        assert_eq!(none, []);
        assert_eq!(hs.tlsh_knn_with(t, &q, 0, 100, true, s, None).unwrap(), []);
        assert_eq!(
            hs.tlsh_knn_with(t, &q, 1, 0, true, s, None).unwrap().len(),
            1
        );
    }
    assert_eq!(hs.tlsh_knn(t, &TlshDigest::NULL, 4, 100, true).unwrap(), []);
    assert_eq!(hs.tlsh_knn(t, &q, 0, 100, true).unwrap(), []);
}

/// The byte offset of `part` inside `whole`.
fn offset_in(whole: &[u8], part: &[u8]) -> usize {
    part.as_ptr() as usize - whole.as_ptr() as usize
}

/// A 300-row records file and the offset of its TIVF payload.
fn indexed_file() -> (Vec<u8>, usize) {
    let bytes = md5_tlsh_file(&corpus(6, 300), &opts());
    let hs = Hashset::load(&bytes).unwrap();
    let tivf = hs.section(tidx(&hs)).tivf.unwrap();
    let off = offset_in(&bytes, tivf);
    drop(hs);
    (bytes, off)
}

/// hset_tlsh_index_decode_rejects_corruption: a bad TIVF version, dims or
/// row count fails the load.
#[test]
fn a_corrupt_tivf_header_fails_the_load() {
    let (bytes, off) = indexed_file();
    assert!(Hashset::load(&bytes).is_ok());
    let corrupt = |at: usize, value: u8, what: &str| {
        let mut b = bytes.clone();
        b[off + at] = value;
        let e = Hashset::load(&b).unwrap_err();
        assert!(matches!(e, Error::Format(_)), "{what}: {e}");
        assert!(e.to_string().contains("TIVF"), "{what}: {e}");
    };
    corrupt(0, 9, "version");
    corrupt(4, 7, "dims");
    corrupt(16, bytes[off + 16].wrapping_add(1), "row count");
}

/// A TIVF is only read on a TLSH section of 36-byte digests (controller
/// ruling 6): on a TLSH-typed section of another hash length it fails the
/// load, whereas without one such a section loads as opaque hashes with
/// no kNN.
#[test]
fn a_tivf_on_a_tlsh_section_of_other_lengths_fails_the_load() {
    let rows = [1u8; 16];
    // a payload of the right length for one row (its offsets do not
    // matter: the load stops at the hash length)
    let payload = hset::tlsh::TlshIvf {
        n: 1,
        ids: vec![0],
        ..hset::tlsh::TlshIvf::empty()
    }
    .to_bytes();
    let doc = |tivf| Document {
        version: FORMAT_VERSION,
        name: "",
        desc: "",
        time: "",
        records: None,
        hashsets: vec![HashsetIn {
            htype: HashType::Tlsh,
            name: "tlsh16",
            hash_length: 16,
            data: &rows,
            hint: None,
            ridx: None,
            tivf,
        }],
    };
    let bytes = encode(&doc(Some(&payload))).unwrap();
    let e = Hashset::load(&bytes).unwrap_err();
    assert!(matches!(e, Error::Format(_)), "{e}");
    assert!(e.to_string().contains("TIVF"), "{e}");

    let bytes = encode(&doc(None)).unwrap();
    let hs = Hashset::load(&bytes).unwrap();
    assert!(matches!(hs.tlsh_knn_strategies(0), Err(Error::Input(_))));
    assert!(hs.contains(0, &rows));
}

/// [`indexed_file`] with the TIVF's first id out of range, which the load
/// does not look at.
fn file_with_a_bad_tivf_id() -> Vec<u8> {
    let (mut bytes, off) = indexed_file();
    let hs = Hashset::load(&bytes).unwrap();
    let n = hs.count(tidx(&hs));
    let tivf_len = hs.section(tidx(&hs)).tivf.unwrap().len();
    drop(hs);
    // ids[0], the first of the n u32 ids at the end of the payload
    let id0 = off + tivf_len - 4 * n;
    bytes[id0..id0 + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes
}

/// Nothing walks the index at load or on first use: a file whose TIVF has
/// an id out of range loads and offers its index. The search bounds-checks
/// what it reads, so a search that reaches the bad id is a format error
/// (naming the section), one that prunes it is answered, and brute force
/// answers every query.
#[test]
fn an_out_of_range_tivf_id_fails_only_the_index_searches_that_read_it() {
    let bytes = file_with_a_bad_tivf_id();
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let rows = hs.tlsh_rows(t).unwrap();
    assert_eq!(hs.tlsh_knn_strategies(t).unwrap(), BOTH);
    let ivf = hs.tlsh_index(t).unwrap().expect("the index is offered");
    assert_eq!(ivf.id(0), u32::MAX);

    // every list scanned: the bad id is read
    let q = TlshDigest(rows[17]);
    let format = |e: Error| {
        assert!(matches!(e, Error::Format(_)), "{e}");
        let e = e.to_string();
        assert!(e.contains("'tlsh'") && e.contains("out of range"), "{e}");
    };
    let all = |s| hs.tlsh_knn_with(t, &q, usize::MAX, u32::MAX, true, s, None);
    format(all(KnnStrategy::Index).unwrap_err());
    format(hs.tlsh_knn(t, &q, usize::MAX, u32::MAX, true).unwrap_err());
    assert_eq!(
        all(KnnStrategy::Brute).unwrap(),
        naive_knn(rows, &q, usize::MAX, u32::MAX, true)
    );
    // an exact-match search of a row in another cell never reaches it
    let first = ivf.list_ids(0).unwrap().count();
    let far = TlshDigest(rows[rows.len() - 1]);
    assert!(TlshDigest(rows[0]).cell() != far.cell(), "{first}");
    assert_eq!(
        hs.tlsh_knn_with(t, &far, 1, 0, true, KnnStrategy::Index, None)
            .unwrap(),
        naive_knn(rows, &far, 1, 0, true)
    );
}

/// [`indexed_file`] with every list's `radius2` 0: in bounds, so the file
/// loads and searches without error, as C++ does (the pruning may then
/// miss matches); only `verify` reports it.
#[test]
fn a_too_small_tivf_radius_loads_and_searches_and_verify_reports_it() {
    let (mut bytes, off) = indexed_file();
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let lists = hs.tlsh_index(t).unwrap().unwrap().lists();
    drop(hs);
    let radius2 = off + 32 + 4 * 65537 + 36 * lists;
    bytes[radius2..radius2 + 4 * lists].fill(0);
    let hs = Hashset::load(&bytes).unwrap();
    let rows = hs.tlsh_rows(t).unwrap();
    for i in [0, rows.len() / 2, rows.len() - 1] {
        let q = TlshDigest(rows[i]);
        for (k, d) in [(1, 0), (10, 200), (usize::MAX, u32::MAX)] {
            hs.tlsh_knn_with(t, &q, k, d, true, KnnStrategy::Index, None)
                .unwrap();
        }
    }
    let report = hs.verify();
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("beyond radius2 0")),
        "{:?}",
        report.problems
    );
    assert!(!report.sections[t].tlsh.unwrap().index.unwrap().valid);
}

/// The flags and reserved TIVF header fields are ignored at load, as C++
/// ignores them.
#[test]
fn nonzero_tivf_flags_and_reserved_fields_load() {
    let (bytes, off) = indexed_file();
    for at in [2, 12, 24] {
        let mut b = bytes.clone();
        b[off + at] = 0x5A;
        let hs = Hashset::load(&b).unwrap_or_else(|e| panic!("byte {at}: {e}"));
        assert!(hs.tlsh_index(tidx(&hs)).unwrap().is_some());
    }
}

/// `verify` reports, per TLSH section, that the cell hint is the cell
/// index of the rows and the TIVF index is valid, and nothing TLSH for
/// other sections.
#[test]
fn verify_checks_the_cell_hint_and_the_tivf_of_a_sound_file() {
    let (bytes, _) = indexed_file();
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let lists = hs.tlsh_index(t).unwrap().unwrap().lists();
    assert!(lists > 1, "{lists}");
    let report = hs.verify();
    assert!(report.is_ok(), "{:?}", report.problems);
    assert_eq!(
        report.sections[t].tlsh,
        Some(TlshReport {
            cells_exact: Some(true),
            index: Some(IndexReport { lists, valid: true }),
        })
    );
    let m = hs.index_for_type(HashType::Md5).unwrap();
    assert_eq!(report.sections[m].tlsh, None);

    // without an index
    let bytes = md5_tlsh_file(&corpus(6, 300), &opts().tlsh_index(false));
    let hs = Hashset::load(&bytes).unwrap();
    let report = hs.verify();
    assert!(report.is_ok(), "{:?}", report.problems);
    assert_eq!(
        report.sections[tidx(&hs)].tlsh,
        Some(TlshReport {
            cells_exact: Some(true),
            index: None,
        })
    );
}

/// An invalid TIVF index is a `verify` problem naming the index.
#[test]
fn verify_reports_an_invalid_tivf() {
    let bytes = file_with_a_bad_tivf_id();
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let report = hs.verify();
    let tivf: Vec<&String> = report
        .problems
        .iter()
        .filter(|p| p.contains("TIVF"))
        .collect();
    assert_eq!(tivf.len(), 1, "{:?}", report.problems);
    assert!(tivf[0].starts_with("tlsh: "), "{}", tivf[0]);
    assert!(tivf[0].contains("out of range"), "{}", tivf[0]);
    let index = report.sections[t].tlsh.unwrap().index.unwrap();
    assert!(!index.valid);
    // verify does not change what the search sees
    assert!(hs.tlsh_index(t).unwrap().is_some());
}

/// A cell hint that still loads (offsets from 0 to n, nondecreasing) but
/// is not the rows' cell index is a `verify` problem.
#[test]
fn verify_reports_a_cell_hint_that_is_not_the_cell_index() {
    let (mut bytes, _) = indexed_file();
    let hs = Hashset::load(&bytes).unwrap();
    let t = tidx(&hs);
    let Some(Hint::TlshCells { table }) = hs.section(t).hint else {
        panic!("no cell hint");
    };
    let at = offset_in(&bytes, table);
    let offsets: Vec<u64> = table
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| u64::from_le_bytes(*b))
        .collect();
    // a cell after the first with two rows or more: moving its start up
    // one row keeps the offsets nondecreasing
    let c = (1..65536)
        .find(|&c| offsets[c + 1] >= offsets[c] + 2)
        .unwrap();
    drop(hs);
    let entry = at + 8 * c;
    bytes[entry..entry + 8].copy_from_slice(&(offsets[c] + 1).to_le_bytes());

    let hs = Hashset::load(&bytes).unwrap();
    let report = hs.verify();
    assert_eq!(report.sections[t].tlsh.unwrap().cells_exact, Some(false));
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.starts_with("tlsh: ") && p.contains("cell index")),
        "{:?}",
        report.problems
    );
}

/// A TLSH section with no rows still gets an index (of no lists), as in
/// C++; it validates and every search is empty.
#[test]
fn an_empty_tlsh_section_with_an_index_works() {
    let mut b = Builder::new(&[HashType::Md5, HashType::Tlsh]).unwrap();
    b.add_text_line(&format!("{} ", fake_md5(0))).unwrap();
    b.add_text_line(&format!("{} TNULL", fake_md5(1))).unwrap();
    for records in [true, false] {
        let bytes = b.build(&opts().records(records)).unwrap();
        let hs = Hashset::load(&bytes).unwrap();
        let t = tidx(&hs);
        assert_eq!(hs.count(t), 0);
        assert_eq!(hs.tlsh_rows(t).unwrap().len(), 0);
        assert_eq!(hs.tlsh_knn_strategies(t).unwrap(), BOTH);
        let ivf = hs.tlsh_index(t).unwrap().unwrap();
        assert_eq!((ivf.n(), ivf.lists()), (0, 0));
        let q = corpus(1, 1)[0];
        for s in [KnnStrategy::Brute, KnnStrategy::Index] {
            assert_eq!(
                hs.tlsh_knn_with(t, &q, 10, u32::MAX, true, s, None)
                    .unwrap(),
                []
            );
        }
        assert_eq!(hs.tlsh_knn(t, &q, 10, u32::MAX, true).unwrap(), []);
        let report = hs.verify();
        assert!(report.is_ok(), "{:?}", report.problems);
    }
}

/// The C++ fixtures the default test checks: every kind of TLSH file the
/// C++ tests write (builder outputs with and without records and index,
/// BISECT and KMEANS indexes, set operations, merges with coalescing) at
/// a debug-build cost of a few seconds.
const REPRESENTATIVE: &[&str] = &[
    "md5_tlsh.hset",
    "md5_tlsh_ho.hset",
    "tlsh_md5.hset",
    "tlsh_vec_noidx.hset",
    "tlsh_vec_ho1.hset",
    "tlsh_vec_method.hset",
    "merge_method_out.hset",
    "merge_alg_ab.hset",
    "inc_out_a.hset",
    "setop_fl_full.hset",
];

/// The TLSH sections of the representative C++ fixtures load, verify
/// clean (TIVF validation included), and search the same through the
/// index as by brute force. `fixtures.rs` loads and verifies every
/// fixture; the ignored test below runs these checks over all of them.
#[test]
fn cpp_fixtures_tlsh_sections_load_verify_and_search_exactly() {
    check_cpp_fixtures(|name| REPRESENTATIVE.contains(&name));
}

#[test]
#[ignore = "every fixture, the large merge outputs included: slow in debug builds"]
fn all_cpp_fixtures_tlsh_sections_load_verify_and_search_exactly() {
    check_cpp_fixtures(|_| true);
}

fn check_cpp_fixtures(select: impl Fn(&str) -> bool) {
    let dir = hset_testkit::fixtures::fixtures_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("SKIP: {} is absent (run the C++ make check)", dir.display());
        return;
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".hset") && select(n))
        .collect();
    names.sort();
    let mut checked = 0;
    for name in &names {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let hs = match Hashset::load(&bytes) {
            Ok(hs) => hs,
            // A file still carrying a TVEC chunk is rejected by name.
            // Other unloadable fixtures (version 1, deliberately bad) are
            // fixtures.rs's concern, which fails on unexpected ones.
            Err(e) => {
                let e = e.to_string();
                assert!(!e.contains("TIVF"), "{name}: {e}");
                continue;
            }
        };
        if hs.index_for_type(HashType::Tlsh).is_none() {
            continue;
        }
        let report = hs.verify();
        assert!(report.is_ok(), "{name}: {:?}", report.problems);
        for (t, s) in hs.sections().iter().enumerate() {
            if s.header.htype == HashType::Tlsh {
                check_section(name, &hs, t);
                checked += 1;
            }
        }
    }
    eprintln!("checked {checked} TLSH sections in {}", dir.display());
}

fn check_section(name: &str, hs: &Hashset, t: usize) {
    let rows = hs.tlsh_rows(t).unwrap();
    let strategies = hs.tlsh_knn_strategies(t).unwrap();
    assert!(strategies.brute, "{name}");
    let index = hs.tlsh_index(t).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(index.is_some(), strategies.index, "{name}");
    assert_eq!(index.is_some(), hs.section(t).tivf.is_some(), "{name}");
    if rows.is_empty() {
        return;
    }
    let digests: Vec<TlshDigest> = rows.iter().map(|r| TlshDigest(*r)).collect();
    let mut queries = perturb_corpus(11, &digests, 2, &Perturbation::default());
    queries.push(digests[digests.len() / 2]);
    for q in &queries {
        for (k, maxd, incl) in [(10, 144, true), (5, 300, false)] {
            let want = knn_brute(rows, q, k, maxd, incl);
            assert_eq!(hs.tlsh_knn(t, q, k, maxd, incl).unwrap(), want, "{name}");
            assert_eq!(
                hs.tlsh_knn_with(t, q, k, maxd, incl, KnnStrategy::Brute, None)
                    .unwrap(),
                want,
                "{name}"
            );
            if strategies.index {
                assert_eq!(
                    hs.tlsh_knn_with(t, q, k, maxd, incl, KnnStrategy::Index, None)
                        .unwrap(),
                    want,
                    "{name}"
                );
            }
        }
    }
}
