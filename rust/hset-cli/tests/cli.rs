//! End-to-end tests of the `hset` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hset::tlsh::TlshDigest;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hset"))
}

fn fixture(name: &str) -> PathBuf {
    hset_testkit::fixtures::fixtures_dir().join(name)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hset-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("spawn hset")
}

fn run_with_stdin(args: &[&str], stdin: &str) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn make_info_query_verify_dump_roundtrip() {
    let dir = tmpdir("roundtrip");
    let out = dir.join("a.hset");
    let input = fixture("md5_sha1_a");
    let o = run(&[
        "make",
        "-t",
        "md5,sha1",
        "-n",
        "A",
        "-d",
        "set a",
        "--timestamp",
        "2024-05-06T07:08:09Z",
        "-o",
        p(&out),
        p(&input),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stderr(&o).contains("344 x 38 bytes"), "{}", stderr(&o));

    let o = run(&["info", p(&out), "--chunks"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&o);
    assert!(s.contains("name:        A"));
    assert!(s.contains("timestamp:   2024-05-06T07:08:09Z"));
    assert!(s.contains("records:     344 x 38 bytes"));
    assert!(s.contains("hull"));
    assert!(s.contains("FEND"));
    assert!(s.contains("(ok)"));

    let o = run(&["verify", p(&out)]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert!(stdout(&o).contains("OK"));

    // Query by positional hashes; type inferred from the hash length.
    let o = run(&[
        "query",
        p(&out),
        "d404b125f9f11f2e2a86a6090def8a23",
        "00000000000000000000000000000000",
    ]);
    assert_eq!(o.status.code(), Some(1), "one missing hash -> exit 1");
    let s = stdout(&o);
    assert!(s.contains("d404b125f9f11f2e2a86a6090def8a23\tfound"));
    assert!(s.contains("00000000000000000000000000000000\tmissing"));

    let o = run(&[
        "query",
        p(&out),
        "-t",
        "sha1",
        "-r",
        "7f8d4622dbd32bda0f546bc4a6027c96d2bead90",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        stdout(&o).trim(),
        "d404b125f9f11f2e2a86a6090def8a23 7f8d4622dbd32bda0f546bc4a6027c96d2bead90"
    );

    let o = run(&["query", p(&out), "-q", "d404b125f9f11f2e2a86a6090def8a23"]);
    assert!(o.status.success());
    assert!(stdout(&o).is_empty());

    // Dump records reproduces the (sorted, unique) input lines.
    let o = run(&["dump", p(&out)]);
    assert!(o.status.success());
    let mut expected: Vec<String> = std::fs::read_to_string(&input)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    expected.sort();
    expected.dedup();
    let got: Vec<String> = stdout(&o).lines().map(str::to_string).collect();
    assert_eq!(got.len(), expected.len());
    let mut got_sorted = got.clone();
    got_sorted.sort();
    assert_eq!(got_sorted, expected);

    let o = run(&["dump", p(&out), "-t", "md5"]);
    assert!(o.status.success());
    assert_eq!(stdout(&o).lines().count(), 344);
    assert!(stdout(&o).lines().all(|l| l.len() == 32));
}

#[test]
fn query_from_stdin_and_found_only() {
    let o = run_with_stdin(
        &["query", p(&fixture("good.hset")), "-f", "-", "--found-only"],
        "0053e9b602c2fa8473262b590f6d24a406ae1cc3\nbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaad\n\nff36a8ea9b657f9c068d91a67195dd0764fd75ff\n",
    );
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        stdout(&o).trim(),
        "0053e9b602c2fa8473262b590f6d24a406ae1cc3\tfound\nff36a8ea9b657f9c068d91a67195dd0764fd75ff\tfound"
    );
}

/// A flag given after a positional hash must still parse as a flag: the
/// fix for negative query values (`--bits`-like decimal entropy values
/// parsing as hashes, not flags) must not make every later hyphen token
/// get swallowed as another hash to look up instead.
#[test]
fn query_flag_after_positional_hash_still_parses() {
    let o = run(&[
        "query",
        p(&fixture("good.hset")),
        "0053e9b602c2fa8473262b590f6d24a406ae1cc3",
        "-q",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).is_empty());

    let o = run(&[
        "query",
        p(&fixture("good.hset")),
        "0053e9b602c2fa8473262b590f6d24a406ae1cc3",
        "--found-only",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        stdout(&o).trim(),
        "0053e9b602c2fa8473262b590f6d24a406ae1cc3\tfound"
    );
}

#[test]
fn set_operations_and_reindex() {
    let dir = tmpdir("setops");
    let a = fixture("md5_sha1_a.hset");
    let b = fixture("md5_sha1_b.hset");
    for (op, expected) in [
        ("union", "md5_sha1_aub.hset"),
        ("intersect", "md5_sha1_anb.hset"),
        ("subtract", "md5_sha1_a-b.hset"),
    ] {
        let out = dir.join(format!("{op}.hset"));
        let o = run(&[op, p(&a), p(&b), "-o", p(&out), "--hint", "legacy"]);
        assert!(o.status.success(), "{op}: {}", stderr(&o));
        let ours = run(&["dump", p(&out)]);
        let theirs = run(&["dump", p(&fixture(expected))]);
        assert_eq!(
            stdout(&ours),
            stdout(&theirs),
            "{op} records differ from reference"
        );
        let o = run(&["verify", p(&out)]);
        assert!(o.status.success(), "{op}: {}", stdout(&o));
        let o = run(&["info", p(&out)]);
        assert!(stdout(&o).contains("block8"), "{}", stdout(&o));
    }

    // Reindex the legacy-hinted union with hull hints at fixed bits.
    let src = dir.join("union.hset");
    let out = dir.join("union-hull.hset");
    let o = run(&[
        "reindex",
        p(&src),
        "-o",
        p(&out),
        "--keep-metadata",
        "--hint",
        "hull",
        "--bits",
        "6",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&["info", p(&out)]);
    assert!(stdout(&o).contains("hull6"), "{}", stdout(&o));
    assert_eq!(
        stdout(&run(&["dump", p(&out)])),
        stdout(&run(&["dump", p(&src)]))
    );
    assert!(run(&["verify", p(&out)]).status.success());

    // Hashes-only output, then reindex to no hint.
    let hashes_only = dir.join("hashes.hset");
    let o = run(&["reindex", p(&src), "-o", p(&hashes_only), "--no-records"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&["info", p(&hashes_only)]);
    assert!(stdout(&o).contains("records:     none"));
    let none = dir.join("none.hset");
    let o = run(&["reindex", p(&hashes_only), "-o", p(&none), "--hint", "none"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&["info", p(&none)]);
    assert!(stdout(&o).contains("hint: none"), "{}", stdout(&o));
    assert!(
        run(&[
            "query",
            p(&none),
            "-t",
            "md5",
            "d404b125f9f11f2e2a86a6090def8a23"
        ])
        .status
        .success()
    );
}

#[test]
fn bench_runs_and_agrees() {
    let o = run(&[
        "bench",
        p(&fixture("good.hset")),
        "--queries",
        "20000",
        "--compare",
        "--batch",
        "64",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&o);
    assert!(s.contains("ns/lookup"));
    assert!(s.contains("no hint (auto search)"));
    assert!(s.contains("legacy block8 hint"));
}

#[test]
fn bench_compare_on_a_tlsh_section_skips_the_legacy_hint() {
    let dir = tmpdir("tlsh-bench");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let o = run(&[
        "bench",
        p(&f),
        "-t",
        "tlsh",
        "--queries",
        "2000",
        "--compare",
        "--hit-fraction",
        "1",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&o);
    assert!(s.contains("tlsh cell index"), "{s}");
    assert_eq!(s.matches("hits 2000/2000").count(), 2, "{s}");
    assert!(s.contains("legacy block8 hint"), "{s}");
    assert!(s.contains("skipped"), "{s}");
}

#[test]
fn errors_are_reported() {
    let o = run(&["info", p(&fixture("bogus.hset"))]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("error"));

    let o = run(&["info", "/nonexistent/file.hset"]);
    assert_eq!(o.status.code(), Some(2));

    let dir = tmpdir("errors");
    let out = dir.join("x.hset");
    let o = run_with_stdin(&["make", "-t", "md5", "-o", p(&out)], "not-hex\n");
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains(":1:"), "{}", stderr(&o));

    let o = run(&[
        "query",
        p(&fixture("good.hset")),
        "-t",
        "md5",
        "00000000000000000000000000000000",
    ]);
    assert_eq!(o.status.code(), Some(2));

    let o = run(&["query", p(&fixture("good.hset"))]);
    assert_eq!(o.status.code(), Some(2));

    let o = run(&[
        "union",
        p(&fixture("good.hset")),
        "/nonexistent/file.hset",
        "-o",
        p(&out),
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("/nonexistent/file.hset"));
}

#[test]
fn make_with_sizes_and_missing_columns() {
    let dir = tmpdir("sizes");
    let out = dir.join("s.hset");
    let o = run_with_stdin(
        &[
            "make",
            "-t",
            "sha1,size",
            "-o",
            p(&out),
            "--hint",
            "block",
            "--bits",
            "4",
        ],
        "0053e9b602c2fa8473262b590f6d24a406ae1cc3 1234\nff36a8ea9b657f9c068d91a67195dd0764fd75ff \n 77\n",
    );
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&["dump", p(&out)]);
    let s = stdout(&o);
    assert!(s.contains("0053e9b602c2fa8473262b590f6d24a406ae1cc3 1234"));
    assert!(s.contains("ff36a8ea9b657f9c068d91a67195dd0764fd75ff "));
    assert!(s.contains(" 77"));
    // Sizes are stored little-endian and sorted bytewise, so 77 (0x4d..) precedes 1234 (0xd2 0x04..).
    let o = run(&["dump", p(&out), "-t", "size"]);
    assert_eq!(stdout(&o).trim(), "77\n1234");
    let o = run(&["query", p(&out), "-t", "size", "77", "78"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("77\tfound"));
    assert!(stdout(&o).contains("78\tmissing"));
    let o = run(&["info", p(&out)]);
    assert!(stdout(&o).contains("block4"), "{}", stdout(&o));
}

const MD5_A: &str = "00112233445566778899aabbccddeeff";
const MD5_B: &str = "ffeeddccbbaa99887766554433221100";
const SHA1_A: &str = "0af8e028c7048ad772ddec2200ec7e0e4d58b0c3";
const SHA1_B: &str = "1127ceb2c2d789c1d7615b12082ca30222f3c612";

/// `make -t md5,sha1` over two records, with `extra` arguments.
fn make_two(out: &Path, extra: &[&str]) {
    let mut args = vec!["make", "-t", "md5,sha1", "-o", p(out)];
    args.extend_from_slice(extra);
    let o = run_with_stdin(&args, &format!("{MD5_A} {SHA1_A}\n{MD5_B} {SHA1_B}\n"));
    assert!(o.status.success(), "{}", stderr(&o));
}

#[test]
fn info_prints_table_sizes_in_bytes_and_kib() {
    let dir = tmpdir("human");
    let small = dir.join("small.hset");
    let big = dir.join("big.hset");
    let input = fixture("md5_sha1_a");
    for (out, bits) in [(&small, "4"), (&big, "8")] {
        let o = run(&[
            "make",
            "-t",
            "md5,sha1",
            "--hint",
            "block",
            "--bits",
            bits,
            "-o",
            p(out),
            p(&input),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
    }
    // 16 entries of 16 bytes, then 256 entries: 4096 bytes.
    let s = stdout(&run(&["info", p(&small)]));
    assert!(s.contains("; table 256 B\n"), "{s}");
    let s = stdout(&run(&["info", p(&big)]));
    assert!(s.contains("; table 4.0 KiB\n"), "{s}");
}

#[test]
fn budget_steers_the_chosen_hint_bits() {
    let dir = tmpdir("budget");
    let input = fixture("md5_sha1_a");
    // 344 hashes of 16 bytes: the default 2% budget affords 16 block
    // entries (4 bits); a budget of the whole hash data affords 256.
    let default = dir.join("default.hset");
    let wide = dir.join("wide.hset");
    for (out, extra) in [(&default, &[][..]), (&wide, &["--budget", "1"][..])] {
        let mut args = vec!["make", "-t", "md5,sha1", "--hint", "block", "-o", p(out)];
        args.extend_from_slice(extra);
        args.push(p(&input));
        let o = run(&args);
        assert!(o.status.success(), "{}", stderr(&o));
    }
    assert!(stdout(&run(&["info", p(&default)])).contains("hint: block4"));
    assert!(stdout(&run(&["info", p(&wide)])).contains("hint: block8"));

    // The same through `reindex` of a file without records, which
    // rebuilds only the hash sections' hints.
    let hashes_only = dir.join("hashes-only.hset");
    let o = run(&[
        "make",
        "-t",
        "md5,sha1",
        "--hint",
        "block",
        "--no-records",
        "-o",
        p(&hashes_only),
        p(&input),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&run(&["info", p(&hashes_only)])).contains("hint: block4"));
    let reindexed = dir.join("reindexed.hset");
    let o = run(&[
        "reindex",
        p(&hashes_only),
        "-o",
        p(&reindexed),
        "--hint",
        "block",
        "--budget",
        "1",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&run(&["info", p(&reindexed)]));
    assert!(s.contains("records:     none"), "{s}");
    assert!(s.contains("hint: block8"), "{s}");
}

#[test]
fn dump_heads_each_section_only_when_there_are_several() {
    let dir = tmpdir("dump-heads");
    let two = dir.join("two.hset");
    make_two(&two, &["--no-records"]);
    assert_eq!(
        stdout(&run(&["dump", p(&two)])),
        format!("# md5 (2 hashes)\n{MD5_A}\n{MD5_B}\n# sha1 (2 hashes)\n{SHA1_A}\n{SHA1_B}\n")
    );
    let one = dir.join("one.hset");
    let o = run_with_stdin(
        &["make", "-t", "md5", "--no-records", "-o", p(&one)],
        &format!("{MD5_A}\n"),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&run(&["dump", p(&one)])), format!("{MD5_A}\n"));
}

#[test]
fn query_records_prints_each_match_and_the_misses() {
    let dir = tmpdir("query-records");
    let f = dir.join("rec.hset");
    make_two(&f, &[]);
    let absent = "00000000000000000000000000000001";
    let o = run(&["query", "-r", p(&f), MD5_B, absent, MD5_A]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        stdout(&o),
        format!("{MD5_B} {SHA1_B}\n{absent}\tmissing\n{MD5_A} {SHA1_A}\n")
    );
    let o = run(&["query", "-r", "--found-only", p(&f), MD5_B, absent]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(stdout(&o), format!("{MD5_B} {SHA1_B}\n"));
}

#[test]
fn bench_single_only_times_single_lookups() {
    let o = run(&[
        "bench",
        p(&fixture("good.hset")),
        "--only",
        "single",
        "--queries",
        "1000",
        "--hit-fraction",
        "1",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("hits 1000/1000"), "{}", stdout(&o));
}

// ---------------------------------------------------------------------------
// TLSH
// ---------------------------------------------------------------------------

/// `make -t md5,tlsh` over `example_text(false)` (83 records, 81 TLSH rows,
/// 80 distinct digests), with `extra` arguments and `env` variables; any
/// inherited `HSET_TLSH_OPTIONS` is removed first.
fn make_tlsh(out: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut args = vec!["make", "-t", "md5,tlsh", "-o", p(out)];
    args.extend_from_slice(extra);
    let mut cmd = bin();
    cmd.args(&args)
        .env_remove("HSET_TLSH_OPTIONS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(hset_testkit::tlsh::example_text(false).as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// [`make_tlsh`] that must succeed.
fn made_tlsh(out: &Path, extra: &[&str]) {
    let o = make_tlsh(out, extra, &[]);
    assert!(o.status.success(), "{}", stderr(&o));
}

/// The 80 distinct example digests in canonical (row) order, as T1 hex.
fn sorted_example_digests() -> Vec<String> {
    let mut d: Vec<TlshDigest> = hset_testkit::tlsh::example_digests()
        .iter()
        .map(|h| TlshDigest::from_hex(h).unwrap())
        .collect();
    d.sort();
    d.iter().map(TlshDigest::to_hex).collect()
}

#[test]
fn dump_prints_tlsh_rows_as_t1_hex() {
    let dir = tmpdir("tlsh-dump");
    let f = dir.join("t.hset");
    made_tlsh(&f, &["--no-records"]);
    let o = run(&["dump", p(&f), "-t", "tlsh"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let want: String = sorted_example_digests()
        .iter()
        .map(|h| format!("{h}\n"))
        .collect();
    assert_eq!(stdout(&o), want);
}

#[test]
fn dumped_tlsh_records_make_the_same_file_again() {
    let dir = tmpdir("tlsh-dump-records");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let o = run(&["dump", p(&f)]);
    assert!(o.status.success(), "{}", stderr(&o));
    let dumped = stdout(&o);
    // The input lines, TNULL printed as an absent (empty) value, sorted.
    let mut want: Vec<String> = hset_testkit::tlsh::example_text(false)
        .lines()
        .map(|l| l.replace("TNULL", ""))
        .collect();
    want.sort();
    let mut got: Vec<String> = dumped.lines().map(str::to_string).collect();
    got.sort();
    assert_eq!(got, want);

    let again = dir.join("again.hset");
    let o = run_with_stdin(&["make", "-t", "md5,tlsh", "-o", p(&again)], &dumped);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&run(&["dump", p(&again)])), dumped);
    assert_eq!(tlsh_parts(&again), tlsh_parts(&f));
}

/// Example digest `i` with hex digit 40 changed: not in the set.
fn absent_digest(i: usize) -> String {
    let mut h = hset_testkit::tlsh::example_digests()[i]
        .clone()
        .into_bytes();
    h[40] = if h[40] == b'0' { b'1' } else { b'0' };
    String::from_utf8(h).unwrap()
}

#[test]
fn query_takes_t1_hex_for_a_tlsh_section() {
    let dir = tmpdir("tlsh-query");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let digests = hset_testkit::tlsh::example_digests();
    let present = &digests[3];
    let absent = absent_digest(3);
    // The section is inferred from a T1 digest's length.
    let o = run(&["query", p(&f), present, &absent]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("{present}\tfound\n{absent}\tmissing\n"));
    // 70 hex digits without the prefix, lowercase, with the type given.
    let bare = present[2..].to_ascii_lowercase();
    let o = run(&["query", p(&f), "-t", "tlsh", &bare]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("{bare}\tfound\n"));
    // The same, inferring the section from the 70-digit length.
    let o = run(&["query", p(&f), &bare]);
    assert!(o.status.success(), "{}", stderr(&o));

    // Records print as dump prints them; digest 7 is in two records.
    let o = run(&["query", p(&f), "-r", &digests[7]]);
    assert!(o.status.success(), "{}", stderr(&o));
    let mut got: Vec<String> = stdout(&o).lines().map(str::to_string).collect();
    got.sort();
    let fake_md5 = hset_testkit::tlsh::fake_md5;
    assert_eq!(
        got,
        vec![
            format!("{} {}", fake_md5(7), digests[7]),
            format!("{} {}", fake_md5(82), digests[7]),
        ]
    );

    // A malformed digest is an error.
    let o = run(&["query", p(&f), "-t", "tlsh", &format!("{present}0")]);
    assert_eq!(o.status.code(), Some(2), "{}", stdout(&o));
}

#[test]
fn info_reports_the_tlsh_cell_hint_and_index() {
    let dir = tmpdir("tlsh-info");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let o = run(&["info", p(&f)]);
    assert!(o.status.success(), "{}", stderr(&o));
    // 76 lists over 81 rows (plan 3.1): 32 + 262148 + 48*76 + 8 + 4*81
    // = 266160 bytes.
    let s = stdout(&o);
    assert!(
        s.contains("      tlsh: cell hint yes; index TIVF, 76 lists (259.9 KiB)\n"),
        "{s}"
    );
    // The md5 section has no TLSH line.
    assert_eq!(s.matches("tlsh: ").count(), 1, "{s}");
}

/// The `info` line of the TLSH section of `f`.
fn tlsh_info_line(f: &Path) -> String {
    let o = run(&["info", p(f)]);
    assert!(o.status.success(), "{}", stderr(&o));
    stdout(&o)
        .lines()
        .find(|l| l.starts_with("      tlsh: "))
        .unwrap_or_else(|| panic!("no tlsh line in {}", stdout(&o)))
        .to_string()
}

const WITH_INDEX: &str = "      tlsh: cell hint yes; index TIVF, 76 lists (259.9 KiB)";
const NO_INDEX: &str = "      tlsh: cell hint yes; index none";

#[test]
fn make_no_tlsh_index_writes_the_cell_hint_but_no_tivf() {
    let dir = tmpdir("tlsh-no-index");
    let f = dir.join("t.hset");
    made_tlsh(&f, &["--no-tlsh-index"]);
    assert_eq!(tlsh_info_line(&f), NO_INDEX);
    // The rows are the same either way.
    let with = dir.join("with.hset");
    made_tlsh(&with, &[]);
    assert_eq!(
        stdout(&run(&["dump", p(&f), "-t", "tlsh"])),
        stdout(&run(&["dump", p(&with), "-t", "tlsh"]))
    );
}

#[test]
fn make_reads_hset_tlsh_options_as_mkhashset_does() {
    let dir = tmpdir("tlsh-env");
    let f = dir.join("t.hset");
    // 2 (INDEX) writes the index; 1 (reserved) and 4 (INHERIT) are ignored.
    for (value, want) in [
        ("0", NO_INDEX),
        ("1", NO_INDEX),
        ("2", WITH_INDEX),
        ("3", WITH_INDEX),
        ("6", WITH_INDEX),
        ("4", NO_INDEX),
    ] {
        let o = make_tlsh(&f, &[], &[("HSET_TLSH_OPTIONS", value)]);
        assert!(o.status.success(), "{value}: {}", stderr(&o));
        assert_eq!(tlsh_info_line(&f), want, "HSET_TLSH_OPTIONS={value}");
    }
    // The flag wins over the variable, which is then not read at all.
    for value in ["2", "junk"] {
        let o = make_tlsh(&f, &["--no-tlsh-index"], &[("HSET_TLSH_OPTIONS", value)]);
        assert!(o.status.success(), "{value}: {}", stderr(&o));
        assert_eq!(tlsh_info_line(&f), NO_INDEX, "HSET_TLSH_OPTIONS={value}");
    }
}

#[test]
fn make_rejects_bad_hset_tlsh_options() {
    let dir = tmpdir("tlsh-env-bad");
    let f = dir.join("t.hset");
    // Not a nonnegative integer (ruling 4; mkhashset's lexical_cast<uint32_t>
    // wraps "-1" around instead), the k-means bit, and unknown bits.
    for value in [
        "-1",
        "abc",
        "",
        " 2",
        "2 ",
        "0x2",
        "4294967296",
        "8",
        "10",
        "16",
    ] {
        let o = make_tlsh(&f, &[], &[("HSET_TLSH_OPTIONS", value)]);
        assert_eq!(o.status.code(), Some(2), "HSET_TLSH_OPTIONS={value:?}");
        assert!(
            stderr(&o).contains("HSET_TLSH_OPTIONS"),
            "{value:?}: {}",
            stderr(&o)
        );
    }
    // Read even when no column is TLSH, as mkhashset reads it.
    let input = dir.join("md5.txt");
    std::fs::write(&input, format!("{MD5_A}\n")).unwrap();
    let o = bin()
        .args(["make", "-t", "md5", "-o", p(&f), p(&input)])
        .env("HSET_TLSH_OPTIONS", "-1")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("HSET_TLSH_OPTIONS"), "{}", stderr(&o));
}

/// The byte ranges in `bytes` of the TLSH section's cell table (the
/// `HINT` payload after its tag) and its `TIVF` payload.
fn tlsh_chunk_ranges(bytes: &[u8]) -> (std::ops::Range<usize>, Option<std::ops::Range<usize>>) {
    let f = hset::format::decode(bytes).unwrap();
    let s = f
        .sections
        .iter()
        .find(|s| s.header.htype == hset::HashType::Tlsh)
        .unwrap();
    let range = |part: &[u8]| {
        let start = part.as_ptr() as usize - bytes.as_ptr() as usize;
        start..start + part.len()
    };
    let Some(hset::format::Hint::TlshCells { table }) = s.hint else {
        panic!("no cell hint");
    };
    (range(table), s.tivf.map(range))
}

/// Write `bytes` to `path` with the file digest recomputed, so that only
/// the deliberate damage is a problem.
fn write_redigested(path: &Path, mut bytes: Vec<u8>) {
    let d = hset::format::encode::file_digest(&bytes).unwrap();
    bytes[8..40].copy_from_slice(&d);
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn verify_prints_the_tlsh_checks() {
    let dir = tmpdir("tlsh-verify");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let o = run(&["verify", p(&f)]);
    assert!(o.status.success(), "{}", stdout(&o));
    let s = stdout(&o);
    assert!(
        s.contains("\ntlsh: tlsh cells_exact=true, index lists=76 valid=true\n"),
        "{s}"
    );
    assert!(s.ends_with("OK\n"), "{s}");

    let none = dir.join("none.hset");
    made_tlsh(&none, &["--no-tlsh-index"]);
    let s = stdout(&run(&["verify", p(&none)]));
    assert!(
        s.contains("\ntlsh: tlsh cells_exact=true, index none\n"),
        "{s}"
    );
}

#[test]
fn verify_fails_on_a_wrong_cell_hint_or_an_invalid_index() {
    let dir = tmpdir("tlsh-verify-bad");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let good = std::fs::read(&f).unwrap();
    let (cells, tivf) = tlsh_chunk_ranges(&good);

    // Move the end of the first nonempty cell down by one row: still a
    // valid (non-decreasing) table, so the file loads, but not the cell
    // index of the rows.
    let mut bad = good.clone();
    let at = |b: &[u8], c: usize| {
        let o = cells.start + 8 * c;
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    };
    let c = (0..65535).find(|&c| at(&bad, c) < at(&bad, c + 1)).unwrap();
    let o = cells.start + 8 * (c + 1);
    let v = at(&bad, c + 1) - 1;
    bad[o..o + 8].copy_from_slice(&v.to_le_bytes());
    let damaged = dir.join("cells.hset");
    write_redigested(&damaged, bad);
    let o = run(&["verify", p(&damaged)]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    let s = stdout(&o);
    assert!(s.contains("tlsh: tlsh cells_exact=false"), "{s}");
    assert!(
        s.contains("PROBLEM: tlsh: TLSH cell hint is not the cell index of the rows"),
        "{s}"
    );

    // Repeat the first row id over the second in the TIVF ids (the last
    // 4n bytes): the header still parses, the full validation fails.
    let tivf = tivf.unwrap();
    let mut bad = good.clone();
    let ids = tivf.end - 4 * 81;
    bad.copy_within(ids..ids + 4, ids + 4);
    let damaged = dir.join("tivf.hset");
    write_redigested(&damaged, bad);
    let o = run(&["verify", p(&damaged)]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    let s = stdout(&o);
    assert!(
        s.contains("tlsh: tlsh cells_exact=true, index lists=76 valid=false"),
        "{s}"
    );
    assert!(s.contains("PROBLEM: tlsh: invalid TIVF index"), "{s}");
}

/// The TLSH section's cell table, `TIVF` payload and rows (`HDAT`) of the
/// file at `path`.
fn tlsh_parts(path: &Path) -> (Vec<u8>, Option<Vec<u8>>, Vec<u8>) {
    let bytes = std::fs::read(path).unwrap();
    let (cells, tivf) = tlsh_chunk_ranges(&bytes);
    let f = hset::format::decode(&bytes).unwrap();
    let rows = f
        .sections
        .iter()
        .find(|s| s.header.htype == hset::HashType::Tlsh)
        .unwrap()
        .data
        .to_vec();
    (bytes[cells].to_vec(), tivf.map(|r| bytes[r].to_vec()), rows)
}

/// `reindex src -o out extra..`, which must succeed and leave a file that
/// verifies.
fn reindexed(src: &Path, out: &Path, extra: &[&str]) {
    let mut args = vec!["reindex", p(src), "-o", p(out)];
    args.extend_from_slice(extra);
    let o = run(&args);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&["verify", p(out)]);
    assert!(o.status.success(), "{}", stdout(&o));
}

#[test]
fn reindex_keeps_the_tlsh_cell_hint_and_index() {
    let dir = tmpdir("tlsh-reindex");
    for (tag, make_extra) in [
        ("records", &[][..]),
        ("hashes", &["--no-records"][..]),
        ("no-index", &["--no-tlsh-index"][..]),
    ] {
        let src = dir.join(format!("{tag}.hset"));
        made_tlsh(&src, make_extra);
        let before = tlsh_parts(&src);
        for hint in ["legacy", "none", "hull"] {
            let out = dir.join(format!("{tag}-{hint}.hset"));
            reindexed(&src, &out, &["--hint", hint]);
            assert_eq!(tlsh_parts(&out), before, "{tag} --hint {hint}");
        }
    }
}

#[test]
fn reindex_to_hashes_only_indexes_the_distinct_rows() {
    let dir = tmpdir("tlsh-reindex-ho");
    let src = dir.join("records.hset");
    made_tlsh(&src, &[]);
    let out = dir.join("hashes.hset");
    reindexed(&src, &out, &["--no-records"]);
    // As make writes the hashes-only file: 80 rows, 76 lists.
    let direct = dir.join("direct.hset");
    made_tlsh(&direct, &["--no-records"]);
    assert_eq!(tlsh_parts(&out), tlsh_parts(&direct));
    // Without an index in, none out.
    let src = dir.join("no-index.hset");
    made_tlsh(&src, &["--no-tlsh-index"]);
    let out = dir.join("no-index-ho.hset");
    reindexed(&src, &out, &["--no-records"]);
    assert_eq!(tlsh_parts(&out).1, None);
}

/// C++ merge outputs carry merged TIVF indexes, which a fresh build would
/// not reproduce (a BISECT build over the same rows has 2858 lists, not
/// 2852, for `merge_alg_ab`; 2266, not 2260, for `merge_df_out2`; 8233, not
/// 34789, for the hashes-only `inc_out_a`): reindex keeps them byte for
/// byte, through the records path and the sections-only path.
#[test]
fn reindex_keeps_a_cpp_merged_index_verbatim() {
    let dir = tmpdir("tlsh-reindex-cpp");
    let mut seen = 0;
    for name in ["merge_alg_ab.hset", "merge_df_out2.hset", "inc_out_a.hset"] {
        let src = fixture(name);
        if !src.exists() {
            eprintln!("skipping {name}: not generated");
            continue;
        }
        seen += 1;
        let out = dir.join(name);
        reindexed(&src, &out, &["--hint", "legacy"]);
        assert_eq!(tlsh_parts(&out), tlsh_parts(&src), "{name}");
    }
    eprintln!("{seen} C++ fixtures checked");
}

/// What `hset knn` prints for `query` as given: one
/// `query<TAB>distance<TAB>row<TAB>digest` line per match of
/// `Hashset::tlsh_knn`, or `query<TAB>none`.
fn library_knn(file: &Path, query: &str, k: usize, max_distance: u32, length: bool) -> String {
    let bytes = std::fs::read(file).unwrap();
    let hs = hset::Hashset::load(&bytes).unwrap();
    let idx = hs.index_for_type(hset::HashType::Tlsh).unwrap();
    let q = TlshDigest::from_hex(query).unwrap();
    let rows = hs.tlsh_rows(idx).unwrap();
    let matches = hs.tlsh_knn(idx, &q, k, max_distance, length).unwrap();
    if matches.is_empty() {
        return format!("{query}\tnone\n");
    }
    matches
        .iter()
        .map(|m| {
            let d = TlshDigest(rows[m.index as usize]);
            format!("{query}\t{}\t{}\t{}\n", m.distance, m.index, d.to_hex())
        })
        .collect()
}

#[test]
fn knn_finds_a_member_at_distance_zero_as_the_library_does() {
    let dir = tmpdir("tlsh-knn");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let digests = hset_testkit::tlsh::example_digests();
    let q = &digests[3];
    let o = run(&["knn", p(&f), q]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&o);
    let first = s.lines().next().unwrap();
    assert!(first.starts_with(&format!("{q}\t0\t")), "{s}");
    assert!(first.ends_with(&format!("\t{q}")), "{s}");
    // Defaults: k = 10, max distance 144, with the length term.
    assert_eq!(s, library_knn(&f, q, 10, 144, true));
    assert!(s.lines().count() <= 10);
}

#[test]
fn knn_strategies_and_options_agree_with_the_library() {
    let dir = tmpdir("tlsh-knn-strategies");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let mut queries = hset_testkit::tlsh::example_digests();
    queries.extend((0..10).map(absent_digest));
    for (k, maxd, length) in [
        (10, 144, true),
        (3, 60, true),
        (25, 300, false),
        (1, 0, true),
    ] {
        let ks = k.to_string();
        let ms = maxd.to_string();
        let mut want = String::new();
        for q in &queries {
            want.push_str(&library_knn(&f, q, k, maxd, length));
        }
        for strategy in ["auto", "brute", "index"] {
            let mut args = vec![
                "knn",
                p(&f),
                "-k",
                &ks,
                "--max-distance",
                &ms,
                "--strategy",
                strategy,
            ];
            if !length {
                args.push("--no-length");
            }
            args.extend(queries.iter().map(String::as_str));
            let o = run(&args);
            assert!(o.status.code().is_some_and(|c| c <= 1), "{}", stderr(&o));
            assert_eq!(
                stdout(&o),
                want,
                "k {k} max {maxd} length {length} {strategy}"
            );
        }
    }
}

#[test]
fn knn_records_stats_stdin_and_exit_status() {
    let dir = tmpdir("tlsh-knn-records");
    let f = dir.join("t.hset");
    made_tlsh(&f, &[]);
    let digests = hset_testkit::tlsh::example_digests();
    let fake_md5 = hset_testkit::tlsh::fake_md5;
    let d7 = &digests[7];

    // Digest 7 is in records 7 and 82: two rows at distance 0, each
    // printed with its record in place of the digest.
    let o = run(&["knn", p(&f), "-k", "2", "--records", d7]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&o);
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2, "{s}");
    let mut records: Vec<&str> = lines
        .iter()
        .map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            assert_eq!(cols.len(), 4, "{l}");
            assert_eq!((cols[0], cols[1]), (d7.as_str(), "0"), "{l}");
            cols[3]
        })
        .collect();
    records.sort();
    assert_eq!(
        records,
        vec![
            format!("{} {d7}", fake_md5(7)),
            format!("{} {d7}", fake_md5(82))
        ]
    );

    // Stats: the index's work counters, as KnnStats counts them.
    let bytes = std::fs::read(&f).unwrap();
    let hs = hset::Hashset::load(&bytes).unwrap();
    let idx = hs.index_for_type(hset::HashType::Tlsh).unwrap();
    let mut stats = hset::tlsh::KnnStats::default();
    let q = TlshDigest::from_hex(&digests[5]).unwrap();
    hs.tlsh_knn_with(
        idx,
        &q,
        10,
        144,
        true,
        hset::hashset::KnnStrategy::Index,
        Some(&mut stats),
    )
    .unwrap();
    let o = run(&["knn", p(&f), "--stats", &digests[5]]);
    assert!(o.status.success(), "{}", stderr(&o));
    let s = stdout(&o);
    assert_eq!(
        s.lines().last().unwrap(),
        format!(
            "# {}: strategy=index cells={} lists={} rows={}",
            digests[5], stats.cells, stats.lists, stats.rows
        ),
        "{s}"
    );
    assert_eq!(
        s.lines().filter(|l| !l.starts_with('#')).count(),
        library_knn(&f, &digests[5], 10, 144, true).lines().count()
    );
    let o = run(&["knn", p(&f), "--stats", "--strategy", "brute", &digests[5]]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        stdout(&o).lines().last().unwrap(),
        format!("# {}: strategy=brute rows=81", digests[5])
    );

    // Queries from stdin, blank lines skipped; one without a match within
    // the bound makes the exit status 1.
    let absent = absent_digest(2);
    let o = run_with_stdin(
        &["knn", p(&f), "-f", "-", "--max-distance", "0"],
        &format!("{}\n\n{absent}\n", digests[2]),
    );
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        format!(
            "{}{absent}\tnone\n",
            library_knn(&f, &digests[2], 10, 0, true)
        )
    );
}

#[test]
fn knn_errors_exit_2() {
    let dir = tmpdir("tlsh-knn-errors");
    let f = dir.join("t.hset");
    made_tlsh(&f, &["--no-tlsh-index"]);
    let ho = dir.join("ho.hset");
    made_tlsh(&ho, &["--no-records"]);
    let md5_only = dir.join("md5.hset");
    make_two(&md5_only, &[]);
    let d = hset_testkit::tlsh::example_digests()[0].clone();
    for (args, what) in [
        (vec!["knn", p(&f), "T1XYZ"], "malformed digest"),
        (vec!["knn", p(&f), &format!("{d}0")], "trailing junk"),
        (vec!["knn", p(&f)], "no queries"),
        (
            vec!["knn", p(&f), "--strategy", "index", &d],
            "index strategy without a TIVF",
        ),
        (
            vec!["knn", p(&ho), "--records", &d],
            "records of a hashes-only file",
        ),
        (vec!["knn", p(&md5_only), &d], "no TLSH section"),
        (vec!["knn", p(&f), "-k", "-1", &d], "negative k"),
        (
            vec!["knn", p(&f), "--max-distance", "-1", &d],
            "negative max distance",
        ),
    ] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2), "{what}: {}", stdout(&o));
        assert!(!stderr(&o).is_empty(), "{what}");
    }
    // Brute force still answers the file without an index.
    let o = run(&["knn", p(&f), &d]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), library_knn(&f, &d, 10, 144, true));
}

/// The C++ `md5_tlsh.hset` fixture (`make check`): every strategy finds a
/// member at distance 0 and answers as the library does.
#[test]
fn knn_on_the_cpp_fixture() {
    let f = fixture("md5_tlsh.hset");
    if !f.exists() {
        eprintln!("skipping: {} not generated", f.display());
        return;
    }
    let digests = hset_testkit::tlsh::example_digests();
    for q in [&digests[0], &digests[7], &digests[42]] {
        let want = library_knn(&f, q, 10, 144, true);
        assert!(want.starts_with(&format!("{q}\t0\t")), "{want}");
        for strategy in ["auto", "brute", "index"] {
            let o = run(&["knn", p(&f), "--strategy", strategy, q]);
            assert!(o.status.success(), "{}", stderr(&o));
            assert_eq!(stdout(&o), want, "{strategy}");
        }
    }
}

// ---------------------------------------------------------------------------
// Set operations by merge
// ---------------------------------------------------------------------------

/// `hset args..` with `env` set, `HSET_TLSH_OPTIONS` and `HSET_COALESCE`
/// removed first.
fn run_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = bin();
    cmd.args(args)
        .env_remove("HSET_TLSH_OPTIONS")
        .env_remove("HSET_COALESCE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// `hset OP left right -o out extra..` with `env`.
fn setop(op: &str, l: &Path, r: &Path, out: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    let mut args = vec![op, p(l), p(r), "-o", p(out)];
    args.extend_from_slice(extra);
    run_env(&args, env)
}

/// [`setop`] that must succeed and leave a file that verifies.
fn setop_ok(op: &str, l: &Path, r: &Path, out: &Path, extra: &[&str], env: &[(&str, &str)]) {
    let o = setop(op, l, r, out, extra, env);
    assert!(o.status.success(), "{op} {extra:?} {env:?}: {}", stderr(&o));
    let o = run(&["verify", p(out)]);
    assert!(o.status.success(), "{op} {extra:?} {env:?}: {}", stdout(&o));
}

/// `make -t types -o out extra..` over `text`, which must succeed.
fn make_text(out: &Path, types: &str, text: &str, extra: &[&str]) {
    let mut args = vec!["make", "-t", types, "-o", p(out)];
    args.extend_from_slice(extra);
    let o = run_with_stdin(&args, text);
    assert!(o.status.success(), "{}", stderr(&o));
}

/// Two `md5,tlsh` files over overlapping parts of the example text
/// (records 0..50 and 30..83), made with `extra_a` and `extra_b`.
fn tlsh_halves(dir: &Path, extra_a: &[&str], extra_b: &[&str]) -> (PathBuf, PathBuf) {
    let text = hset_testkit::tlsh::example_text(false);
    let lines: Vec<&str> = text.lines().collect();
    let (a, b) = (dir.join("a.hset"), dir.join("b.hset"));
    make_text(&a, "md5,tlsh", &(lines[..50].join("\n") + "\n"), extra_a);
    make_text(&b, "md5,tlsh", &(lines[30..].join("\n") + "\n"), extra_b);
    (a, b)
}

/// The library's merge of the files `l` and `r` under `opts`, written to
/// `out`.
fn library_merge(
    op: hset::SetOp,
    l: &Path,
    r: &Path,
    opts: &hset::merge::MergeOptions,
    out: &Path,
) {
    let (lb, rb) = (std::fs::read(l).unwrap(), std::fs::read(r).unwrap());
    let (lh, rh) = (
        hset::Hashset::load(&lb).unwrap(),
        hset::Hashset::load(&rb).unwrap(),
    );
    std::fs::write(out, hset::merge::merge(op, &lh, &rh, opts).unwrap()).unwrap();
}

/// The number of lists of `f`'s TLSH index, `None` without one.
fn tivf_lists(f: &Path) -> Option<usize> {
    let line = tlsh_info_line(f);
    let rest = line.split_once("index TIVF, ")?.1;
    Some(rest.split_once(" lists").unwrap().0.parse().unwrap())
}

#[test]
fn union_of_tlsh_files_carries_the_merged_index() {
    let dir = tmpdir("setop-tlsh");
    let (a, b) = tlsh_halves(&dir, &[], &[]);
    let out = dir.join("u.hset");
    setop_ok("union", &a, &b, &out, &[], &[]);
    let s = stdout(&run(&["verify", p(&out)]));
    assert!(s.contains("tlsh cells_exact=true, index lists="), "{s}");
    assert!(s.contains("valid=true"), "{s}");
    // the index is the library merge's (merged, not rebuilt)
    let lib = dir.join("lib.hset");
    library_merge(
        hset::SetOp::Union,
        &a,
        &b,
        &hset::merge::MergeOptions::new("", ""),
        &lib,
    );
    let parts = tlsh_parts(&out);
    assert!(parts.1.is_some(), "no TIVF");
    assert_eq!(parts, tlsh_parts(&lib));
    // 83 input records, all in the union: the full example's rows
    let full = dir.join("full.hset");
    made_tlsh(&full, &["--no-tlsh-index"]);
    assert_eq!(parts.2, tlsh_parts(&full).2);

    // the index answers as brute force does
    let queries = dir.join("q.txt");
    let mut q = hset_testkit::tlsh::example_digests();
    q.extend((0..10).map(absent_digest));
    std::fs::write(&queries, q.join("\n") + "\n").unwrap();
    let knn = |strategy: &str| {
        let o = run(&[
            "knn",
            p(&out),
            "-f",
            p(&queries),
            "-k",
            "5",
            "--strategy",
            strategy,
        ]);
        assert!(o.status.code().is_some_and(|c| c < 2), "{}", stderr(&o));
        stdout(&o)
    };
    assert_eq!(knn("index"), knn("brute"));

    // `difference` is `subtract`
    let (d1, d2) = (dir.join("d1.hset"), dir.join("d2.hset"));
    setop_ok("subtract", &a, &b, &d1, &[], &[]);
    setop_ok("difference", &a, &b, &d2, &[], &[]);
    assert_eq!(
        stdout(&run(&["dump", p(&d1)])),
        stdout(&run(&["dump", p(&d2)]))
    );
    assert_eq!(tlsh_parts(&d1), tlsh_parts(&d2));
    assert_eq!(stdout(&run(&["dump", p(&d1)])).lines().count(), 30);
}

#[test]
fn tlsh_index_flag_inherits_writes_or_omits_the_index() {
    let dir = tmpdir("setop-tlsh-index");
    let (a, bare) = tlsh_halves(&dir, &[], &["--no-tlsh-index"]);
    let b = dir.join("b-indexed.hset");
    let text = hset_testkit::tlsh::example_text(false);
    let lines: Vec<&str> = text.lines().collect();
    make_text(&b, "md5,tlsh", &(lines[30..].join("\n") + "\n"), &[]);
    let out = dir.join("o.hset");
    // inherit (the default): an index only when every input has one
    for extra in [&[][..], &["--tlsh-index", "inherit"][..]] {
        setop_ok("union", &a, &bare, &out, extra, &[]);
        assert_eq!(tlsh_info_line(&out), NO_INDEX, "{extra:?}");
        setop_ok("union", &a, &b, &out, extra, &[]);
        assert!(tivf_lists(&out).is_some(), "{extra:?}");
    }
    // write: built from the merged rows when an input lacks one
    setop_ok("union", &a, &bare, &out, &["--tlsh-index", "write"], &[]);
    assert!(tivf_lists(&out).is_some());
    let lib = dir.join("lib.hset");
    let mut opts = hset::merge::MergeOptions::new("", "");
    opts.tlsh_index = hset::merge::TlshIndexPolicy::Write;
    library_merge(hset::SetOp::Union, &a, &bare, &opts, &lib);
    assert_eq!(tlsh_parts(&out), tlsh_parts(&lib));
    // omit: never, the cell hint still written
    setop_ok("union", &a, &b, &out, &["--tlsh-index", "omit"], &[]);
    assert_eq!(tlsh_info_line(&out), NO_INDEX);
    let o = setop("union", &a, &b, &out, &["--tlsh-index", "kmeans"], &[]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

#[test]
fn set_operations_read_hset_tlsh_options_as_hsetop_does() {
    let dir = tmpdir("setop-tlsh-env");
    let (a, bare) = tlsh_halves(&dir, &[], &["--no-tlsh-index"]);
    let out = dir.join("o.hset");
    // 0 none, 2 (INDEX) write, 4 (INHERIT) inherit, INHERIT winning over
    // INDEX; bit 1 is ignored
    for (value, indexed) in [
        ("0", false),
        ("1", false),
        ("2", true),
        ("3", true),
        ("4", false),
        ("6", false),
    ] {
        setop_ok(
            "union",
            &a,
            &bare,
            &out,
            &[],
            &[("HSET_TLSH_OPTIONS", value)],
        );
        assert_eq!(
            tivf_lists(&out).is_some(),
            indexed,
            "HSET_TLSH_OPTIONS={value}"
        );
    }
    setop_ok("union", &a, &a, &out, &[], &[("HSET_TLSH_OPTIONS", "0")]);
    assert_eq!(tivf_lists(&out), None);
    // the flag wins over the variable, which is then not read at all
    for value in ["2", "junk"] {
        let env = [("HSET_TLSH_OPTIONS", value)];
        setop_ok("union", &a, &bare, &out, &["--tlsh-index", "omit"], &env);
        assert_eq!(tivf_lists(&out), None, "{value}");
    }
    // not a nonnegative decimal integer (ruling 4), the k-means bit, unknown
    // bits
    for value in [
        "-1",
        "abc",
        "",
        " 2",
        "+2",
        "0x2",
        "4294967296",
        "8",
        "10",
        "16",
    ] {
        let o = setop(
            "union",
            &a,
            &bare,
            &out,
            &[],
            &[("HSET_TLSH_OPTIONS", value)],
        );
        assert_eq!(o.status.code(), Some(2), "HSET_TLSH_OPTIONS={value:?}");
        assert!(
            stderr(&o).contains("HSET_TLSH_OPTIONS"),
            "{value:?}: {}",
            stderr(&o)
        );
    }
}

/// A `tlsh`-only text of `n` random digests in the single header cell
/// (L 50, Q 0x23), from `seed`.
fn one_cell_text(seed: u64, n: usize) -> String {
    let mut rng = hset::synth::SplitMix64::new(seed);
    (0..n)
        .map(|_| hset_testkit::tlsh::random_digest_with_header(&mut rng, 50, 2, 3).to_hex() + "\n")
        .collect()
}

#[test]
fn coalesce_threshold_comes_from_the_flag_or_hset_coalesce() {
    let dir = tmpdir("setop-coalesce");
    // a master and a batch whose rows share one cell: a list each, both
    // below half the default threshold 64
    let (master, batch) = (dir.join("master.hset"), dir.join("batch.hset"));
    make_text(&master, "tlsh", &one_cell_text(1, 10), &[]);
    make_text(&batch, "tlsh", &one_cell_text(2, 10), &[]);
    assert_eq!(
        (tivf_lists(&master), tivf_lists(&batch)),
        (Some(1), Some(1))
    );
    let out = dir.join("o.hset");
    for (extra, env, lists) in [
        (&[][..], &[][..], 1),
        (&["--coalesce", "0"][..], &[][..], 2),
        (&["--coalesce", "64"][..], &[][..], 1),
        (&[][..], &[("HSET_COALESCE", "0")][..], 2),
        (&[][..], &[("HSET_COALESCE", "64")][..], 1),
        (&["--coalesce", "64"][..], &[("HSET_COALESCE", "0")][..], 1),
        (
            &["--coalesce", "0"][..],
            &[("HSET_COALESCE", "junk")][..],
            2,
        ),
    ] {
        setop_ok("union", &master, &batch, &out, extra, env);
        assert_eq!(tivf_lists(&out), Some(lists), "{extra:?} {env:?}");
    }
    for value in ["-1", "abc", "", " 1", "+5", "0x10", "4294967296"] {
        let o = setop(
            "union",
            &master,
            &batch,
            &out,
            &[],
            &[("HSET_COALESCE", value)],
        );
        assert_eq!(o.status.code(), Some(2), "HSET_COALESCE={value:?}");
        assert!(
            stderr(&o).contains("HSET_COALESCE"),
            "{value:?}: {}",
            stderr(&o)
        );
        let o = setop("union", &master, &batch, &out, &["--coalesce", value], &[]);
        assert_eq!(o.status.code(), Some(2), "--coalesce {value:?}");
        assert!(stderr(&o).contains("coalesce"), "{value:?}: {}", stderr(&o));
    }
}

/// The lines `hset dump f extra..` prints, as a set.
fn dump_set(f: &Path, extra: &[&str]) -> std::collections::BTreeSet<String> {
    let mut args = vec!["dump", p(f)];
    args.extend_from_slice(extra);
    let o = run(&args);
    assert!(o.status.success(), "{}", stderr(&o));
    stdout(&o).lines().map(str::to_string).collect()
}

#[test]
fn set_operations_widen_fields_and_merge_differently_shaped_inputs() {
    let dir = tmpdir("setop-widen");
    const MD5_C: &str = "88888888888888888888888888888888";
    let (x, y) = (dir.join("x.hset"), dir.join("y.hset"));
    make_text(&x, "md5,size", &format!("{MD5_A} 10\n{MD5_B} 20\n"), &[]);
    make_text(&y, "md5", &format!("{MD5_A}\n{MD5_C}\n"), &[]);
    // records widened to left's fields then right's extras; a record with
    // the size absent is not one with a size
    let out = dir.join("u.hset");
    for (l, r) in [(&x, &y), (&y, &x)] {
        setop_ok("union", l, r, &out, &[], &[]);
        let info = stdout(&run(&["info", p(&out)]));
        assert!(info.contains("records:     4 x 26 bytes"), "{info}");
        let fields: Vec<&str> = info
            .lines()
            .filter_map(|l| l.strip_prefix("  field "))
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(fields, ["md5", "sizes"]);
        assert_eq!(
            stdout(&run(&["dump", p(&out)])),
            format!("{MD5_A} \n{MD5_A} 10\n{MD5_C} \n{MD5_B} 20\n")
        );
    }
    setop_ok("intersect", &x, &y, &out, &[], &[]);
    assert!(stdout(&run(&["info", p(&out)])).contains("records:     0 x 26 bytes"));

    // a side without records gives a hashsets-only output, a section per
    // type of either input (left's first), each the set union of the rows
    let (good, rec) = (fixture("good.hset"), fixture("md5_sha1_a.hset"));
    setop_ok("union", &good, &rec, &out, &[], &[]);
    let info = stdout(&run(&["info", p(&out)]));
    assert!(info.contains("records:     none"), "{info}");
    assert!(
        info.contains("[0] sha1") && info.contains("[1] md5"),
        "{info}"
    );
    let sha1: std::collections::BTreeSet<String> = dump_set(&good, &["-t", "sha1"])
        .union(&dump_set(&rec, &["-t", "sha1"]))
        .cloned()
        .collect();
    assert_eq!(dump_set(&out, &["-t", "sha1"]), sha1);
    assert_eq!(
        dump_set(&out, &["-t", "md5"]),
        dump_set(&rec, &["-t", "md5"])
    );
    // --no-records on two record files: each row once
    setop_ok("union", &x, &y, &out, &["--no-records"], &[]);
    assert_eq!(
        stdout(&run(&["dump", p(&out), "-t", "md5"])),
        format!("{MD5_A}\n{MD5_C}\n{MD5_B}\n")
    );
    // --no-hashsets: the record table only
    setop_ok("union", &x, &y, &out, &["--no-hashsets"], &[]);
    let info = stdout(&run(&["info", p(&out)]));
    assert!(
        info.contains("sections:    0") && info.contains("records:     4"),
        "{info}"
    );
}

#[test]
fn set_operations_refuse_records_only_against_sections_and_nothing_to_write() {
    let dir = tmpdir("setop-refuse");
    let (two, ro) = (dir.join("two.hset"), dir.join("ro.hset"));
    make_two(&two, &[]);
    make_two(&ro, &["--no-hashsets"]);
    let out = dir.join("o.hset");
    let refused = |l: &Path, r: &Path, extra: &[&str], want: &str| {
        let o = setop("union", l, r, &out, extra, &[]);
        assert_eq!(o.status.code(), Some(2), "{extra:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(want), "{extra:?}: {}", stderr(&o));
    };
    let records_only = "cannot merge a records-only hashset with one that has hash sections";
    refused(&ro, &two, &[], records_only);
    refused(&two, &ro, &[], records_only);
    let nothing = "neither records nor hash sections are to be written";
    refused(&two, &two, &["--no-records", "--no-hashsets"], nothing);
    refused(&ro, &ro, &["--no-records"], nothing);
    refused(&fixture("good.hset"), &two, &["--no-hashsets"], nothing);
    // two records-only files merge to a records-only file
    setop_ok("union", &ro, &ro, &out, &[], &[]);
    let info = stdout(&run(&["info", p(&out)]));
    assert!(
        info.contains("records:     2 x 38 bytes") && info.contains("sections:    0"),
        "{info}"
    );
}
