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
        p(&fixture("md5_sha1_a.hset")),
        "-o",
        p(&out),
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("mismatch"));
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
