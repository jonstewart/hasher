//! End-to-end tests of the `hset` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hset"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test")
        .join(name)
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
