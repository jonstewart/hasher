//! Property test: `hset make` ingests `Doc::to_text()` and writes the file
//! `Doc::expected()` models, `hset dump` reproduces its sorted,
//! deduplicated records and `hset make` of the dump the same file, `hset
//! info --chunks` reports a verified digest, `hset query` agrees with
//! `NaiveSet` for a mix of present and random values of the first field
//! and of a TLSH field, and `hset knn` with `naive_knn`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use hset::HashType;
use hset::builder::format_value;
use hset::format::{FieldDescriptor, decode};
use hset::lookup::HintSpec;
use hset::synth::SplitMix64;
use hset::tlsh::TlshDigest;
use hset_testkit::doc::{Doc, Field, Opts};
use hset_testkit::oracle::NaiveSet;
use hset_testkit::strategies::cli_doc;
use hset_testkit::tlsh::{naive_knn, random_digest};
use proptest::prelude::*;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hset"))
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("spawn hset")
}

fn run_with_stdin(args: &[&str], stdin: &str) -> Output {
    run_cmd_with_stdin(bin(), args, stdin)
}

fn run_cmd_with_stdin(mut cmd: Command, args: &[&str], stdin: &str) -> Output {
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hset");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait hset")
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh scratch path, removed by its `Drop` impl (also on the proptest
/// failure path, since `prop_assert!` fails via an early `return`).
struct TempOut(PathBuf);

impl TempOut {
    fn new() -> TempOut {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        TempOut(std::env::temp_dir().join(format!("hset-prop-{}-{n}.hset", std::process::id())))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempOut {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `--hint`/`--bits` flags that make `hset make` build `spec`, per
/// `OutputArgs::hint_spec`'s inverse in `hset-cli/src/main.rs`.
fn hint_args(spec: HintSpec) -> Vec<String> {
    match spec {
        HintSpec::None => vec!["--hint".to_string(), "none".to_string()],
        HintSpec::Block { bits: 0 } => vec!["--hint".to_string(), "block".to_string()],
        HintSpec::Block { bits } => vec![
            "--hint".to_string(),
            "block".to_string(),
            "--bits".to_string(),
            bits.to_string(),
        ],
        HintSpec::Hull { bits } if bits == u8::MAX => {
            vec!["--hint".to_string(), "hull".to_string()]
        }
        HintSpec::Hull { bits } => vec![
            "--hint".to_string(),
            "hull".to_string(),
            "--bits".to_string(),
            bits.to_string(),
        ],
    }
}

/// `fields[i]`'s slice (presence byte, then value) of a laid-out record row.
fn field_slice<'a>(fields: &[FieldDescriptor], row: &'a [u8], i: usize) -> &'a [u8] {
    let off: usize = fields[..i].iter().map(FieldDescriptor::stride).sum();
    &row[off..off + fields[i].stride()]
}

/// Render one laid-out record row exactly as `hset dump` prints it: per
/// field, `format_value` or empty when absent, space-joined.
fn render_record(fields: &[FieldDescriptor], row: &[u8]) -> String {
    (0..fields.len())
        .map(|i| {
            let slice = field_slice(fields, row, i);
            if slice[0] == 1 {
                format_value(&fields[i], &slice[1..])
            } else {
                String::new()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A random value shaped like `htype`, drawn from `rng`. Entropy bits that
/// decode to a non-finite float are coerced to `0.0` so the CLI's decimal
/// text round-trip (`format_value`/`parse_value`) agrees with the oracle.
///
/// A TLSH value is a random canonical digest, which `hset query` can parse.
fn random_value(htype: HashType, rng: &mut SplitMix64) -> Vec<u8> {
    match htype {
        HashType::Tlsh => random_digest(rng).0.to_vec(),
        HashType::Size => rng.next_u64().to_le_bytes().to_vec(),
        HashType::Entropy => {
            let v = f64::from_bits(rng.next_u64());
            let v = if v.is_finite() { v } else { 0.0 };
            v.to_le_bytes().to_vec()
        }
        _ => {
            let len = htype.length().expect("storable type");
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf);
            buf
        }
    }
}

/// `hset make` arguments building `d` into `out`: its types, metadata,
/// timestamp, budget and hint, and `--no-tlsh-index` when it has no index.
fn make_args(d: &Doc, out: &Path) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "make".to_string(),
        "-t".to_string(),
        d.type_list(),
        "-n".to_string(),
        d.opts.name.clone(),
        "-d".to_string(),
        d.opts.desc.clone(),
        "--timestamp".to_string(),
        d.opts.timestamp.clone(),
        "--budget".to_string(),
        d.opts.bits_policy.budget.to_string(),
    ];
    args.extend(hint_args(d.opts.hint));
    if !d.opts.tlsh_index {
        args.push("--no-tlsh-index".to_string());
    }
    args.push("-o".to_string());
    args.push(p(out).to_string());
    args
}

/// `hset make` with `args` and `stdin`, `HSET_TLSH_OPTIONS` unset.
fn make(args: &[String], stdin: &str) -> Output {
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut cmd = bin();
    cmd.env_remove("HSET_TLSH_OPTIONS");
    run_cmd_with_stdin(cmd, &arg_refs, stdin)
}

/// What `hset knn FILE -k K --max-distance M QUERIES..` prints over the
/// sorted TLSH rows `rows`: per query its [`naive_knn`] matches as
/// `query, distance, row, row digest`, or `query none`.
fn knn_lines(rows: &[[u8; 36]], queries: &[TlshDigest], k: usize, max: u32) -> Vec<String> {
    let mut out = Vec::new();
    for q in queries {
        let hex = q.to_hex();
        let m = naive_knn(rows, q, k, max, true);
        if m.is_empty() {
            out.push(format!("{hex}\tnone"));
        }
        for mt in m {
            let row = TlshDigest(rows[mt.index as usize]).to_hex();
            out.push(format!("{hex}\t{}\t{}\t{row}", mt.distance, mt.index));
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, .. ProptestConfig::default() })]
    #[test]
    fn make_dump_query_match_oracle(d in cli_doc(), seed in any::<u64>()) {
        let out = TempOut::new();
        let expected = d.expected();

        let o = make(&make_args(&d, out.path()), &d.to_text());
        prop_assert!(o.status.success(), "make failed: {}", stderr(&o));
        let bytes = std::fs::read(out.path()).unwrap();
        expected.assert_matches(&decode(&bytes).unwrap());

        // `hset dump` reproduces the expected sorted, deduplicated records.
        let o = run(&["dump", p(out.path())]);
        prop_assert!(o.status.success(), "dump failed: {}", stderr(&o));
        let expected_lines: Vec<String> = expected
            .records
            .as_ref()
            .expect("cli_doc always has records")
            .iter()
            .map(|r| render_record(&expected.fields, r))
            .collect();
        let dump_text = stdout(&o);
        let got_lines: Vec<&str> = dump_text.lines().collect();
        prop_assert_eq!(
            got_lines,
            expected_lines.iter().map(String::as_str).collect::<Vec<_>>()
        );

        // `hset make` of the dump builds the same file again.
        let again = TempOut::new();
        let o = make(&make_args(&d, again.path()), &dump_text);
        prop_assert!(o.status.success(), "make of the dump failed: {}", stderr(&o));
        prop_assert!(std::fs::read(again.path()).unwrap() == bytes, "make of the dump differs");

        // `hset info --chunks` verifies its own digest.
        let o = run(&["info", p(out.path()), "--chunks"]);
        prop_assert!(o.status.success(), "info failed: {}", stderr(&o));
        prop_assert!(stdout(&o).contains("(ok)"), "no verified digest: {}", stdout(&o));

        // Query the first field, and the TLSH field when there is one, with
        // up to 4 present values plus 4 random ones, checked against a
        // `NaiveSet` built on the expected section.
        let mut rng = SplitMix64::new(seed);
        let tlsh = d.fields.iter().position(|f| f.htype == HashType::Tlsh);
        let mut queried = vec![0];
        queried.extend(tlsh.filter(|&i| i != 0));
        for i in queried {
            let f = &d.fields[i];
            let section = &expected.sections[i];
            let present: std::collections::BTreeSet<Vec<u8>> =
                section.hashes.iter().cloned().collect();
            let mut values: Vec<Vec<u8>> = present.into_iter().take(4).collect();
            for _ in 0..4 {
                values.push(random_value(f.htype, &mut rng));
            }

            let naive = NaiveSet::from_bytes(&section.hashes.concat(), section.hash_length);
            let rendered: Vec<String> = values
                .iter()
                .map(|v| format_value(&f.descriptor(), v))
                .collect();
            let expect_found: Vec<bool> = values.iter().map(|v| naive.contains(v)).collect();

            let mut qargs: Vec<&str> = vec!["query", p(out.path()), "-t", f.htype.field_name()];
            qargs.extend(rendered.iter().map(String::as_str));
            let o = run(&qargs);
            let all_found = expect_found.iter().all(|&b| b);
            let want_code = Some(if all_found { 0 } else { 1 });
            prop_assert_eq!(
                o.status.code(),
                want_code,
                "exit code disagreed with the oracle: {}",
                stderr(&o)
            );
            let query_text = stdout(&o);
            let out_lines: Vec<&str> = query_text.lines().collect();
            let want_lines: Vec<String> = rendered
                .iter()
                .zip(&expect_found)
                .map(|(v, &found)| format!("{v}\t{}", if found { "found" } else { "missing" }))
                .collect();
            prop_assert_eq!(out_lines, want_lines.iter().map(String::as_str).collect::<Vec<_>>());
        }

        // `hset knn`: every stored digest finds its own rows at distance 0,
        // and the default search (k 10, distance 144) of members and a
        // random digest is the naive kNN.
        if let Some(i) = tlsh {
            let section = &expected.sections[i];
            let rows: Vec<[u8; 36]> =
                section.hashes.iter().map(|h| h[..].try_into().unwrap()).collect();
            let mut members: Vec<TlshDigest> = rows.iter().map(|r| TlshDigest(*r)).collect();
            members.dedup();
            if !members.is_empty() {
                let hexes: Vec<String> = members.iter().map(TlshDigest::to_hex).collect();
                let k = rows.len().to_string();
                let mut kargs = vec!["knn", p(out.path()), "-k", &k, "--max-distance", "0"];
                kargs.extend(hexes.iter().map(String::as_str));
                let o = run(&kargs);
                prop_assert!(o.status.success(), "knn of members failed: {}", stderr(&o));
                let want: Vec<String> = rows
                    .iter()
                    .enumerate()
                    .map(|(row, r)| {
                        let hex = TlshDigest(*r).to_hex();
                        (members.binary_search(&TlshDigest(*r)).unwrap(), row, hex)
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .map(|(_, row, hex)| format!("{hex}\t0\t{row}\t{hex}"))
                    .collect();
                let text = stdout(&o);
                prop_assert_eq!(text.lines().collect::<Vec<_>>(), want.iter().map(String::as_str).collect::<Vec<_>>());
            }

            let mut queries: Vec<TlshDigest> = members.iter().take(3).copied().collect();
            queries.push(random_digest(&mut rng));
            let hexes: Vec<String> = queries.iter().map(TlshDigest::to_hex).collect();
            let mut kargs = vec!["knn", p(out.path())];
            kargs.extend(hexes.iter().map(String::as_str));
            let o = run(&kargs);
            let want = knn_lines(&rows, &queries, 10, 144);
            let unmatched = want.iter().any(|l| l.ends_with("\tnone"));
            prop_assert_eq!(o.status.code(), Some(i32::from(unmatched)), "knn: {}", stderr(&o));
            let text = stdout(&o);
            prop_assert_eq!(text.lines().collect::<Vec<_>>(), want.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }
}

/// Pins the text format's skip rule for the case that collides with a
/// single-field record: a blank line is always a skipped separator,
/// never an all-absent record, even though that line is also the only
/// other way a single-field document could render "the field is
/// absent". `cli_doc()` accordingly never generates an all-absent record
/// for a single-field document (it has no text rendering `hset make`
/// would read back), so the property test above never has to reconcile
/// this with the oracle.
#[test]
fn single_field_blank_line_is_skipped_not_stored() {
    let d = Doc {
        fields: vec![Field::canonical(HashType::Size)],
        records: vec![vec![Some(7u64.to_le_bytes().to_vec())], vec![None]],
        opts: Opts::default_for_tests(),
    };
    // The present record renders as "7"; the absent one renders as its
    // one empty column, i.e. a blank line.
    assert_eq!(d.to_text(), "7\n\n");
    let out = TempOut::new();
    let o = run_with_stdin(
        &[
            "make",
            "-t",
            &d.type_list(),
            "-o",
            out.path().to_str().unwrap(),
        ],
        &d.to_text(),
    );
    assert!(o.status.success(), "make failed: {}", stderr(&o));
    let o = run(&["dump", p(out.path())]);
    assert!(o.status.success(), "dump failed: {}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "7\n",
        "a blank single-field line must be skipped, not stored as a record"
    );
}

/// Regression: a name or description starting with `-` is ordinary data
/// (`Opts::name` and `Opts::desc` are arbitrary printable ASCII), but
/// clap parses it as an unrecognized flag following `-n`/`-d`, because
/// `OutputArgs::name` and `OutputArgs::desc` lack `allow_hyphen_values`.
#[test]
fn make_accepts_a_name_starting_with_a_hyphen() {
    let out = TempOut::new();
    let o = run_with_stdin(
        &[
            "make",
            "-t",
            "sha2_224",
            "-n",
            "-A",
            "-d",
            "-B",
            "-o",
            out.path().to_str().unwrap(),
        ],
        "",
    );
    assert!(o.status.success(), "make failed: {}", stderr(&o));
    let o = run(&["info", p(out.path())]);
    assert!(o.status.success(), "info failed: {}", stderr(&o));
    let s = stdout(&o);
    assert!(s.contains("name:        -A"), "{s}");
    assert!(s.contains("description: -B"), "{s}");
}

/// Regression: a negative decimal entropy value, passed positionally to
/// `hset query`, is parsed by clap as an unrecognized flag (e.g. `-1`
/// out of `-1.5`) rather than accepted as a hash to look up, because
/// `QueryArgs::hashes` lacks a way to recognize negative numbers as
/// values. The fix must not require `--` before a negative query value,
/// and must not reopen `query_flag_after_positional_hash_still_parses`
/// in `cli.rs` (a flag after a positional hash must still parse as a
/// flag, not get swallowed as another hash).
#[test]
fn query_accepts_negative_entropy_values() {
    let d = Doc {
        fields: vec![Field::canonical(HashType::Entropy)],
        records: vec![vec![Some((-1.5f64).to_le_bytes().to_vec())]],
        opts: Opts::default_for_tests(),
    };
    let out = TempOut::new();
    let o = run_with_stdin(
        &[
            "make",
            "-t",
            &d.type_list(),
            "-o",
            out.path().to_str().unwrap(),
        ],
        &d.to_text(),
    );
    assert!(o.status.success(), "make failed: {}", stderr(&o));
    let o = run(&["query", p(out.path()), "-t", "entropy", "-1.5"]);
    assert!(o.status.success(), "query failed: {}", stderr(&o));
    assert_eq!(stdout(&o), "-1.5\tfound\n");
}
