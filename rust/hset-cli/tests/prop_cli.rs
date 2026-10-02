//! Property test: `hset make` ingests `Doc::to_text()`, `hset dump`
//! reproduces `Doc::expected()`'s sorted, deduplicated records, `hset info
//! --chunks` reports a verified digest, and `hset query` agrees with
//! `NaiveSet` for a mix of present and random values of the first field.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use hset::HashType;
use hset::builder::format_value;
use hset::format::FieldDescriptor;
use hset::lookup::HintSpec;
use hset::synth::SplitMix64;
use hset_testkit::doc::{Doc, Field, Opts};
use hset_testkit::oracle::NaiveSet;
use hset_testkit::strategies::cli_doc;
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
    let mut child = bin()
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
fn random_value(htype: HashType, rng: &mut SplitMix64) -> Vec<u8> {
    match htype {
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

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, .. ProptestConfig::default() })]
    #[test]
    fn make_dump_query_match_oracle(d in cli_doc(), seed in any::<u64>()) {
        let out = TempOut::new();
        let expected = d.expected();

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
        args.push("-o".to_string());
        args.push(out.path().to_str().unwrap().to_string());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

        let o = run_with_stdin(&arg_refs, &d.to_text());
        prop_assert!(o.status.success(), "make failed: {}", stderr(&o));

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

        // `hset info --chunks` verifies its own digest.
        let o = run(&["info", p(out.path()), "--chunks"]);
        prop_assert!(o.status.success(), "info failed: {}", stderr(&o));
        prop_assert!(stdout(&o).contains("(ok)"), "no verified digest: {}", stdout(&o));

        // Query the first field with up to 4 present values plus 4 random
        // ones, checked against a `NaiveSet` built on the expected section.
        let f = &d.fields[0];
        let section = &expected.sections[0];
        let present: std::collections::BTreeSet<Vec<u8>> =
            section.hashes.iter().cloned().collect();
        let mut values: Vec<Vec<u8>> = present.into_iter().take(4).collect();
        let mut rng = SplitMix64::new(seed);
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
