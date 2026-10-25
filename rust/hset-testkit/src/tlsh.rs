//! TLSH test data: the reference implementation's example digests and
//! distance scores (vendored from `vendors/tlsh/Testing/exp/` into
//! `rust/hset/tests/data/tlsh/`, so `cargo-mutants`' copy of the workspace
//! has them), and the text fixture the C++ TLSH hash-set tests build from.
//!
//! Everything here is plain strings and numbers read from the files or
//! written out by hand, not values computed with `hset::tlsh`.

use std::fs;
use std::path::PathBuf;

/// The first example digest (`example_data/021106_yossivassa.txt`), the
/// C++ tests' `VEC_HEX`.
pub const VEC_HEX: &str =
    "T11FA1B357F78913B236924271569EA6D1FB2C451C33668484552C812D33138B8C73FFCE";

/// Directory holding the vendored reference files.
pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../hset/tests/data/tlsh")
}

fn read_data(name: &str) -> String {
    let path = data_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The 80 `(hex digest, file name)` pairs of
/// `example_data.128.1.len.out_EXP`, in file order.
///
/// Read as the C++ tests read it (`in >> hex >> path`): whitespace-separated
/// tokens taken two at a time.
pub fn example_entries() -> Vec<(String, String)> {
    let text = read_data("example_data.128.1.len.out_EXP");
    let tokens: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(tokens.len() % 2, 0, "len.out_EXP has an odd token count");
    let v: Vec<(String, String)> = tokens
        .chunks(2)
        .map(|p| (p[0].to_string(), p[1].to_string()))
        .collect();
    assert_eq!(v.len(), 80);
    v
}

/// The 80 example hex digests, in file order (`read_example_digests` in
/// `test_hset_tlsh.cpp`).
pub fn example_digests() -> Vec<String> {
    example_entries().into_iter().map(|(hex, _)| hex).collect()
}

/// Hex digest of an example file by name, as in the entries.
pub fn example_digest_of(path: &str) -> String {
    example_entries()
        .into_iter()
        .find(|(_, p)| p == path)
        .map(|(hex, _)| hex)
        .unwrap_or_else(|| panic!("no example digest for {path}"))
}

/// The 80 `(file a, file b, score)` triples of the reference's distance
/// scores: `example_data.128.1.len.scores_EXP` (`include_length` true) or
/// `example_data.128.1.xlen.scores_EXP` (false). Read as the C++ test does
/// (`in >> a >> b >> score`).
pub fn example_scores(include_length: bool) -> Vec<(String, String, u32)> {
    let name = if include_length {
        "example_data.128.1.len.scores_EXP"
    } else {
        "example_data.128.1.xlen.scores_EXP"
    };
    let text = read_data(name);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(tokens.len() % 3, 0, "{name} has a token count not a multiple of 3");
    let v: Vec<(String, String, u32)> = tokens
        .chunks(3)
        .map(|t| {
            let score = t[2]
                .parse()
                .unwrap_or_else(|_| panic!("{name}: bad score {:?}", t[2]));
            (t[0].to_string(), t[1].to_string(), score)
        })
        .collect();
    assert_eq!(v.len(), 80);
    v
}

/// A distinct, deterministic 32-digit hex "md5" per index, as `fake_md5` in
/// `test_hset_tlsh.cpp`: `i * 2654435761 + 0x9E3779B9` (wrapping `u64`)
/// zero-padded to 32 lowercase hex digits.
pub fn fake_md5(i: u64) -> String {
    format!(
        "{:032x}",
        i.wrapping_mul(2_654_435_761).wrapping_add(0x9E37_79B9)
    )
}

/// The two-column text of `make_fixture` in `test_hset_tlsh.cpp`, one
/// `"<md5> <tlsh>\n"` line per record (`"<tlsh> <md5>\n"` with
/// `tlsh_first`): the 80 example digests with `fake_md5(0..80)`, then
/// `fake_md5(80)` with `TNULL`, `fake_md5(81)` with an empty TLSH column
/// (the line keeps its separating space), and `fake_md5(82)` with
/// example digest 7 again. 83 records, 81 TLSH rows, 80 distinct digests.
pub fn example_text(tlsh_first: bool) -> String {
    let digests = example_digests();
    let mut tlsh: Vec<&str> = digests.iter().map(String::as_str).collect();
    tlsh.push("TNULL");
    tlsh.push("");
    tlsh.push(&digests[7]);
    let mut out = String::new();
    for (i, t) in tlsh.iter().enumerate() {
        let md5 = fake_md5(i as u64);
        if tlsh_first {
            out.push_str(&format!("{t} {md5}\n"));
        } else {
            out.push_str(&format!("{md5} {t}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_md5_matches_hand_values() {
        // 0 * 2654435761 + 0x9E3779B9; 1 * 2654435761 = 0x9E3779B1.
        assert_eq!(fake_md5(0), "0000000000000000000000009e3779b9");
        assert_eq!(fake_md5(1), "0000000000000000000000013c6ef36a");
    }

    #[test]
    fn example_text_has_83_lines_and_the_special_rows() {
        let t = example_text(false);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 83);
        assert_eq!(lines[0], format!("{} {VEC_HEX}", fake_md5(0)));
        assert_eq!(lines[80], format!("{} TNULL", fake_md5(80)));
        assert_eq!(lines[81], format!("{} ", fake_md5(81)));
        assert_eq!(lines[82].split(' ').nth(1), lines[7].split(' ').nth(1));
        let f = example_text(true);
        assert_eq!(f.lines().nth(81), Some(format!(" {}", fake_md5(81)).as_str()));
        assert_eq!(
            f.lines().next(),
            Some(format!("{VEC_HEX} {}", fake_md5(0)).as_str())
        );
    }

    #[test]
    fn scores_name_example_files() {
        for include_length in [true, false] {
            for (a, b, _) in example_scores(include_length) {
                example_digest_of(&a);
                example_digest_of(&b);
            }
        }
    }
}
