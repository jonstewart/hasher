//! Set operations (`hset::ops::apply`) against the `BTreeSet` model, plus
//! the algebraic laws and the error contract.

use hset::format::decode;
use hset::ops::{SetOp, apply};
use hset::{BuildOptions, Hashset};
use hset_testkit::checks::{apply_rows, check_set_op};
use hset_testkit::doc::Opts;
use hset_testkit::oracle::set_op_model;
use hset_testkit::strategies::{doc_pair, doc_pair_mismatched, set_op};
use proptest::prelude::*;

proptest! {
    #[test]
    fn apply_matches_model((a, b) in doc_pair(), op in set_op()) {
        check_set_op(op, &a, &b);
    }

    #[test]
    fn union_commutes((a, b) in doc_pair()) {
        prop_assert_eq!(apply_rows(SetOp::Union, &a, &b), apply_rows(SetOp::Union, &b, &a));
    }

    /// Self-union is the operand's own rows, so `a ∩ b` lies within both.
    #[test]
    fn intersection_within_both((a, b) in doc_pair()) {
        let i = apply_rows(SetOp::Intersect, &a, &b);
        let ra = apply_rows(SetOp::Union, &a, &a);
        let rb = apply_rows(SetOp::Union, &b, &b);
        if let (Some(i), Some(ra), Some(rb)) = (i, ra, rb) {
            prop_assert!(i.is_subset(&ra), "{i:?} not within {ra:?}");
            prop_assert!(i.is_subset(&rb), "{i:?} not within {rb:?}");
        }
    }

    #[test]
    fn difference_disjoint_from_right((a, b) in doc_pair()) {
        let d = apply_rows(SetOp::Subtract, &a, &b);
        let rb = apply_rows(SetOp::Union, &b, &b);
        if let (Some(d), Some(rb)) = (d, rb) {
            prop_assert!(d.is_disjoint(&rb), "{d:?} meets {rb:?}");
        }
    }

    /// `(A ∪ B) − B == A − B`.
    #[test]
    fn union_minus_right_is_difference((a, b) in doc_pair()) {
        let u = apply_rows(SetOp::Union, &a, &b);
        let rb = apply_rows(SetOp::Union, &b, &b);
        let d = apply_rows(SetOp::Subtract, &a, &b);
        if let (Some(u), Some(rb), Some(d)) = (u, rb, d) {
            prop_assert_eq!(set_op_model(SetOp::Subtract, &u, &rb), d);
        }
    }

    #[test]
    fn result_builds_and_decodes((a, b) in doc_pair(), op in set_op()) {
        let (ab, bb) = (a.build().unwrap(), b.build().unwrap());
        let (fa, fb) = (decode(&ab).unwrap(), decode(&bb).unwrap());
        if let Ok(builder) = apply(op, &fa, &fb) {
            let opts: BuildOptions = Opts::default_for_tests().build_options();
            let out = builder.build(&opts).unwrap();
            let hs = Hashset::load(&out).unwrap();
            let report = hs.verify();
            prop_assert!(report.is_ok(), "verify: {:?}", report.problems);
        }
    }

    /// No result for differing type sets; `check_set_op` asserts the
    /// error is `Error::Input` mentioning the mismatch (or, when an operand
    /// is records-less with several fields, the missing records).
    #[test]
    fn mismatched_types_error((a, b) in doc_pair_mismatched()) {
        prop_assert!(apply_rows(SetOp::Union, &a, &b).is_none());
        check_set_op(SetOp::Union, &a, &b);
    }
}
