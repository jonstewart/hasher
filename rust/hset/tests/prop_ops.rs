//! Set operations (`hset::merge::merge`) against the testkit's model of
//! the C++ merge semantics, plus the algebraic laws.
//!
//! The laws compare [`OpContent`]: records as their present fields (so a
//! union's field order, left's then right's extras, plays no part) when the
//! output has records, else the distinct `(type, value)` section rows.

use std::collections::BTreeSet;

use hset::SetOp;
use hset_testkit::checks::{OpContent, check_set_op, set_op_content};
use hset_testkit::strategies::{doc_pair, doc_pair_mismatched, set_op};
use proptest::prelude::*;

/// `a − b` of the record sets when both outputs have records, else of the
/// section rows.
fn difference(a: &OpContent, b: &OpContent) -> OpContent {
    OpContent {
        records: match (&a.records, &b.records) {
            (Some(x), Some(y)) => Some(x.difference(y).cloned().collect()),
            _ => None,
        },
        values: a.values.difference(&b.values).cloned().collect(),
    }
}

fn subset<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> bool {
    a.is_subset(b)
}

proptest! {
    #[test]
    fn merge_matches_model((a, b) in doc_pair(), op in set_op()) {
        check_set_op(op, &a, &b);
    }

    /// Documents of different field types merge as the model says: widened
    /// to left's fields then right's extras with records on both sides,
    /// section by section otherwise, refused only when exactly one side
    /// has hash sections.
    #[test]
    fn differently_typed_documents_merge_as_modelled(
        (a, b) in doc_pair_mismatched(),
        op in set_op(),
    ) {
        check_set_op(op, &a, &b);
        let merged = set_op_content(op, &a, &b);
        prop_assert_eq!(merged.is_some(), a.opts.with_hashsets == b.opts.with_hashsets);
    }

    #[test]
    fn union_commutes((a, b) in prop_oneof![doc_pair(), doc_pair_mismatched()]) {
        prop_assert_eq!(
            set_op_content(SetOp::Union, &a, &b),
            set_op_content(SetOp::Union, &b, &a)
        );
    }

    /// Self-union is the operand's own content, so `a ∩ b` lies within
    /// both.
    #[test]
    fn intersection_within_both((a, b) in prop_oneof![doc_pair(), doc_pair_mismatched()]) {
        let i = set_op_content(SetOp::Intersect, &a, &b);
        let ra = set_op_content(SetOp::Union, &a, &a);
        let rb = set_op_content(SetOp::Union, &b, &b);
        if let (Some(i), Some(ra), Some(rb)) = (i, ra, rb) {
            prop_assert!(subset(&i.values, &ra.values), "{i:?} not within {ra:?}");
            prop_assert!(subset(&i.values, &rb.values), "{i:?} not within {rb:?}");
            if let (Some(ir), Some(ar), Some(br)) = (&i.records, &ra.records, &rb.records) {
                prop_assert!(subset(ir, ar) && subset(ir, br), "{i:?}");
            }
        }
    }

    /// A record difference shares no record with the right side; a
    /// section difference (no records on some side) no row.
    #[test]
    fn difference_disjoint_from_right((a, b) in prop_oneof![doc_pair(), doc_pair_mismatched()]) {
        let d = set_op_content(SetOp::Subtract, &a, &b);
        let rb = set_op_content(SetOp::Union, &b, &b);
        if let (Some(d), Some(rb)) = (d, rb) {
            match (&d.records, &rb.records) {
                (Some(dr), Some(br)) => prop_assert!(dr.is_disjoint(br), "{d:?} meets {rb:?}"),
                _ => prop_assert!(d.values.is_disjoint(&rb.values), "{d:?} meets {rb:?}"),
            }
        }
    }

    /// `(A ∪ B) − B == A − B`.
    #[test]
    fn union_minus_right_is_difference(
        (a, b) in prop_oneof![doc_pair(), doc_pair_mismatched()],
    ) {
        let u = set_op_content(SetOp::Union, &a, &b);
        let rb = set_op_content(SetOp::Union, &b, &b);
        let d = set_op_content(SetOp::Subtract, &a, &b);
        if let (Some(u), Some(rb), Some(d)) = (u, rb, d) {
            let got = difference(&u, &rb);
            match d.records {
                Some(_) => prop_assert_eq!(got.records, d.records),
                None => prop_assert_eq!(got.values, d.values),
            }
        }
    }
}
