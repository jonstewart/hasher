//! The order in which a kNN search visits cells: (L, Q) headers sorted by
//! their header cost from the query (`tlsh_header_order.cpp`).
//!
//! TLSH header costs depend only on the circular differences k of L
//! (mod 256) and of Q1, Q2 (mod 16) from the query, so the order is the
//! same for every query up to a translation. L values are visited as
//! `L, L+1, L-1, L+2, L-2, ..., L-127, L+128` at cost [`l_cost`]`(k)`, or
//! as `0..=255` at cost 0 when the length is excluded. Q bytes follow a
//! static table of `(k1, k2)` pairs, `k` in `0..=8`, stably sorted by
//! `q_cost(k1) + q_cost(k2)`; each pair expands to the Q bytes
//! `(q1 ± k1, q2 ± k2)` (mod 16) in the order `(+,+)`, `(+,-)`, `(-,+)`,
//! `(-,-)`, dropping a `-` that repeats its `+` (k of 0, or 8).

use super::digest::TlshDigest;
use super::distance::{l_cost, q_cost};

/// Q-cost of a `(k1, k2)` offset pair.
const fn pair_cost((k1, k2): (u8, u8)) -> u32 {
    q_cost(k1 as u32) + q_cost(k2 as u32)
}

/// The 81 `(k1, k2)` pairs in `0..=8 x 0..=8`, k1-major, stably sorted by
/// [`pair_cost`] (C++ `QPairs`, which uses `std::stable_sort`).
const Q_PAIRS: [(u8, u8); 81] = {
    let mut p = [(0u8, 0u8); 81];
    let mut n = 0;
    let mut k1 = 0;
    while k1 <= 8 {
        let mut k2 = 0;
        while k2 <= 8 {
            p[n] = (k1, k2);
            n += 1;
            k2 += 1;
        }
        k1 += 1;
    }
    // insertion sort, moving only past strictly costlier pairs: stable
    let mut i = 1;
    while i < p.len() {
        let x = p[i];
        let mut j = i;
        while j > 0 && pair_cost(p[j - 1]) > pair_cost(x) {
            p[j] = p[j - 1];
            j -= 1;
        }
        p[j] = x;
        i += 1;
    }
    p
};

/// The 256 L values and the 256 Q bytes in nondecreasing header-cost
/// order from a query (C++ `TlshHeaderOrder`; see the
/// [module docs](self)). A cell search walks L in [`l`](Self::l) order,
/// then Q in [`q`](Self::q) order, and can stop each loop at the first
/// entry whose cost alone exceeds its bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderOrder {
    l: [u8; 256],
    l_cost: [u32; 256],
    q: [u8; 256],
    q_cost: [u32; 256],
}

impl HeaderOrder {
    /// The visiting order for `query`; with `include_length` false every L
    /// costs 0 and the L order is `0..=255`.
    pub fn new(query: &TlshDigest, include_length: bool) -> Self {
        let mut l = [0u8; 256];
        let mut l_costs = [0u32; 256];
        if include_length {
            let ql = query.l();
            l[0] = ql;
            let mut n = 1;
            for k in 1..=128u8 {
                let c = l_cost(k.into());
                l[n] = ql.wrapping_add(k);
                l_costs[n] = c;
                n += 1;
                if k != 128 {
                    l[n] = ql.wrapping_sub(k);
                    l_costs[n] = c;
                    n += 1;
                }
            }
        } else {
            for (i, v) in l.iter_mut().enumerate() {
                *v = i as u8;
            }
        }

        let mut q = [0u8; 256];
        let mut q_costs = [0u32; 256];
        let (q1, q2) = (query.q1(), query.q2());
        let mut n = 0;
        let mut emit = |x: u8, y: u8, c: u32| {
            q[n] = (x << 4) | y;
            q_costs[n] = c;
            n += 1;
        };
        for (k1, k2) in Q_PAIRS {
            let c = pair_cost((k1, k2));
            let (a1, b1) = (q1.wrapping_add(k1) & 0x0F, q1.wrapping_sub(k1) & 0x0F);
            let (a2, b2) = (q2.wrapping_add(k2) & 0x0F, q2.wrapping_sub(k2) & 0x0F);
            emit(a1, a2, c);
            if b2 != a2 {
                emit(a1, b2, c);
            }
            if b1 != a1 {
                emit(b1, a2, c);
                if b2 != a2 {
                    emit(b1, b2, c);
                }
            }
        }
        debug_assert_eq!(n, 256);

        Self {
            l,
            l_cost: l_costs,
            q,
            q_cost: q_costs,
        }
    }

    /// L values, nondecreasing [`l_cost`](Self::l_cost).
    pub fn l(&self) -> &[u8; 256] {
        &self.l
    }

    /// The L cost of each entry of [`l`](Self::l) (all 0 without the
    /// length).
    pub fn l_cost(&self) -> &[u32; 256] {
        &self.l_cost
    }

    /// Q bytes (`(Q1 << 4) | Q2`), nondecreasing [`q_cost`](Self::q_cost).
    pub fn q(&self) -> &[u8; 256] {
        &self.q
    }

    /// The Q1 plus Q2 cost of each entry of [`q`](Self::q).
    pub fn q_cost(&self) -> &[u32; 256] {
        &self.q_cost
    }
}
