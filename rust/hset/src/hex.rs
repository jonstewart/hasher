//! Hexadecimal encoding and decoding.
//!
//! The public functions run SIMD kernels (see [`simd`]) chosen at runtime by
//! `fearless_simd`; [`scalar`] is the portable reference used for tests.

use crate::error::{Error, Result};

/// Portable scalar reference implementation.
pub mod scalar {
    const LOWER: &[u8; 16] = b"0123456789abcdef";

    /// Write `2 * bytes.len()` lowercase hex digits into `out`.
    pub fn encode_into(bytes: &[u8], out: &mut [u8]) {
        debug_assert_eq!(out.len(), bytes.len() * 2);
        let (pairs, _) = out.as_chunks_mut::<2>();
        for (b, o) in bytes.iter().zip(pairs) {
            o[0] = LOWER[(b >> 4) as usize];
            o[1] = LOWER[(b & 0xf) as usize];
        }
    }

    /// Encode bytes as a lowercase hex string.
    pub fn encode(bytes: &[u8]) -> String {
        let mut v = vec![0u8; bytes.len() * 2];
        encode_into(bytes, &mut v);
        // SAFETY-free: every byte written is an ASCII hex digit.
        String::from_utf8(v).expect("hex digits are ASCII")
    }

    #[inline]
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    /// Decode `2 * out.len()` hex digits from `src` into `out`. Returns
    /// `false` (leaving `out` unspecified) if any byte is not a hex digit.
    pub fn decode_into(src: &[u8], out: &mut [u8]) -> bool {
        debug_assert_eq!(src.len(), out.len() * 2);
        let (pairs, _) = src.as_chunks::<2>();
        for (o, pair) in out.iter_mut().zip(pairs) {
            match (nibble(pair[0]), nibble(pair[1])) {
                (Some(h), Some(l)) => *o = (h << 4) | l,
                _ => return false,
            }
        }
        true
    }
}

/// SIMD kernels, generic over the `fearless_simd` level and dispatched at
/// runtime. Both kernels work on 16-byte blocks. A partial final block is
/// handled by re-running the kernel on the last full block (overlapping
/// output with identical bytes) or, for inputs shorter than one block, by
/// padding into a stack buffer, so every byte goes through the vector path.
pub mod simd {
    use fearless_simd::{Level, Simd, dispatch, mask8x16, prelude::*, u8x16, u16x8};

    const BLOCK: usize = 16;

    /// Write `2 * bytes.len()` lowercase hex digits into `out`, using the
    /// best SIMD level detected on this CPU.
    pub fn encode_into(bytes: &[u8], out: &mut [u8]) {
        encode_into_at(Level::new(), bytes, out);
    }

    /// Decode `2 * out.len()` hex digits from `src` into `out`, using the
    /// best SIMD level detected on this CPU. Returns `false` (leaving `out`
    /// unspecified) if any byte is not a hex digit.
    pub fn decode_into(src: &[u8], out: &mut [u8]) -> bool {
        decode_into_at(Level::new(), src, out)
    }

    /// [`encode_into`] pinned to a specific SIMD level (for tests and benches).
    #[doc(hidden)]
    pub fn encode_into_at(level: Level, bytes: &[u8], out: &mut [u8]) {
        assert_eq!(out.len(), bytes.len() * 2, "output must be 2x input");
        dispatch!(level, simd => encode_kernel(simd, bytes, out));
    }

    /// [`decode_into`] pinned to a specific SIMD level (for tests and benches).
    #[doc(hidden)]
    pub fn decode_into_at(level: Level, src: &[u8], out: &mut [u8]) -> bool {
        assert_eq!(src.len(), out.len() * 2, "input must be 2x output");
        dispatch!(level, simd => decode_kernel(simd, src, out))
    }

    /// 16 bytes -> 32 ASCII hex digits.
    #[inline(always)]
    fn encode_block<S: Simd>(simd: S, v: u8x16<S>) -> (u8x16<S>, u8x16<S>) {
        let hi = v >> 4;
        let lo = v & 0x0f;
        // n -> '0' + n for n <= 9, 'a' + (n - 10) otherwise.
        let nine = u8x16::splat(simd, 9);
        let digit = u8x16::splat(simd, b'0');
        let alpha = u8x16::splat(simd, b'a' - 10);
        let hi = hi + hi.simd_gt(nine).select(alpha, digit);
        let lo = lo + lo.simd_gt(nine).select(alpha, digit);
        // Interleave: hi digit then lo digit for each byte.
        (hi.zip_low(lo), hi.zip_high(lo))
    }

    #[inline(always)]
    fn encode_kernel<S: Simd>(simd: S, bytes: &[u8], out: &mut [u8]) {
        let n = bytes.len();
        let (src, rem) = bytes.as_chunks::<BLOCK>();
        let (dst, tail) = out.as_chunks_mut::<{ 2 * BLOCK }>();
        for (s, d) in src.iter().zip(dst) {
            let (a, b) = encode_block(simd, u8x16::from_slice(simd, s));
            a.store_slice(&mut d[..BLOCK]);
            b.store_slice(&mut d[BLOCK..]);
        }
        if rem.is_empty() {
            return;
        }
        if n >= BLOCK {
            // Re-encode the last full block, overlapping already-written
            // output with identical bytes; cheaper than padding and copying.
            let s = &bytes[n - BLOCK..];
            let d = &mut out[2 * (n - BLOCK)..];
            let (a, b) = encode_block(simd, u8x16::from_slice(simd, s));
            a.store_slice(&mut d[..BLOCK]);
            b.store_slice(&mut d[BLOCK..]);
        } else {
            let mut pad = [0u8; BLOCK];
            pad[..n].copy_from_slice(rem);
            let (a, b) = encode_block(simd, u8x16::from_slice(simd, &pad));
            let mut tmp = [0u8; 2 * BLOCK];
            a.store_slice(&mut tmp[..BLOCK]);
            b.store_slice(&mut tmp[BLOCK..]);
            tail.copy_from_slice(&tmp[..2 * n]);
        }
    }

    /// 16 ASCII bytes -> 16 nibble values (0..=15) plus a mask of invalid lanes.
    #[inline(always)]
    fn nibbles<S: Simd>(simd: S, c: u8x16<S>) -> (u8x16<S>, mask8x16<S>) {
        // Digits: c - '0' in 0..=9 (unsigned compare makes wrapping harmless).
        let d = c - b'0';
        let is_digit = d.simd_lt(u8x16::splat(simd, 10));
        // Letters: fold case, then (c | 0x20) - 'a' in 0..=5.
        let a = (c | 0x20) - b'a';
        let is_alpha = a.simd_lt(u8x16::splat(simd, 6));
        let val = is_digit.select(d, a + 10);
        (val, !(is_digit | is_alpha))
    }

    /// 32 ASCII hex digits -> 16 bytes, OR-ing invalid lanes into `bad`.
    #[inline(always)]
    fn decode_block<S: Simd>(
        simd: S,
        c0: u8x16<S>,
        c1: u8x16<S>,
        bad: &mut mask8x16<S>,
    ) -> u8x16<S> {
        let (n0, b0) = nibbles(simd, c0);
        let (n1, b1) = nibbles(simd, c1);
        *bad |= b0 | b1;
        // Each u16 lane holds [hi_nibble, lo_nibble] (little-endian), so the
        // byte is (lane << 4 | lane >> 8) & 0xff; narrow truncates to u8.
        let w0: u16x8<S> = n0.bitcast();
        let w1: u16x8<S> = n1.bitcast();
        let w0 = (w0 << 4) | (w0 >> 8);
        let w1 = (w1 << 4) | (w1 >> 8);
        w0.narrow(w1)
    }

    #[inline(always)]
    fn decode_kernel<S: Simd>(simd: S, src: &[u8], out: &mut [u8]) -> bool {
        let mut bad = mask8x16::splat(simd, false);
        let n = out.len();
        let (blocks, rem) = src.as_chunks::<{ 2 * BLOCK }>();
        let (dst, tail) = out.as_chunks_mut::<BLOCK>();
        for (s, d) in blocks.iter().zip(dst) {
            let c0 = u8x16::from_slice(simd, &s[..BLOCK]);
            let c1 = u8x16::from_slice(simd, &s[BLOCK..]);
            decode_block(simd, c0, c1, &mut bad).store_slice(d);
        }
        if rem.is_empty() {
            // nothing left
        } else if n >= BLOCK {
            // Re-decode the last full block; the overlap rewrites identical
            // bytes and re-validates digits that were already accepted.
            let s = &src[2 * (n - BLOCK)..];
            let c0 = u8x16::from_slice(simd, &s[..BLOCK]);
            let c1 = u8x16::from_slice(simd, &s[BLOCK..]);
            decode_block(simd, c0, c1, &mut bad).store_slice(&mut out[n - BLOCK..]);
        } else {
            let mut pad = [b'0'; 2 * BLOCK];
            pad[..2 * n].copy_from_slice(rem);
            let c0 = u8x16::from_slice(simd, &pad[..BLOCK]);
            let c1 = u8x16::from_slice(simd, &pad[BLOCK..]);
            let v = decode_block(simd, c0, c1, &mut bad);
            tail.copy_from_slice(&v.as_slice()[..n]);
        }
        !bad.any_true()
    }
}

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut v = vec![0u8; bytes.len() * 2];
    simd::encode_into(bytes, &mut v);
    // Every byte written is an ASCII hex digit.
    String::from_utf8(v).expect("hex digits are ASCII")
}

/// Decode hex into `out`. The input must be exactly `2 * out.len()` hex digits.
pub fn decode_into(src: &str, out: &mut [u8]) -> Result<()> {
    let s = src.as_bytes();
    if s.len() != out.len() * 2 {
        return Err(Error::input(format!(
            "expected {} hex digits, found {} in '{src}'",
            out.len() * 2,
            s.len()
        )));
    }
    if !simd::decode_into(s, out) {
        return Err(Error::input(format!("invalid hex digit in '{src}'")));
    }
    Ok(())
}

/// Decode a hex string of any even length.
pub fn decode(src: &str) -> Result<Vec<u8>> {
    if !src.len().is_multiple_of(2) {
        return Err(Error::input(format!("odd-length hex string '{src}'")));
    }
    let mut v = vec![0u8; src.len() / 2];
    decode_into(src, &mut v)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (xorshift) so failures reproduce.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn is_hex_digit(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    // ---- public API --------------------------------------------------------

    #[test]
    fn roundtrip_all_byte_values() {
        let bytes: Vec<u8> = (0..=255).collect();
        let s = encode(&bytes);
        assert_eq!(s.len(), 512);
        assert_eq!(decode(&s).unwrap(), bytes);
        assert_eq!(decode(&s.to_uppercase()).unwrap(), bytes);
    }

    #[test]
    fn encode_is_lowercase_and_matches_reference() {
        for len in 0..=80 {
            let bytes = pseudo_random(len, 0xA5A5 + len as u64);
            let s = encode(&bytes);
            assert_eq!(s, scalar::encode(&bytes), "len {len}");
            assert!(s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        }
    }

    #[test]
    fn decode_accepts_mixed_case() {
        let bytes = pseudo_random(40, 7);
        let lower = encode(&bytes);
        let mixed: String = lower
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 3 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(decode(&mixed).unwrap(), bytes);
    }

    #[test]
    fn decode_rejects_odd_length_and_wrong_width() {
        assert!(decode("abc").is_err());
        let mut out = [0u8; 2];
        assert!(decode_into("abcdef", &mut out).is_err());
        assert!(decode_into("ab", &mut out).is_err());
        assert!(decode_into("abcd", &mut out).is_ok());
        assert_eq!(out, [0xab, 0xcd]);
    }

    #[test]
    fn decode_rejects_non_ascii_utf8() {
        // Two-byte UTF-8 sequence in place of two hex digits.
        assert!(decode("é").is_err());
        assert!(decode("abcdé").is_err());
    }

    #[test]
    fn decode_error_messages_name_the_problem() {
        let e = decode("zz").unwrap_err().to_string();
        assert!(e.contains("invalid hex digit"), "{e}");
        let e = decode("abc").unwrap_err().to_string();
        assert!(e.contains("odd-length"), "{e}");
        let mut out = [0u8; 4];
        let e = decode_into("ab", &mut out).unwrap_err().to_string();
        assert!(e.contains("expected 8 hex digits, found 2"), "{e}");
    }

    // ---- simd kernels vs scalar reference -----------------------------------

    /// Every SIMD level we can run here: the baseline the binary is compiled
    /// for (SSE2 on x86_64) and whatever runtime detection picks.
    fn levels() -> Vec<fearless_simd::Level> {
        vec![
            fearless_simd::Level::baseline(),
            fearless_simd::Level::new(),
        ]
    }

    #[test]
    fn simd_kernels_agree_across_levels() {
        for len in 0..=80 {
            let bytes = pseudo_random(len, 0x1EE7 + len as u64);
            let want = scalar::encode(&bytes).into_bytes();
            for level in levels() {
                let mut got = vec![0u8; len * 2];
                simd::encode_into_at(level, &bytes, &mut got);
                assert_eq!(got, want, "encode len {len} at {level:?}");
                let mut back = vec![0u8; len];
                assert!(simd::decode_into_at(level, &want, &mut back));
                assert_eq!(back, bytes, "decode len {len} at {level:?}");
                let upper = want.to_ascii_uppercase();
                assert!(simd::decode_into_at(level, &upper, &mut back));
                assert_eq!(back, bytes, "decode upper len {len} at {level:?}");
                if len > 0 {
                    let mut bad = want.clone();
                    bad[len] = b'g';
                    assert!(!simd::decode_into_at(level, &bad, &mut back), "{level:?}");
                }
            }
        }
    }

    #[test]
    fn simd_encode_matches_scalar_at_every_length() {
        for len in 0..=80 {
            let bytes = pseudo_random(len, 0xBEEF + len as u64);
            let mut got = vec![0u8; len * 2];
            simd::encode_into(&bytes, &mut got);
            let mut want = vec![0u8; len * 2];
            scalar::encode_into(&bytes, &mut want);
            assert_eq!(got, want, "len {len}");
        }
    }

    #[test]
    fn simd_encode_covers_every_byte_value() {
        let bytes: Vec<u8> = (0..=255).collect();
        let mut got = vec![0u8; 512];
        simd::encode_into(&bytes, &mut got);
        assert_eq!(got, scalar::encode(&bytes).into_bytes());
    }

    #[test]
    fn simd_decode_matches_scalar_lower_upper_and_mixed() {
        for len in 0..=80 {
            let bytes = pseudo_random(len, 0xC0DE + len as u64);
            let lower = scalar::encode(&bytes).into_bytes();
            let upper = lower.to_ascii_uppercase();
            let mixed: Vec<u8> = lower
                .iter()
                .enumerate()
                .map(|(i, &c)| {
                    if i % 2 == 1 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            for src in [&lower, &upper, &mixed] {
                let mut got = vec![0xEEu8; len];
                assert!(simd::decode_into(src, &mut got), "len {len}");
                assert_eq!(got, bytes, "len {len}");
            }
        }
    }

    #[test]
    fn simd_decode_covers_every_digit_pair() {
        // Every (hi, lo) digit pair in both cases decodes to the right byte.
        let bytes: Vec<u8> = (0..=255).collect();
        for src in [
            scalar::encode(&bytes).into_bytes(),
            scalar::encode(&bytes).to_ascii_uppercase().into_bytes(),
        ] {
            let mut got = vec![0u8; 256];
            assert!(simd::decode_into(&src, &mut got));
            assert_eq!(got, bytes);
        }
    }

    #[test]
    fn simd_decode_rejects_every_invalid_byte_at_every_position() {
        // Covers the case-fold traps ('@' | 0x20 == '`', '[' .. '_' map into
        // 'a'-adjacent values), digits' neighbours '/' and ':', 'g'/'G', and
        // all non-ASCII bytes, at every lane of both full and padded blocks.
        for len in [1usize, 15, 16, 17, 20, 32, 33, 64] {
            let bytes = pseudo_random(len, 0xF00D + len as u64);
            let valid = scalar::encode(&bytes).into_bytes();
            let mut out = vec![0u8; len];
            for pos in 0..valid.len() {
                for b in 0..=255u8 {
                    if is_hex_digit(b) {
                        continue;
                    }
                    let mut src = valid.clone();
                    src[pos] = b;
                    assert!(
                        !simd::decode_into(&src, &mut out),
                        "len {len}: accepted byte {b:#04x} at position {pos}"
                    );
                }
            }
        }
    }

    #[test]
    fn simd_decode_accepts_every_valid_byte_at_every_position() {
        for len in [1usize, 16, 20, 32] {
            let bytes = pseudo_random(len, 0xD00D + len as u64);
            let valid = scalar::encode(&bytes).into_bytes();
            let mut out = vec![0u8; len];
            let mut want = vec![0u8; len];
            for pos in 0..valid.len() {
                for b in 0..=255u8 {
                    if !is_hex_digit(b) {
                        continue;
                    }
                    let mut src = valid.clone();
                    src[pos] = b;
                    assert!(scalar::decode_into(&src, &mut want));
                    assert!(simd::decode_into(&src, &mut out), "len {len} pos {pos} {b}");
                    assert_eq!(out, want, "len {len} pos {pos} {b}");
                }
            }
        }
    }

    #[test]
    fn simd_decode_rejects_bad_digit_in_padded_tail() {
        // 20 bytes = one full 32-char block + 8-char tail; the tail is padded.
        let bytes = pseudo_random(20, 99);
        let mut src = scalar::encode(&bytes).into_bytes();
        src[39] = b'g';
        let mut out = [0u8; 20];
        assert!(!simd::decode_into(&src, &mut out));
        src[39] = b'0';
        src[32] = 0xff;
        assert!(!simd::decode_into(&src, &mut out));
    }

    #[test]
    fn simd_empty_input_is_a_noop() {
        let mut out: [u8; 0] = [];
        simd::encode_into(&[], &mut out);
        assert!(simd::decode_into(&[], &mut out));
    }
}
