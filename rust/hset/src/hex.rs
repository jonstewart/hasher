//! Hexadecimal encoding and decoding.
//!
//! Three tiers, all backed by the same SIMD kernels (see [`simd`]), which
//! `fearless_simd` dispatches at runtime; [`scalar`] is the portable
//! reference used by the tests.
//!
//! * Convenience: [`encode`] and [`decode`] allocate and return a `String`
//!   or `Vec<u8>`.
//! * Buffer and sink: [`encode_into`] fills a byte slice, [`encode_to_string`]
//!   appends to a `String` (Rust's growable string buffer) and
//!   [`encode_to_writer`] streams into any [`io::Write`]; [`decode_into`]
//!   fills a byte slice. None of these allocate.
//! * Rows: [`encode_rows`], [`encode_rows_to_writer`] and [`decode_rows`]
//!   handle many fixed-width values at once, the shape of a hash-set
//!   section, running the kernel densely across row boundaries.

use std::io;

use crate::error::{Error, Result};

/// Size of the stack buffers the streaming functions work through.
const SCRATCH: usize = 8192;

/// Inputs up to this many bytes (every digest, SHA-512 included) use a
/// small stack buffer; zeroing the full `SCRATCH` per call would cost more
/// than the encode itself.
const SMALL: usize = 64;

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

pub use simd::encode_into;

/// Encode bytes as a new lowercase hex `String`.
pub fn encode(bytes: &[u8]) -> String {
    // Encode straight into the allocation the String will own; the UTF-8
    // check on all-ASCII output is cheap and keeps this module `unsafe`-free.
    let mut v = vec![0u8; bytes.len() * 2];
    simd::encode_into(bytes, &mut v);
    String::from_utf8(v).expect("hex digits are ASCII")
}

/// Append the lowercase hex of `bytes` to `out`. Allocates only if `out`
/// lacks capacity for `2 * bytes.len()` more bytes.
pub fn encode_to_string(bytes: &[u8], out: &mut String) {
    out.reserve(bytes.len() * 2);
    // Every byte produced is an ASCII hex digit; the UTF-8 check is cheap
    // and keeps this module free of `unsafe`.
    if bytes.len() <= SMALL {
        let mut buf = [0u8; 2 * SMALL];
        let hex = &mut buf[..bytes.len() * 2];
        simd::encode_into(bytes, hex);
        out.push_str(str::from_utf8(hex).expect("hex digits are ASCII"));
        return;
    }
    let mut buf = [0u8; SCRATCH];
    for chunk in bytes.chunks(SCRATCH / 2) {
        let hex = &mut buf[..chunk.len() * 2];
        simd::encode_into(chunk, hex);
        out.push_str(str::from_utf8(hex).expect("hex digits are ASCII"));
    }
}

/// Write the lowercase hex of `bytes` to `w` without allocating.
pub fn encode_to_writer<W: io::Write + ?Sized>(bytes: &[u8], w: &mut W) -> io::Result<()> {
    if bytes.len() <= SMALL {
        let mut buf = [0u8; 2 * SMALL];
        let hex = &mut buf[..bytes.len() * 2];
        simd::encode_into(bytes, hex);
        return w.write_all(hex);
    }
    let mut buf = [0u8; SCRATCH];
    for chunk in bytes.chunks(SCRATCH / 2) {
        let hex = &mut buf[..chunk.len() * 2];
        simd::encode_into(chunk, hex);
        w.write_all(hex)?;
    }
    Ok(())
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

/// Decode a hex string of any even length into a new `Vec`.
pub fn decode(src: &str) -> Result<Vec<u8>> {
    if !src.len().is_multiple_of(2) {
        return Err(Error::input(format!("odd-length hex string '{src}'")));
    }
    let mut v = vec![0u8; src.len() / 2];
    decode_into(src, &mut v)?;
    Ok(v)
}

fn check_rows(data: &[u8], width: usize) -> usize {
    assert!(width > 0, "row width must be non-zero");
    assert!(
        data.len().is_multiple_of(width),
        "data length {} is not a multiple of the row width {width}",
        data.len()
    );
    data.len() / width
}

/// Append the hex of every `width`-byte row of `data`, each followed by
/// `sep`, to `out`. `data` is the contiguous layout of a hash-set section.
///
/// Panics if `width` is zero or `data.len()` is not a multiple of it.
pub fn encode_rows(data: &[u8], width: usize, sep: &[u8], out: &mut Vec<u8>) {
    let rows = check_rows(data, width);
    out.reserve(rows * (2 * width + sep.len()));
    if sep.is_empty() {
        // Rows are contiguous in the output too: one dense pass.
        let start = out.len();
        out.resize(start + 2 * data.len(), 0);
        simd::encode_into(data, &mut out[start..]);
        return;
    }
    if 2 * width > SCRATCH {
        for row in data.chunks_exact(width) {
            let start = out.len();
            out.resize(start + 2 * width, 0);
            simd::encode_into(row, &mut out[start..]);
            out.extend_from_slice(sep);
        }
        return;
    }
    // Encode a run of rows densely, then scatter them with separators.
    let per = SCRATCH / (2 * width);
    let mut hex = [0u8; SCRATCH];
    for block in data.chunks(per * width) {
        let h = &mut hex[..block.len() * 2];
        simd::encode_into(block, h);
        for row in h.chunks_exact(2 * width) {
            out.extend_from_slice(row);
            out.extend_from_slice(sep);
        }
    }
}

/// Stream the hex of every `width`-byte row of `data`, each followed by
/// `sep`, to `w`, using fixed stack buffers. Suited to dumping a whole
/// section to a `BufWriter`.
///
/// Panics if `width` is zero or `data.len()` is not a multiple of it.
pub fn encode_rows_to_writer<W: io::Write + ?Sized>(
    data: &[u8],
    width: usize,
    sep: &[u8],
    w: &mut W,
) -> io::Result<()> {
    check_rows(data, width);
    let line = 2 * width + sep.len();
    if line > SCRATCH {
        for row in data.chunks_exact(width) {
            encode_to_writer(row, w)?;
            w.write_all(sep)?;
        }
        return Ok(());
    }
    let per = SCRATCH / line;
    let mut hex = [0u8; SCRATCH];
    let mut lines = [0u8; SCRATCH];
    for block in data.chunks(per * width) {
        let h = &mut hex[..block.len() * 2];
        simd::encode_into(block, h);
        let mut p = 0;
        for row in h.chunks_exact(2 * width) {
            lines[p..p + 2 * width].copy_from_slice(row);
            p += 2 * width;
            lines[p..p + sep.len()].copy_from_slice(sep);
            p += sep.len();
        }
        w.write_all(&lines[..p])?;
    }
    Ok(())
}

/// Decode many hex strings of the same `width` (in bytes), appending the
/// decoded rows to `out` contiguously, and return how many were decoded.
/// Rows are gathered into a stack buffer and decoded in dense batches.
///
/// On error `out` is left exactly as it was and the message names the
/// offending row by its zero-based index.
pub fn decode_rows<'a, I>(rows: I, width: usize, out: &mut Vec<u8>) -> Result<usize>
where
    I: IntoIterator<Item = &'a str>,
{
    assert!(width > 0, "row width must be non-zero");
    let start = out.len();
    let hex_len = 2 * width;
    let per = (SCRATCH / hex_len).max(1);
    let mut scratch = [0u8; SCRATCH];
    let mut gathered = 0usize;
    let mut count = 0usize;

    let bad_digit = |row: usize, s: &[u8]| {
        Error::input(format!(
            "row {row}: invalid hex digit in '{}'",
            String::from_utf8_lossy(s)
        ))
    };
    // Decode a gathered batch into the tail of `out`.
    let flush = |scratch: &[u8], out: &mut Vec<u8>, first_row: usize| -> Result<()> {
        let o = out.len();
        out.resize(o + scratch.len() / 2, 0);
        if simd::decode_into(scratch, &mut out[o..]) {
            return Ok(());
        }
        // Error path only: find which row failed.
        let mut tmp = vec![0u8; width];
        for (i, row) in scratch.chunks_exact(hex_len).enumerate() {
            if !scalar::decode_into(row, &mut tmp) {
                return Err(bad_digit(first_row + i, row));
            }
        }
        unreachable!("dense decode failed but every row decodes");
    };

    for (i, s) in rows.into_iter().enumerate() {
        let b = s.as_bytes();
        if b.len() != hex_len {
            out.truncate(start);
            return Err(Error::input(format!(
                "row {i}: expected {hex_len} hex digits, found {} in '{s}'",
                b.len()
            )));
        }
        if hex_len > SCRATCH {
            let o = out.len();
            out.resize(o + width, 0);
            if !simd::decode_into(b, &mut out[o..]) {
                out.truncate(start);
                return Err(bad_digit(i, b));
            }
            count += 1;
            continue;
        }
        scratch[gathered * hex_len..(gathered + 1) * hex_len].copy_from_slice(b);
        gathered += 1;
        count += 1;
        if gathered == per {
            if let Err(e) = flush(&scratch[..gathered * hex_len], out, count - gathered) {
                out.truncate(start);
                return Err(e);
            }
            gathered = 0;
        }
    }
    if gathered > 0
        && let Err(e) = flush(&scratch[..gathered * hex_len], out, count - gathered)
    {
        out.truncate(start);
        return Err(e);
    }
    Ok(count)
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

    // ---- buffer, writer and row APIs ----------------------------------------

    #[test]
    fn encode_to_string_appends_without_reallocating() {
        let bytes = pseudo_random(20, 3);
        let mut s = String::with_capacity(8 + 40);
        s.push_str("prefix: ");
        let cap = s.capacity();
        encode_to_string(&bytes, &mut s);
        assert_eq!(s, format!("prefix: {}", encode(&bytes)));
        assert_eq!(s.capacity(), cap);
    }

    #[test]
    fn encode_to_string_handles_long_input_across_chunks() {
        let bytes = pseudo_random(10_000, 4);
        let mut s = String::new();
        encode_to_string(&bytes, &mut s);
        assert_eq!(s, encode(&bytes));
    }

    #[test]
    fn encode_to_writer_writes_exact_bytes() {
        let bytes = pseudo_random(64, 5);
        let mut w: Vec<u8> = b"x".to_vec();
        encode_to_writer(&bytes, &mut w).unwrap();
        assert_eq!(w, format!("x{}", encode(&bytes)).into_bytes());
        let mut w = Vec::new();
        encode_to_writer(&pseudo_random(10_000, 6), &mut w).unwrap();
        assert_eq!(w, encode(&pseudo_random(10_000, 6)).into_bytes());
    }

    #[test]
    fn encode_into_top_level_fills_buffer() {
        let bytes = pseudo_random(20, 8);
        let mut out = [0u8; 40];
        encode_into(&bytes, &mut out);
        assert_eq!(&out[..], encode(&bytes).as_bytes());
    }

    #[test]
    #[should_panic(expected = "2x")]
    fn encode_into_panics_on_wrong_size() {
        let mut out = [0u8; 3];
        encode_into(&[1, 2], &mut out);
    }

    fn rows_reference(data: &[u8], width: usize, sep: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        for row in data.chunks_exact(width) {
            v.extend_from_slice(encode(row).as_bytes());
            v.extend_from_slice(sep);
        }
        v
    }

    #[test]
    fn encode_rows_matches_per_row_encode_for_every_width_and_count() {
        for width in [1usize, 16, 20, 32, 64] {
            for rows in [0usize, 1, 2, 7, 63, 64, 65, 200] {
                let data = pseudo_random(rows * width, 9 + width as u64 + rows as u64);
                for sep in [&b""[..], b"\n", b", "] {
                    let mut out = b"head\n".to_vec();
                    encode_rows(&data, width, sep, &mut out);
                    let mut want = b"head\n".to_vec();
                    want.extend(rows_reference(&data, width, sep));
                    assert_eq!(out, want, "width {width} rows {rows} sep {sep:?}");
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "multiple of")]
    fn encode_rows_panics_on_ragged_data() {
        let mut out = Vec::new();
        encode_rows(&[0u8; 21], 20, b"\n", &mut out);
    }

    #[test]
    #[should_panic(expected = "width")]
    fn encode_rows_panics_on_zero_width() {
        let mut out = Vec::new();
        encode_rows(&[], 0, b"\n", &mut out);
    }

    #[test]
    fn encode_rows_to_writer_matches_encode_rows() {
        for width in [1usize, 20, 64, 5000] {
            for rows in [0usize, 1, 5, 130, 1000] {
                let data = pseudo_random(rows * width, 11 + width as u64 + rows as u64);
                let mut want = Vec::new();
                encode_rows(&data, width, b"\n", &mut want);
                let mut got = Vec::new();
                encode_rows_to_writer(&data, width, b"\n", &mut got).unwrap();
                assert_eq!(got, want, "width {width} rows {rows}");
            }
        }
    }

    #[test]
    fn decode_rows_appends_every_row_and_returns_count() {
        for width in [1usize, 16, 20, 32, 64, 5000] {
            for rows in [0usize, 1, 2, 63, 64, 65, 300] {
                let data = pseudo_random(rows * width, 13 + width as u64 + rows as u64);
                let strs: Vec<String> = data
                    .chunks_exact(width)
                    .enumerate()
                    .map(|(i, r)| {
                        let s = encode(r);
                        if i % 2 == 0 { s } else { s.to_uppercase() }
                    })
                    .collect();
                let mut out = vec![0xAAu8; 3];
                let n = decode_rows(strs.iter().map(String::as_str), width, &mut out).unwrap();
                assert_eq!(n, rows, "width {width}");
                assert_eq!(&out[..3], &[0xAA; 3]);
                assert_eq!(&out[3..], &data[..], "width {width} rows {rows}");
            }
        }
    }

    #[test]
    fn decode_rows_reports_the_bad_row_and_leaves_output_untouched() {
        let data = pseudo_random(20 * 100, 17);
        let mut strs: Vec<String> = data.as_chunks::<20>().0.iter().map(|r| encode(r)).collect();
        strs[77].replace_range(5..6, "g");
        let mut out = vec![1u8, 2, 3];
        let e = decode_rows(strs.iter().map(String::as_str), 20, &mut out).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("row 77"), "{msg}");
        assert!(msg.contains("invalid hex digit"), "{msg}");
        assert_eq!(out, [1, 2, 3]);

        let mut strs: Vec<String> = data.as_chunks::<20>().0.iter().map(|r| encode(r)).collect();
        strs[3].pop();
        let e = decode_rows(strs.iter().map(String::as_str), 20, &mut out).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("row 3"), "{msg}");
        assert!(msg.contains("expected 40 hex digits, found 39"), "{msg}");
        assert_eq!(out, [1, 2, 3]);
    }

    #[test]
    fn decode_rows_rejects_bad_row_in_a_later_chunk() {
        // 300 SHA-512 rows span several gather chunks; corrupt one near the end.
        let data = pseudo_random(64 * 300, 19);
        let mut strs: Vec<String> = data.as_chunks::<64>().0.iter().map(|r| encode(r)).collect();
        strs[290].replace_range(127..128, "Z");
        let mut out = Vec::new();
        let e = decode_rows(strs.iter().map(String::as_str), 64, &mut out).unwrap_err();
        assert!(e.to_string().contains("row 290"), "{e}");
        assert!(out.is_empty());
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
