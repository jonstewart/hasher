//! Hexadecimal encoding and decoding.

use crate::error::{Error, Result};

const LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LOWER[(b >> 4) as usize] as char);
        s.push(LOWER[(b & 0xf) as usize] as char);
    }
    s
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
    for (i, o) in out.iter_mut().enumerate() {
        let hi = nibble(s[2 * i]);
        let lo = nibble(s[2 * i + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => *o = (h << 4) | l,
            _ => return Err(Error::input(format!("invalid hex digit in '{src}'"))),
        }
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

    #[test]
    fn roundtrip() {
        let bytes: Vec<u8> = (0..=255).collect();
        let s = encode(&bytes);
        assert_eq!(s.len(), 512);
        assert_eq!(decode(&s).unwrap(), bytes);
        assert_eq!(decode(&s.to_uppercase()).unwrap(), bytes);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        let mut out = [0u8; 2];
        assert!(decode_into("abcdef", &mut out).is_err());
        assert!(decode_into("abcd", &mut out).is_ok());
        assert_eq!(out, [0xab, 0xcd]);
    }
}
