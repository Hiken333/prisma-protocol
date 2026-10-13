//! QUIC variable-length integer encoding (RFC 9000 §16).
//!
//! The two most-significant bits of the first byte select the length
//! (1/2/4/8 bytes); the remaining bits carry the value, big-endian.

use crate::error::{Result, TransportError};

/// Append `value` to `out` as a QUIC varint.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        let v = value as u16 | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
    } else if value < (1 << 30) {
        let v = value as u32 | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        let v = value | 0xC000_0000_0000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Number of bytes a varint of `value` will occupy.
pub fn len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Decode a varint from `buf`, returning `(value, bytes_consumed)`.
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf
        .first()
        .ok_or_else(|| TransportError::Malformed("varint: empty".into()))?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(TransportError::Malformed("varint: truncated".into()));
    }
    let mut value = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_lengths() {
        for v in [0u64, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, u64::MAX >> 2] {
            let mut out = Vec::new();
            encode(v, &mut out);
            assert_eq!(out.len(), len(v));
            let (got, n) = decode(&out).unwrap();
            assert_eq!(got, v);
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn truncated_is_error() {
        assert!(decode(&[0x40]).is_err()); // says 2 bytes, only 1 present
    }
}
