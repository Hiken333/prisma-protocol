//! Datagram framing for the native UDP transport.
//!
//! Two datagram shapes:
//! * **INIT** (client's first packet): a cleartext Reality handshake carrier.
//! * **Short** (data): a 9-byte header `[0x40][pn: u64 BE]` followed by the AEAD
//!   ciphertext. The packet number doubles as the AEAD nonce input.

use crate::error::{Result, TransportError};

/// Magic prefix for INIT datagrams (native-mode marker).
pub const MAGIC: [u8; 4] = *b"PRZM";
pub const VERSION: u8 = 0x01;

pub const TYPE_INIT: u8 = 0x01;

/// First byte of a short-header (data) datagram.
pub const SHORT_HEADER: u8 = 0x40;
pub const SHORT_HEADER_LEN: usize = 1 + 8;

/// Whether `datagram` looks like a native INIT.
pub fn is_init(datagram: &[u8]) -> bool {
    datagram.len() >= 6 && datagram[0..4] == MAGIC && datagram[5] == TYPE_INIT
}

/// Whether `datagram` looks like a short-header data packet.
pub fn is_short(datagram: &[u8]) -> bool {
    datagram.len() >= SHORT_HEADER_LEN && datagram[0] == SHORT_HEADER
}

/// Write a short-header for packet number `pn` into `out`, returning the offset
/// at which the ciphertext should begin.
pub fn write_short_header(out: &mut [u8], pn: u64) -> usize {
    out[0] = SHORT_HEADER;
    out[1..9].copy_from_slice(&pn.to_be_bytes());
    SHORT_HEADER_LEN
}

/// Parse the packet number from a short-header datagram.
pub fn read_short_header(datagram: &[u8]) -> Result<(u64, &[u8])> {
    if !is_short(datagram) {
        return Err(TransportError::Malformed("not a short-header datagram".into()));
    }
    let mut pn = [0u8; 8];
    pn.copy_from_slice(&datagram[1..9]);
    Ok((u64::from_be_bytes(pn), &datagram[SHORT_HEADER_LEN..]))
}
