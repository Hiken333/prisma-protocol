//! Minimal TLS 1.3 ClientHello parser for the fields PRISM needs.
//!
//! Operates on the reassembled, decrypted TLS handshake bytes (the QUIC backend
//! is responsible for QUIC Initial decryption and CRYPTO-frame reassembly).
//! Only the X25519 `key_share` entry, the GREASE auth extension and the
//! ClientHello random are extracted — everything else is skipped.

use crate::client_hello::{grease_perf_from_wire, GREASE_AUTH_EXT};
use crate::error::AuthError;

const HS_CLIENT_HELLO: u8 = 0x01;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;

/// The subset of ClientHello fields PRISM inspects.
#[derive(Clone, Debug)]
pub struct ClientHelloView {
    pub random: [u8; 32],
    /// X25519 ephemeral public key from `key_share`, if present.
    pub x25519_key_share: Option<[u8; 32]>,
    /// Value of GREASE extension 0x0A0A (auth tag, optional perf cap byte), if present.
    pub auth_tag: Option<Vec<u8>>,
    /// Client requested perf mode via trailing GREASE `0x0A0A` capability byte.
    pub client_perf: bool,
}

impl ClientHelloView {
    pub fn x25519_keyshare(&self) -> Option<[u8; 32]> {
        self.x25519_key_share
    }
    pub fn grease_auth(&self) -> Option<&[u8]> {
        self.auth_tag.as_deref()
    }
}

/// A tiny big-endian cursor with bounds checks.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn u8(&mut self) -> Result<u8, AuthError> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Result<u16, AuthError> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Result<u32, AuthError> {
        self.take(3).map(|s| u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], AuthError> {
        if self.remaining() < n {
            return Err(AuthError::Parse(format!(
                "unexpected end of ClientHello (need {n}, have {})",
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    /// Read a length-prefixed vector with an `len_bytes`-wide length field.
    fn vec(&mut self, len_bytes: usize) -> Result<&'a [u8], AuthError> {
        let len = match len_bytes {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            3 => self.u24()? as usize,
            _ => unreachable!(),
        };
        self.take(len)
    }
}

/// Parse a TLS handshake `ClientHello` message.
pub fn parse_client_hello(handshake: &[u8]) -> Result<ClientHelloView, AuthError> {
    let mut r = Reader::new(handshake);

    if r.u8()? != HS_CLIENT_HELLO {
        return Err(AuthError::Parse("not a ClientHello handshake message".into()));
    }
    let _len = r.u24()?;
    let _legacy_version = r.u16()?;

    let random: [u8; 32] = r.take(32)?.try_into().unwrap();
    let _session_id = r.vec(1)?;
    let _cipher_suites = r.vec(2)?;
    let _compression = r.vec(1)?;

    // Extensions.
    let ext_block = r.vec(2)?;
    let mut er = Reader::new(ext_block);

    let mut x25519_key_share = None;
    let mut auth_tag = None;
    let mut client_perf = false;

    while er.remaining() >= 4 {
        let ext_type = er.u16()?;
        let ext_data = er.vec(2)?;
        match ext_type {
            EXT_KEY_SHARE => {
                x25519_key_share = parse_key_share(ext_data)?;
            }
            GREASE_AUTH_EXT => {
                client_perf = grease_perf_from_wire(ext_data);
                auth_tag = Some(ext_data.to_vec());
            }
            _ => {}
        }
    }

    Ok(ClientHelloView {
        random,
        x25519_key_share,
        auth_tag,
        client_perf,
    })
}

/// Extract the X25519 entry from a `key_share` extension body.
fn parse_key_share(ext_data: &[u8]) -> Result<Option<[u8; 32]>, AuthError> {
    let mut r = Reader::new(ext_data);
    let shares = r.vec(2)?; // KeyShareClientHello.client_shares<0..2^16-1>
    let mut sr = Reader::new(shares);
    while sr.remaining() >= 4 {
        let group = sr.u16()?;
        let key_exchange = sr.vec(2)?;
        if group == GROUP_X25519 {
            if key_exchange.len() != 32 {
                return Err(AuthError::Parse("X25519 key_share is not 32 bytes".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(key_exchange);
            return Ok(Some(k));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello carrying an X25519 key_share and the GREASE tag.
    fn synth_client_hello(x25519: &[u8; 32], tag: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        // key_share extension.
        let mut ks_body = Vec::new();
        let mut entries = Vec::new();
        entries.extend_from_slice(&GROUP_X25519.to_be_bytes());
        entries.extend_from_slice(&(32u16).to_be_bytes());
        entries.extend_from_slice(x25519);
        ks_body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        ks_body.extend_from_slice(&entries);
        ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        ext.extend_from_slice(&(ks_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&ks_body);
        // GREASE auth extension.
        ext.extend_from_slice(&GREASE_AUTH_EXT.to_be_bytes());
        ext.extend_from_slice(&(tag.len() as u16).to_be_bytes());
        ext.extend_from_slice(tag);

        let mut body = Vec::new();
        body.extend_from_slice(&(0x0303u16).to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&(2u16).to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods len
        body.push(0); // null
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut msg = Vec::new();
        msg.push(HS_CLIENT_HELLO);
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn parses_key_share_and_auth_tag() {
        let x = [9u8; 32];
        let tag = [0xABu8; 32];
        let ch = synth_client_hello(&x, &tag);
        let view = parse_client_hello(&ch).unwrap();
        assert_eq!(view.x25519_keyshare(), Some(x));
        assert_eq!(view.grease_auth(), Some(tag.as_slice()));
        assert!(!view.client_perf);
    }

    #[test]
    fn parses_perf_capability_byte() {
        let x = [9u8; 32];
        let mut tag = vec![0xABu8; 32];
        tag.push(crate::client_hello::GREASE_PERF_CAP);
        let ch = synth_client_hello(&x, &tag);
        let view = parse_client_hello(&ch).unwrap();
        assert!(view.client_perf);
        assert_eq!(view.grease_auth(), Some(tag.as_slice()));
    }

    #[test]
    fn rejects_non_clienthello() {
        let err = parse_client_hello(&[0x02, 0, 0, 0]);
        assert!(err.is_err());
    }
}
