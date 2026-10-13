//! AES-256-GCM keys derived from the PRISM TLS exporter.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use prism_core::PrismExporter;
use thiserror::Error;

use crate::frame::{BoltFrame, FrameError, WireLayout, MAX_PLAINTEXT_CAP};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoltDirection {
    /// Client → server (upload from client).
    Up,
    /// Server → client (download to client).
    Down,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("hkdf: {0}")]
    Hkdf(String),
    #[error("aead")]
    Aead,
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
}

#[derive(Clone)]
pub struct BoltCipher {
    tx: Aes256Gcm,
    rx: Aes256Gcm,
    role_up: BoltDirection,
}

impl BoltCipher {
    pub fn from_exporter(exporter: &PrismExporter, role_up: BoltDirection) -> Result<Self, CryptoError> {
        let up = exporter.bolt_up_key().map_err(|e| CryptoError::Hkdf(e.to_string()))?;
        let dn = exporter.bolt_dn_key().map_err(|e| CryptoError::Hkdf(e.to_string()))?;
        let (tx_raw, rx_raw) = match role_up {
            BoltDirection::Up => (up, dn),
            BoltDirection::Down => (dn, up),
        };
        Ok(Self {
            tx: Aes256Gcm::new_from_slice(&tx_raw).map_err(|_| CryptoError::Aead)?,
            rx: Aes256Gcm::new_from_slice(&rx_raw).map_err(|_| CryptoError::Aead)?,
            role_up,
        })
    }

    pub fn seal_frame(
        &self,
        frame: &BoltFrame,
        lane: u8,
        layout: WireLayout,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut pt = [0u8; MAX_PLAINTEXT_CAP];
        frame.encode_plaintext(layout, &mut pt)?;
        let dir = match self.role_up {
            BoltDirection::Up => 0u8,
            BoltDirection::Down => 1u8,
        };
        let nonce = BoltFrame::nonce_prefix(frame.seq, lane, dir);
        let ct = self
            .tx
            .encrypt(Nonce::from_slice(&nonce), &pt[..layout.max_plaintext])
            .map_err(|_| CryptoError::Aead)?;
        BoltFrame::assemble_wire(layout, &nonce, &ct, out)?;
        Ok(())
    }

    pub fn open_wire(&self, wire: &[u8]) -> Result<BoltFrame, CryptoError> {
        let layout = WireLayout::new(wire.len())?;
        let nonce = *BoltFrame::wire_nonce(layout, wire)?;
        let ct = BoltFrame::wire_ciphertext(layout, wire)?;
        let pt = self
            .rx
            .decrypt(Nonce::from_slice(&nonce), ct)
            .map_err(|_| CryptoError::Aead)?;
        let mut buf = [0u8; MAX_PLAINTEXT_CAP];
        let n = pt.len().min(layout.max_plaintext);
        buf[..n].copy_from_slice(&pt[..n]);
        Ok(BoltFrame::decode_plaintext(layout, &buf)?)
    }

    pub fn role_up(&self) -> BoltDirection {
        self.role_up
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::WIRE_SIZE;
    use prism_core::EXPORTER_LEN;

    #[test]
    fn client_server_symmetry() {
        let layout = WireLayout::new(WIRE_SIZE).unwrap();
        let exp = PrismExporter::from_raw([7u8; EXPORTER_LEN]);
        let client = BoltCipher::from_exporter(&exp, BoltDirection::Up).unwrap();
        let server = BoltCipher::from_exporter(&exp, BoltDirection::Down).unwrap();
        let frame = BoltFrame::bulk(1, vec![vec![9, 9, 9]]);
        let mut wire = vec![0u8; layout.wire_size];
        client.seal_frame(&frame, 0, layout, &mut wire).unwrap();
        let opened = server.open_wire(&wire).unwrap();
        assert_eq!(opened.seq, 1);
        assert_eq!(opened.chunks[0], vec![9, 9, 9]);
    }
}
