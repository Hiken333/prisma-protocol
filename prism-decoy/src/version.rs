//! QUIC Version Negotiation packet construction (RFC 9000 §17.2.1).
//!
//! When a probe sends an unsupported QUIC version, the server replies with a VN
//! packet advertising the same version list a real CDN edge would — never a
//! PRISM-specific signal.

/// Build a Version Negotiation packet.
///
/// Per RFC 9000, the server echoes the connection IDs with roles swapped: the VN
/// packet's DCID is the client's SCID and its SCID is the client's DCID.
/// `versions` is the supported-version list to advertise (each a 32-bit value).
pub fn version_negotiation(client_dcid: &[u8], client_scid: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(7 + client_dcid.len() + client_scid.len() + versions.len() * 4);

    // First byte: long-header form (0x80). The remaining bits are unused for VN
    // and conventionally randomized; we set a fixed-bit-style 0xC0 like real impls.
    pkt.push(0xC0);

    // Version = 0x00000000 signals Version Negotiation.
    pkt.extend_from_slice(&0u32.to_be_bytes());

    // DCID = client's SCID.
    pkt.push(client_scid.len() as u8);
    pkt.extend_from_slice(client_scid);

    // SCID = client's DCID.
    pkt.push(client_dcid.len() as u8);
    pkt.extend_from_slice(client_dcid);

    // Supported versions.
    for v in versions {
        pkt.extend_from_slice(&v.to_be_bytes());
    }
    pkt
}

/// A plausible CDN version list: QUICv1 plus a GREASE version (Chrome includes
/// a reserved `0x?a?a?a?a` GREASE version).
pub fn default_versions() -> Vec<u32> {
    vec![0x0000_0001, 0x1a2a_3a4a]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vn_swaps_connection_ids() {
        let dcid = [1u8, 2, 3, 4];
        let scid = [9u8, 8, 7];
        let pkt = version_negotiation(&dcid, &scid, &[0x0000_0001]);
        assert_eq!(pkt[0] & 0x80, 0x80); // long header
        assert_eq!(&pkt[1..5], &[0, 0, 0, 0]); // version 0 = VN
        // DCID = client SCID.
        assert_eq!(pkt[5] as usize, scid.len());
        assert_eq!(&pkt[6..6 + scid.len()], &scid);
        // SCID = client DCID.
        let off = 6 + scid.len();
        assert_eq!(pkt[off] as usize, dcid.len());
        assert_eq!(&pkt[off + 1..off + 1 + dcid.len()], &dcid);
    }
}
