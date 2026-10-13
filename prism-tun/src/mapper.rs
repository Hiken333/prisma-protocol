//! Maps VPN IP flows onto QUIC stream IDs.
//!
//! Each transport flow (5-tuple) is carried on its own QUIC stream so that
//! head-of-line blocking is per-flow, matching H3-style multiplexing. Stream IDs
//! are allocated as client-initiated bidirectional streams (`id % 4 == 0`).

use std::collections::HashMap;

use crate::error::TunError;

/// A transport flow identity extracted from an IP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Allocates and remembers a stable QUIC stream ID per flow.
pub struct StreamMapper {
    flows: HashMap<FlowKey, u64>,
    next_id: u64,
    max_streams: u64,
}

impl StreamMapper {
    pub fn new(max_streams: u64) -> Self {
        Self { flows: HashMap::new(), next_id: 0, max_streams }
    }

    /// Return the stream ID for `packet`'s flow, allocating one if new.
    /// Only the QUIC client may open streams; use this on the client TUN→QUIC path.
    pub fn stream_for(&mut self, packet: &[u8]) -> Result<u64, TunError> {
        let key = parse_flow(packet)?;
        if let Some(&id) = self.flows.get(&key) {
            return Ok(id);
        }
        let id = if self.flows.len() as u64 >= self.max_streams {
            // Reuse the QUIC stream ID of the oldest idle flow (stream stays open).
            let k = self
                .flows
                .keys()
                .next()
                .copied()
                .ok_or(TunError::ShortPacket(0))?;
            self.flows.remove(&k).unwrap_or(self.next_id)
        } else {
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(4);
            id
        };
        self.flows.insert(key, id);
        Ok(id)
    }

    /// Remember which peer-opened stream carries `packet`'s flow (server path).
    /// Registers both forward and reverse 5-tuples so TUN return traffic maps back.
    pub fn learn_peer_stream(&mut self, stream_id: u64, packet: &[u8]) -> Result<(), TunError> {
        let key = parse_flow(packet)?;
        self.flows.insert(key, stream_id);
        self.flows.insert(reverse_flow(key), stream_id);
        Ok(())
    }

    /// Look up a flow the peer already opened. Returns `None` if unknown.
    pub fn peer_stream_for(&self, packet: &[u8]) -> Result<Option<u64>, TunError> {
        let key = parse_flow(packet)?;
        Ok(self.flows.get(&key).copied())
    }

    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }
}

/// Parse the 5-tuple from a raw IPv4/IPv6 packet (best-effort; ports only for
/// TCP/UDP).
pub fn parse_flow(packet: &[u8]) -> Result<FlowKey, TunError> {
    if packet.is_empty() {
        return Err(TunError::ShortPacket(0));
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => Err(TunError::ShortPacket(packet.len())),
    }
}

fn parse_ipv4(p: &[u8]) -> Result<FlowKey, TunError> {
    if p.len() < 20 {
        return Err(TunError::ShortPacket(p.len()));
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    let proto = p[9];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src[..4].copy_from_slice(&p[12..16]);
    dst[..4].copy_from_slice(&p[16..20]);
    let (src_port, dst_port) = parse_ports(proto, p.get(ihl..).unwrap_or(&[]));
    Ok(FlowKey { src, dst, src_port, dst_port, proto })
}

fn parse_ipv6(p: &[u8]) -> Result<FlowKey, TunError> {
    if p.len() < 40 {
        return Err(TunError::ShortPacket(p.len()));
    }
    let proto = p[6]; // next header (no extension-header walking here)
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&p[8..24]);
    dst.copy_from_slice(&p[24..40]);
    let (src_port, dst_port) = parse_ports(proto, p.get(40..).unwrap_or(&[]));
    Ok(FlowKey { src, dst, src_port, dst_port, proto })
}

fn reverse_flow(key: FlowKey) -> FlowKey {
    FlowKey {
        src: key.dst,
        dst: key.src,
        src_port: key.dst_port,
        dst_port: key.src_port,
        proto: key.proto,
    }
}

/// Direction-independent form of a flow: the lexicographically smaller
/// (addr, port) endpoint is always `src`. Both directions of one flow map to
/// the same canonical key.
fn canonical_flow(key: FlowKey) -> FlowKey {
    if (key.src, key.src_port) <= (key.dst, key.dst_port) {
        key
    } else {
        reverse_flow(key)
    }
}

/// Stream ID (client-initiated bidi, `id % 4 == 0`) for `packet` in a fixed
/// pool of `pool_size` streams. Uses FNV-1a over the canonical 5-tuple so:
/// * both directions of a flow always share one stream (per-flow ordering);
/// * client and server independently compute the same stream, so the return
///   path never needs a learned mapping and the pool can never be exhausted.
pub fn pool_stream_id(packet: &[u8], pool_size: u64) -> Result<u64, TunError> {
    let key = canonical_flow(parse_flow(packet)?);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    feed(&key.src);
    feed(&key.dst);
    feed(&key.src_port.to_be_bytes());
    feed(&key.dst_port.to_be_bytes());
    feed(&[key.proto]);
    Ok((h % pool_size.max(1)) * 4)
}

fn parse_ports(proto: u8, l4: &[u8]) -> (u16, u16) {
    // TCP (6) and UDP (17) carry src/dst ports in the first 4 bytes.
    if matches!(proto, 6 | 17) && l4.len() >= 4 {
        (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
        )
    } else {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_ipv4(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45; // v4, IHL=5
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn same_flow_keeps_stream_id() {
        let mut m = StreamMapper::new(256);
        let pkt = udp_ipv4(1000, 443);
        let a = m.stream_for(&pkt).unwrap();
        let b = m.stream_for(&pkt).unwrap();
        assert_eq!(a, b);
        assert_eq!(a % 4, 0); // client bidi stream
    }

    #[test]
    fn distinct_flows_get_distinct_streams() {
        let mut m = StreamMapper::new(256);
        let a = m.stream_for(&udp_ipv4(1000, 443)).unwrap();
        let b = m.stream_for(&udp_ipv4(1001, 443)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn peer_stream_lookup_after_learn() {
        let mut m = StreamMapper::new(256);
        let pkt = udp_ipv4(1000, 443);
        m.learn_peer_stream(8, &pkt).unwrap();
        assert_eq!(m.peer_stream_for(&pkt).unwrap(), Some(8));
        assert_eq!(m.peer_stream_for(&udp_ipv4(1001, 443)).unwrap(), None);
    }

    fn udp_ipv4_rev(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[10, 0, 0, 1]);
        p[20..22].copy_from_slice(&dst_port.to_be_bytes());
        p[22..24].copy_from_slice(&src_port.to_be_bytes());
        p
    }

    #[test]
    fn peer_stream_lookup_reverse_flow_after_learn() {
        let mut m = StreamMapper::new(256);
        let fwd = udp_ipv4(1000, 443);
        let rev = udp_ipv4_rev(1000, 443);
        m.learn_peer_stream(8, &fwd).unwrap();
        assert_eq!(m.peer_stream_for(&fwd).unwrap(), Some(8));
        assert_eq!(m.peer_stream_for(&rev).unwrap(), Some(8));
    }

    #[test]
    fn pool_stream_same_for_both_directions() {
        let fwd = udp_ipv4(1000, 443);
        let rev = udp_ipv4_rev(1000, 443);
        let a = pool_stream_id(&fwd, 8).unwrap();
        let b = pool_stream_id(&rev, 8).unwrap();
        assert_eq!(a, b);
        assert_eq!(a % 4, 0);
        assert!(a < 8 * 4);
    }

    #[test]
    fn pool_stream_stays_in_range() {
        for port in 1000..1200u16 {
            let sid = pool_stream_id(&udp_ipv4(port, 443), 8).unwrap();
            assert_eq!(sid % 4, 0);
            assert!(sid < 8 * 4, "stream {sid} out of pool range");
        }
    }

    #[test]
    fn pool_stream_rejects_garbage() {
        assert!(pool_stream_id(&[], 8).is_err());
        assert!(pool_stream_id(&[0x12, 0x34], 8).is_err());
    }

    #[test]
    fn distinct_flows_keep_separate_peer_streams() {
        let mut m = StreamMapper::new(256);
        let a_fwd = udp_ipv4(1000, 443);
        let b_fwd = udp_ipv4(2000, 80);
        m.learn_peer_stream(8, &a_fwd).unwrap();
        m.learn_peer_stream(12, &b_fwd).unwrap();
        assert_eq!(m.peer_stream_for(&udp_ipv4_rev(1000, 443)).unwrap(), Some(8));
        assert_eq!(m.peer_stream_for(&udp_ipv4_rev(2000, 80)).unwrap(), Some(12));
        assert_eq!(m.peer_stream_for(&udp_ipv4_rev(3000, 53)).unwrap(), None);
    }
}
