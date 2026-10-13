# quiche fork — PRISM integration points

PRISM builds its wire path on `quiche` + BoringSSL because Chrome itself uses
BoringSSL, so the TLS ClientHello fingerprint (cipher suites, extension order,
GREASE layout, `key_share` format) matches Chrome 124 out of the box.

Stock `quiche` does not expose four capabilities PRISM needs. Each is small and
additive. The recommended path is a thin fork; where a fork is rejected, the
listed fallback keeps PRISM functional with reduced fidelity.

The abstraction boundary is [`prism-quic::backend::QuicBackend`](../prism-quic/src/backend.rs);
the real wiring is in [`prism-quic::quiche_backend`](../prism-quic/src/quiche_backend.rs)
behind the `quiche-backend` feature.

## 1. Pluggable congestion control

**Need:** install `BbrPrism` as the connection's controller.

**Fork:** expose a public trait and setter.

```rust
// quiche/src/recovery/congestion/mod.rs
pub trait CongestionControl: Send {
    fn on_packet_sent(&mut self, now: Instant, bytes: usize, pkt: &SentPacket);
    fn on_ack(&mut self, now: Instant, acked: &[Acked], rtt: Duration);
    fn on_loss(&mut self, now: Instant, lost: &[Lost]);
    fn cwnd(&self) -> usize;
    fn pacing_rate(&self) -> u64;
    fn can_send(&self, in_flight: usize) -> bool;
}

// quiche/src/lib.rs (Config)
impl Config {
    pub fn set_custom_congestion_control(&mut self, cc: Box<dyn CongestionControl>);
}
```

`prism-cc::BbrPrism` already implements an identical trait
([`prism-cc::traits`](../prism-cc/src/traits.rs)); only newtype glue is required.

**Fallback (no fork):** run stock quiche with
`Config::set_cc_algorithm(CongestionControlAlgorithm::Bbr2)` and disable internal
pacing (`Config::enable_pacing(false)`). The real cwnd / pacing is then enforced
*above* quiche by [`prism-cc::CcGate`](../prism-cc/src/gate.rs), whose `acquire`
the send loop awaits before each datagram. Lower fidelity (quiche still bounds
its own window) but no fork.

## 2. TLS exporter access

**Need:** derive `prism_exporter = export_keying_material("prism/master", 48)`.

**Fork:** surface BoringSSL's exporter.

```rust
// quiche/src/lib.rs
impl Connection {
    pub fn export_keying_material(
        &self, label: &[u8], context: &[u8], out: &mut [u8],
    ) -> Result<()> {
        self.handshake.ssl().export_keying_material(out, label, Some(context))
            .map_err(|_| Error::TlsFail)
    }
}
```

**Fallback:** none that preserves zero-overhead seeding. If unavailable, derive
the seed from the resumption secret exposed via `NewSessionTicket` instead, at
the cost of a small protocol deviation.

## 3. Frame-level padding to a target size

**Need:** pad a datagram up to the morph target *inside* the AEAD plaintext
(PADDING frame `0x00`) so the encrypted datagram reaches the CDN-profile size
without IP fragmentation.

**Fork:**

```rust
// quiche/src/lib.rs
impl Connection {
    /// Like `send`, but appends PADDING frames so the emitted datagram is at
    /// least `min_size` bytes (capped at the path MTU).
    pub fn send_with_min_size(&mut self, out: &mut [u8], min_size: usize)
        -> Result<(usize, SendInfo)>;
}
```

This hooks the existing packet builder, which already pads Initial packets to
1200 bytes — the change generalizes the target.

**Fallback:** request a coalesced datagram size via `Config::set_max_send_udp_payload_size`
and pad at the UDP layer with a trailing run of bytes. This is observable in
principle (padding sits outside AEAD), so it is a last resort; prefer the fork.

## 4. Explicit PING + PADDING dummy frame

**Need:** entropy regularization injects a dummy frame every ~8 KiB (§4.3).

**Fork:**

```rust
impl Connection {
    pub fn send_ping(&mut self) -> Result<()>; // queue PING (0x01) + PADDING
}
```

**Fallback:** rely on quiche's own ack-eliciting PINGs for keep-alive; entropy
shaping is then weaker but the connection is unaffected.

## 5. JA4 ClientHello parity with Chrome

**Need:** the PRISM client's QUIC ClientHello must produce the *same JA4
fingerprint* as Chrome's HTTP/3 (so DPI / JA4 classifiers cannot separate them).

**Measured target (Chrome 148, `www.google.com` h3):**

```
q13d0311h3_55b375c5d22e_653d80c3fe9d
```

Stock quiche + BoringSSL already matches the **cipher suites** (`1301,1302,1303`
-> JA4_b `55b375c5d22e`) and the **signature_algorithms** list, because BoringSSL
is Chrome's TLS stack. Three gaps remained, all closed in the fork:

| JA4 diff                         | Fix (PRISM fork)                                                        |
| -------------------------------- | ----------------------------------------------------------------------- |
| ALPN `prism` -> `h3`             | [`prism-quic::live`](../prism-quic/src/live.rs) `ALPN = b"h3"`           |
| missing ext `0xfe0d` (ECH GREASE)| `SSL_set_enable_ech_grease(ssl, 1)` in `tls::Handshake::init` (client)   |
| missing ext `0x44cd` (ALPS)      | `SSL_add_application_settings(ssl, "h3", ...)` in `init`; codepoint bumped 0x4469 -> 0x44cd in `tls1.h` |
| missing ext `0x001b` (compress_certificate) | `SSL_CTX_add_cert_compression_alg(ctx, 2 /*brotli*/, None, stub)` in `tls::Context::new` |

These use stock BoringSSL APIs (no C patch beyond the one-line ALPS codepoint in
`include/openssl/tls1.h`, which upstream BoringSSL itself later adopted). After
the change the PRISM ClientHello JA4 is byte-identical to Chrome's:

```
q13d0311h3_55b375c5d22e_653d80c3fe9d   == Chrome 148
```

Verify with `scripts/capture.ps1` + `scripts/extract_ja4.ps1` +
`scripts/ja4_compare.py` (see [`prism/README.md`](../README.md)).

## 6. Known gap: ClientHello size / Initial count

**Status:** documented, intentionally not implemented (low priority).

Chrome 124+ offers the post-quantum hybrid `X25519MLKEM768` (group `0x11ec`).
Its client `key_share` is **1216 bytes** (ML-KEM-768 encapsulation key 1184 ||
X25519 32), which pushes Chrome's QUIC ClientHello **across two Initial
datagrams**. PRISM negotiates plain X25519 (32-byte `key_share`) and its
ClientHello fits in **one Initial**.

| Property | Chrome 148 | PRISM |
| -------- | ---------- | ----- |
| `supported_groups` | `0x11ec` (X25519MLKEM768) first | X25519 only |
| `key_share` size | 1216 + 32 bytes | 32 bytes |
| Client Initial count | 2 | 1 |
| JA4 | `q13d0311h3_55b375c5d22e_653d80c3fe9d` | **same** |

JA4 hashes extension/cipher/sigalg *types*, not `supported_groups` values or
`key_share` contents, so **JA4 parity holds** (see §5). The gap matters only for
passive analysis of ClientHello *length* or Initial-packet *count* — a weaker
signal than JA4, which is what DPI classifiers typically use.

**Why not fixed:** the vendored BoringSSL predates ML-KEM. Closing the gap would
require either (a) porting ML-KEM-768 into BoringSSL (large, high risk), or
(b) injecting a cosmetic `0x11ec` key_share plus multi-Initial classifier
changes on the security-critical Reality path (regression risk to the working
handshake). Both are out of scope; JA4 parity is the primary indistinguishability
target and is already met.

## 7. Representative live traffic for the statistical gate

The demo client's [`run_client_bulk`](../prism-quic/src/live.rs) (`--bulk SECONDS`)
streams morph-shaped datagrams: a tiny app chunk per tick so the **morph target**
(not the payload) sets each datagram's size, one datagram per `morph.delay()` so
inter-arrival tracks the profile. A ~14 s capture yields ~1000 datagrams whose
size distribution and ciphertext entropy (≈7.96 bits/byte, matching Chrome's QUIC
1-RTT) are statistically meaningful. `prism-eval --live` enforces entropy + a
live `size_kl` bound and reports `iat_kl` informationally (Windows' ~15.6 ms timer
floor cannot realize sub-2 ms inter-arrival via real sleeps); the deterministic
[`morph_fidelity`](../prism-morph/tests/morph_fidelity.rs) test is the
authoritative size+IAT proof of the morph algorithm.

## Summary

| Capability                | Fork API                          | Fallback                         |
| ------------------------- | --------------------------------- | -------------------------------- |
| Custom congestion control | `set_custom_congestion_control`   | Bbr2 + external `CcGate`         |
| TLS exporter              | `export_keying_material`          | resumption-secret seed (deviates)|
| Pad to target size        | `send_with_min_size`              | UDP-layer trailing pad (visible) |
| PING dummy frame          | `send_ping`                       | quiche keep-alive PINGs          |
| JA4 ClientHello parity    | ECH GREASE + ALPS(0x44cd) + cert-compression + ALPN h3 | none (fingerprint diverges) |
| ClientHello size parity   | known gap (documented, §6)        | not implemented by design        |

All are wired through `QuicBackend` so switching between fork and fallback
is a backend swap, not a change to PRISM's logic.
