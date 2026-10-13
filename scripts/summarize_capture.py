#!/usr/bin/env python3
"""Summarize a pcapng capture into the `CaptureSummary` JSON consumed by
`prism-eval`.

Produces datagram-size and inter-arrival-time histograms plus a real payload
sample (on-wire UDP bytes) for entropy estimation. Bucket layouts MUST match
across the Chrome baseline and the PRISM capture for the KL divergence to be
meaningful.

The tshark binary is resolved from (in order): the PRISM_TSHARK environment
variable, a `tshark` on PATH, or the default Windows install path.

Usage: summarize_capture.py <capture.pcapng> <up|down>
"""
import json
import os
import shutil
import subprocess
import sys

# Size buckets: 200..1450 bytes in 64 bins (spec §4.2 size_histogram[64]).
SIZE_BINS = 64
SIZE_LO, SIZE_HI = 200.0, 1450.0
# IAT buckets: 0.5..500 ms in 32 bins (spec iat_histogram[32]).
IAT_BINS = 32
IAT_LO, IAT_HI = 0.5, 500.0

# Skip the first few datagrams (handshake) when sampling payload entropy so the
# sample reflects steady-state 1-RTT ciphertext, and cap the sample size.
PAYLOAD_SKIP = 4
PAYLOAD_CAP = 8192


def resolve_tshark() -> str:
    env = os.environ.get("PRISM_TSHARK")
    if env and os.path.exists(env):
        return env
    found = shutil.which("tshark")
    if found:
        return found
    default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(default):
        return default
    return "tshark"  # last resort; will error if missing


def bucket(value: float, lo: float, hi: float, n: int) -> int:
    if value <= lo:
        return 0
    if value >= hi:
        return n - 1
    return int((value - lo) / (hi - lo) * n)


def tshark_rows(tshark: str, pcap: str):
    """Yield (time_epoch, udp_length, udp_payload_hex, is_long_header) per QUIC
    packet. `is_long_header` is True for Initial/Handshake/0-RTT packets, whose
    payload is structured (TLS records) rather than 1-RTT AEAD ciphertext."""
    out = subprocess.check_output(
        [tshark, "-r", pcap, "-Y", "quic", "-T", "fields",
         "-e", "frame.time_epoch", "-e", "udp.length", "-e", "udp.payload",
         "-e", "quic.long.packet_type"],
        text=True,
    )
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[1]:
            continue
        try:
            t = float(parts[0])
            length = int(parts[1])
        except ValueError:
            continue
        payload = parts[2].replace(":", "").strip() if len(parts) > 2 else ""
        is_long = bool(parts[3].strip()) if len(parts) > 3 else False
        yield t, length, payload, is_long


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: summarize_capture.py <capture.pcapng> <up|down>", file=sys.stderr)
        return 2
    pcap, direction = sys.argv[1], sys.argv[2]
    tshark = resolve_tshark()

    size_hist = [0] * SIZE_BINS
    iat_hist = [0] * IAT_BINS
    last_t = None
    payload_hex_parts = []
    payload_bytes = 0
    # Fallback sample from long-header packets if no 1-RTT packets are present
    # (e.g. a handshake-only capture), so entropy is still reported.
    fallback_hex_parts = []
    fallback_bytes = 0
    idx = 0

    for t, length, payload, is_long in tshark_rows(tshark, pcap):
        # udp.length includes the 8-byte UDP header; the morph engine targets
        # the QUIC datagram size (the UDP payload), so subtract the header to
        # compare like-for-like with the CdnProfile / sample_profile baseline.
        qsize = max(0.0, float(length) - 8.0)
        size_hist[bucket(qsize, SIZE_LO, SIZE_HI, SIZE_BINS)] += 1
        if last_t is not None:
            iat_ms = (t - last_t) * 1000.0
            iat_hist[bucket(iat_ms, IAT_LO, IAT_HI, IAT_BINS)] += 1
        last_t = t

        if payload:
            if not is_long and payload_bytes < PAYLOAD_CAP:
                # 1-RTT short-header packet: pure AEAD ciphertext.
                take = min(len(payload), (PAYLOAD_CAP - payload_bytes) * 2)
                payload_hex_parts.append(payload[:take])
                payload_bytes += take // 2
            elif idx >= PAYLOAD_SKIP and fallback_bytes < PAYLOAD_CAP:
                take = min(len(payload), (PAYLOAD_CAP - fallback_bytes) * 2)
                fallback_hex_parts.append(payload[:take])
                fallback_bytes += take // 2
        idx += 1

    if not payload_hex_parts:
        payload_hex_parts = fallback_hex_parts

    summary = {
        "size_hist": size_hist,
        "iat_hist": iat_hist,
        "payload_sample": "".join(payload_hex_parts),
        "direction": direction,
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
