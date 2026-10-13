#!/usr/bin/env python3
"""Sample a `CaptureSummary` JSON from a CDN traffic profile.

Produces the same JSON shape as `summarize_capture.py` (64-bin size histogram,
32-bin IAT histogram, hex payload sample) by drawing samples from a profile.
Used to generate hermetic, representative fixtures for the `prism-eval`
statistical gate in CI, where live bulk captures are not available.

The built-in buckets mirror `prism_morph::CdnProfile::synthetic_chrome()`.

Usage:
    python sample_profile.py <up|down> [n_samples] [seed] > summary.json
"""
import json
import os
import random
import sys

SIZE_BINS, SIZE_LO, SIZE_HI = 64, 200.0, 1450.0
IAT_BINS, IAT_LO, IAT_HI = 32, 0.5, 500.0

# (lo, hi, weight, sigma) mirroring synthetic_chrome().
SIZE_BUCKETS = [
    (200.0, 400.0, 0.10, 40.0),
    (400.0, 800.0, 0.15, 60.0),
    (800.0, 1200.0, 0.25, 80.0),
    (1200.0, 1452.0, 0.50, 30.0),
]
IAT_BUCKETS = [
    (0.5, 2.0, 0.50, 0.3),
    (2.0, 10.0, 0.30, 2.0),
    (10.0, 50.0, 0.15, 8.0),
    (50.0, 500.0, 0.05, 50.0),
]


def bucket_idx(value, lo, hi, n):
    if value <= lo:
        return 0
    if value >= hi:
        return n - 1
    return int((value - lo) / (hi - lo) * n)


def sample_value(buckets, rng):
    weights = [b[2] for b in buckets]
    lo, hi, _, sigma = rng.choices(buckets, weights=weights, k=1)[0]
    mid = (lo + hi) / 2.0
    return mid + rng.gauss(0.0, sigma)


# The morph engine clamps every target size to [200, mtu-48]. To compare the
# baseline against a real PRISM capture (which is subject to that clamp), the
# sampler applies the same clamp. Default mtu mirrors prism-quic live MAX_DGRAM.
SIZE_CLAMP_LO = 200.0
DEFAULT_MTU = 1452
SIZE_CLAMP_HI = DEFAULT_MTU - 48  # = 1404


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sample_profile.py <up|down> [n] [seed] [mtu]", file=sys.stderr)
        return 2
    direction = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    mtu = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_MTU
    clamp_hi = mtu - 48
    rng = random.Random(seed)

    size_hist = [0] * SIZE_BINS
    iat_hist = [0] * IAT_BINS
    for _ in range(n):
        sz = sample_value(SIZE_BUCKETS, rng)
        sz = min(max(sz, SIZE_CLAMP_LO), clamp_hi)
        size_hist[bucket_idx(sz, SIZE_LO, SIZE_HI, SIZE_BINS)] += 1
        iat = sample_value(IAT_BUCKETS, rng)
        iat_hist[bucket_idx(iat, IAT_LO, IAT_HI, IAT_BINS)] += 1

    # QUIC payloads are AEAD ciphertext (~8 bits/byte); model with random bytes.
    payload = os.urandom(4096).hex()

    summary = {
        "size_hist": size_hist,
        "iat_hist": iat_hist,
        "payload_sample": payload,
        "direction": direction,
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
