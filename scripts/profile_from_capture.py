#!/usr/bin/env python3
"""Derive a PRISM `CdnProfile` JSON from a capture summary.

Takes the output of `summarize_capture.py` (64-bin size histogram over
200..1450 bytes, 32-bin IAT histogram over 0.5..500 ms) for a real decoy-origin
HTTP/3 session (e.g. Chrome -> www.google.com) and condenses it into the bucket
layout that `prism_morph::CdnProfile` deserializes. The PRISM client/server then
load it via the PRISM_CDN_PROFILE environment variable so the morph engine
shapes datagram sizes / inter-arrival times to match the real CDN.

Usage:
    python profile_from_capture.py <chrome_summary.json> > chrome_profile.json
"""
import json
import sys

# Must match summarize_capture.py.
SIZE_BINS, SIZE_LO, SIZE_HI = 64, 200.0, 1450.0
IAT_BINS, IAT_LO, IAT_HI = 32, 0.5, 500.0

# CdnProfile bucket edges (coarser than the measurement bins). Each output
# bucket aggregates the measured mass in [lo, hi); sigma is half the width so a
# Normal centred on the midpoint stays within the bucket.
SIZE_EDGES = [200.0, 400.0, 800.0, 1200.0, 1452.0]
IAT_EDGES = [0.5, 2.0, 10.0, 50.0, 500.0]


def bin_edges(lo, hi, n):
    step = (hi - lo) / n
    return [lo + i * step for i in range(n + 1)]


def aggregate(hist, meas_lo, meas_hi, meas_n, out_edges):
    """Sum measured histogram mass into coarse [lo,hi) output buckets."""
    edges = bin_edges(meas_lo, meas_hi, meas_n)
    buckets = []
    for i in range(len(out_edges) - 1):
        lo, hi = out_edges[i], out_edges[i + 1]
        weight = 0
        for b in range(meas_n):
            mid = (edges[b] + edges[b + 1]) / 2.0
            if lo <= mid < hi or (i == len(out_edges) - 2 and mid >= lo):
                weight += hist[b] if b < len(hist) else 0
        buckets.append({"lo": lo, "hi": hi, "weight": float(weight),
                         "sigma": max((hi - lo) / 2.0, 1.0)})
    total = sum(b["weight"] for b in buckets)
    if total > 0:
        for b in buckets:
            b["weight"] = round(b["weight"] / total, 6)
    else:
        # Degenerate capture: fall back to uniform mass so the profile is valid.
        for b in buckets:
            b["weight"] = round(1.0 / len(buckets), 6)
    return buckets


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: profile_from_capture.py <summary.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        summary = json.load(f)

    size_buckets = aggregate(summary.get("size_hist", []),
                             SIZE_LO, SIZE_HI, SIZE_BINS, SIZE_EDGES)
    iat_buckets = aggregate(summary.get("iat_hist", []),
                            IAT_LO, IAT_HI, IAT_BINS, IAT_EDGES)

    profile = {
        "size_hist": {"buckets": size_buckets},
        "iat_hist": {"buckets": iat_buckets},
        # Burst structure cannot be inferred from a flat histogram; use a
        # conservative single-burst default. Operators may hand-tune.
        "bursts": [
            {"packets": 8, "inter_burst_pause_ms": 15.0, "weight": 0.5},
            {"packets": 24, "inter_burst_pause_ms": 40.0, "weight": 0.3},
            {"packets": 64, "inter_burst_pause_ms": 120.0, "weight": 0.2},
        ],
        "direction_ratio": 0.12,
    }
    print(json.dumps(profile, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
