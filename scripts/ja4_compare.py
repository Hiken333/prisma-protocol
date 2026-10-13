#!/usr/bin/env python3
"""Compare two JA4 fingerprints (frozen Chrome baseline vs PRISM capture).

The JA4 string encodes TLS version, cipher-suite set, extension set, ALPN and
signature algorithms. For PRISM to be indistinguishable, the PRISM handshake
must produce the *same* JA4 as the reference Chrome handshake to the same decoy.

Exit code 0 on match, 1 on mismatch (CI gate).
"""
import sys


def load_ja4(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        line = fh.readline().strip()
    # Files may be `<ja4>` or `<src>,<ja4>` depending on the tool; take the JA4.
    return line.split(",")[-1].strip()


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: ja4_compare.py <baseline.ja4> <capture.ja4>", file=sys.stderr)
        return 2

    baseline = load_ja4(sys.argv[1])
    capture = load_ja4(sys.argv[2])

    if baseline == capture:
        print(f"JA4 parity OK: {capture}")
        return 0

    print("JA4 MISMATCH", file=sys.stderr)
    print(f"  baseline: {baseline}", file=sys.stderr)
    print(f"  capture : {capture}", file=sys.stderr)
    # Show the first differing field to speed up debugging.
    for i, (b, c) in enumerate(zip(baseline.split("_"), capture.split("_"))):
        if b != c:
            print(f"  first differing JA4 field #{i}: {b!r} != {c!r}", file=sys.stderr)
            break
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
