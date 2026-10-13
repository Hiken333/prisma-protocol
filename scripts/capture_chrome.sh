#!/usr/bin/env bash
# Capture a reference Chrome HTTP/3 session to the decoy origin and a PRISM
# session to the same origin, then summarize both for the indistinguishability
# gate (prism-eval) and extract JA4 fingerprints.
#
# Requirements: google-chrome, tshark (>= 4.x with QUIC dissector), python3,
# and the `ja4` extraction tooling (https://github.com/FoxIO-LLC/ja4).
#
# Usage: scripts/capture_chrome.sh <decoy_origin_host> <out_dir>
set -euo pipefail

DECOY="${1:?usage: capture_chrome.sh <decoy_host> <out_dir>}"
OUT="${2:?usage: capture_chrome.sh <decoy_host> <out_dir>}"
mkdir -p "$OUT"

IFACE="${PRISM_CAPTURE_IFACE:-any}"
DURATION="${PRISM_CAPTURE_SECS:-30}"

echo "[*] Capturing Chrome HTTP/3 to ${DECOY} on ${IFACE} for ${DURATION}s"
tshark -i "$IFACE" -f "udp port 443 and host ${DECOY}" -a "duration:${DURATION}" \
  -w "${OUT}/chrome_124.pcapng" &
TSHARK_PID=$!

# Force QUIC/HTTP3 to the decoy and load it a few times to generate traffic.
google-chrome --headless=new --disable-gpu \
  --enable-quic --origin-to-force-quic-on="${DECOY}:443" \
  --user-data-dir="$(mktemp -d)" "https://${DECOY}/" >/dev/null 2>&1 || true
wait "$TSHARK_PID" || true

echo "[*] Extracting JA4 from the Chrome ClientHello"
# ja4 tooling emits one fingerprint per handshake; we keep the first.
ja4 "${OUT}/chrome_124.pcapng" | head -n1 > "${OUT}/chrome_124.ja4"

echo "[*] Summarizing size/IAT histograms for prism-eval"
python3 "$(dirname "$0")/summarize_capture.py" \
  "${OUT}/chrome_124.pcapng" "down" > "${OUT}/chrome_baseline.json"

echo "[*] Done. Now capture a PRISM session to the same decoy and run:"
echo "    python3 scripts/summarize_capture.py prism.pcapng down > testdata/prism_capture.json"
echo "    ja4 prism.pcapng | head -n1 > testdata/prism.ja4"
echo "    cargo run -p prism-eval -- testdata/chrome_baseline.json testdata/prism_capture.json"
