#!/bin/sh
set -eu

DATA_DIR="${PRISM_DATA_DIR:-/var/lib/prism}"
CERT="${PRISM_CERT:-$DATA_DIR/cert.pem}"
KEY="${PRISM_KEY:-$DATA_DIR/key.pem}"
DECOY="${PRISM_DECOY:-www.cloudflare.com}"
LISTEN="${PRISM_LISTEN:-0.0.0.0:4433}"
TUN_NAME="${PRISM_TUN_NAME:-prism0}"
TUN_CIDR="${PRISM_TUN_CIDR:-172.19.0.1/30}"
WAN_IFACE="${PRISM_WAN_IFACE:-}"

mkdir -p "$DATA_DIR"

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Generating self-signed cert for decoy=$DECOY ..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" -days 3650 \
    -subj "/CN=$DECOY" \
    -addext "subjectAltName=DNS:$DECOY"
fi

# Enable IPv4 forwarding (required to route client traffic to the WAN).
sysctl -w net.ipv4.ip_forward=1 2>/dev/null \
  || (echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null) \
  || true
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
if [ "$FWD" != "1" ]; then
  echo "ERROR: net.ipv4.ip_forward=$FWD (forwarding disabled)."
  echo "       Client traffic cannot reach the internet (tunnel connects but no internet)."
  echo "       Fix: run the container privileged (compose: privileged: true), or on the VPS host run:"
  echo "         sudo sysctl -w net.ipv4.ip_forward=1"
  echo "         echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-prism.conf"
fi

if [ -z "$WAN_IFACE" ]; then
  WAN_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
fi
if [ -n "$WAN_IFACE" ]; then
  iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
  iptables -C FORWARD -i "$TUN_NAME" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$TUN_NAME" -o "$WAN_IFACE" -j ACCEPT
  iptables -C FORWARD -i "$WAN_IFACE" -o "$TUN_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$WAN_IFACE" -o "$TUN_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT
  # Clamp TCP MSS so connections survive the 1280-byte tunnel MTU (SYN passes but
  # data stalls without this on a smaller path MTU).
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
    || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  echo "NAT MASQUERADE on $WAN_IFACE (FORWARD $TUN_NAME <-> $WAN_IFACE, MSS clamp)"
else
  echo "WARN: could not detect WAN interface; NAT not configured"
fi

ARGS="--listen $LISTEN --decoy $DECOY --cert $CERT --key $KEY --tun --tun-name $TUN_NAME --tun-cidr $TUN_CIDR"

if [ -n "${PRISM_SHADOW_SK:-}" ]; then
  ARGS="$ARGS --shadow-sk $PRISM_SHADOW_SK"
fi

echo "Starting prism-server $ARGS"
exec prism-server $ARGS
