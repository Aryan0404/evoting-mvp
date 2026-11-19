#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Phone timings for the paper (Table 8): the voter-side cryptography — a
#  2048-bit Paillier ballot, its ballot-validity proof, the ECDSA P-256 device
#  key and signature, and the receipt check — timed on the phone itself.
#
#  Easiest: open https://aryan0404.github.io/evoting-mvp/ on the phone (no computer needed).
#
#  ./run_phone_benchmark.sh      serves the same page (docs/index.html) on the
#                                local network instead; open the printed address
#
#  Works on iPhone (Safari) and Android (Chrome). The page needs no server-side
#  code and no internet once loaded. The phone and this computer must be on the
#  same Wi-Fi.
# ─────────────────────────────────────────────────────────────────────────────
set -u
cd "$(dirname "$0")/docs" || exit 1
PORT="${PORT:-8090}"
PAGE=""

lan_ips() {
  if command -v ipconfig >/dev/null 2>&1; then                 # macOS
    for i in en0 en1 en2 en3 bridge100; do ipconfig getifaddr "$i" 2>/dev/null; done
  else                                                          # Linux
    hostname -I 2>/dev/null | tr ' ' '\n'
  fi | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v -E '^(127|172\.17)\.' | sort -u
}

IPS="$(lan_ips)"
echo
echo "  Phone benchmark — open this on the phone (same Wi-Fi as this computer):"
echo
if [ -n "$IPS" ]; then
  for ip in $IPS; do echo "      http://$ip:$PORT/$PAGE"; done
else
  echo "      http://<this computer's Wi-Fi address>:$PORT/$PAGE"
  echo "      (no Wi-Fi address found — connect to Wi-Fi, or to the phone's hotspot, and rerun)"
fi
echo
echo "  iPhone: Safari.  Android: Chrome.  Tap 'Run benchmark', keep the screen on"
echo "  and the page open for about two minutes, then tap 'Copy results'."
echo "  macOS may ask to allow incoming connections: choose Allow."
echo "  If the page does not load on the phone, the Wi-Fi blocks devices from"
echo "  reaching each other (common on university and office networks): connect"
echo "  this computer to the phone's hotspot and rerun, or use the online page:"
echo "      https://aryan0404.github.io/evoting-mvp/"
echo "  Press Ctrl+C here when the phone has finished."
echo

if command -v python3 >/dev/null 2>&1 && python3 -c 'import http.server' >/dev/null 2>&1; then
  exec python3 -m http.server "$PORT" --bind 0.0.0.0
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  exec docker run --rm -p "$PORT:$PORT" -v "$PWD:/srv:ro" -w /srv python:3.11-slim \
       python -m http.server "$PORT" --bind 0.0.0.0
else
  echo "  Needs Python 3 or a running Docker to serve the page."
  echo "  Use the online page instead: https://aryan0404.github.io/evoting-mvp/"
  echo "  (the same single file as docs/index.html)."
  exit 1
fi
