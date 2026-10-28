#!/bin/bash
# Replays a pcap through ipfixprobe, captures the IPFIX export on loopback
# and writes that capture as pcap to stdout (input for flowpipeline's pcapstdin).
# Needs root or CAP_NET_RAW for tcpdump.
set -euo pipefail

INPUT_FILE="${1:?usage: $0 <pcap>}"
IPFIXPROBE="${IPFIXPROBE:-ipfixprobe}"
TCPDUMP="${TCPDUMP:-tcpdump}"
[ -f "$INPUT_FILE" ] || { echo "error: '$INPUT_FILE' not found" >&2; exit 1; }

PLUGIN_ARGS=()
[ -n "${PLUGIN_DIR:-}" ] && PLUGIN_ARGS=(-L "$PLUGIN_DIR")

WORK_DIR=$(mktemp -d)
SINK_PID=""
TCPDUMP_PID=""
cleanup() {
  kill $SINK_PID $TCPDUMP_PID 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# The sink binds a free port chosen by the kernel, so parallel runs never
# collide. It must keep the port open: otherwise ICMP port-unreachable makes
# the exporter's connected UDP socket fail with ECONNREFUSED.
exec {SINK_FD}< <(python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1], flush=True)
while True:
    s.recv(65535)
')
SINK_PID=$!
read -r PORT <&"$SINK_FD"

# -U writes every packet immediately so nothing is lost when tcpdump is killed.
"$TCPDUMP" -i lo -U -w "$WORK_DIR/ipfix.pcap" "udp port $PORT" 2> "$WORK_DIR/tcpdump.log" &
TCPDUMP_PID=$!
for _ in $(seq 100); do
  grep -q "listening on" "$WORK_DIR/tcpdump.log" && break
  kill -0 "$TCPDUMP_PID" 2>/dev/null || break
  sleep 0.1
done
grep -q "listening on" "$WORK_DIR/tcpdump.log" || {
  echo "error: tcpdump did not start" >&2; cat "$WORK_DIR/tcpdump.log" >&2; exit 1; }

"$IPFIXPROBE" "${PLUGIN_ARGS[@]}" -i "pcap;file=$INPUT_FILE" \
  -o "ipfix;host=127.0.0.1;u;port=$PORT;id=1" \
  -s "cache;inactive=300" -p "quic" > "$WORK_DIR/ipfixprobe.log" 2>&1 || {
  echo "error: ipfixprobe failed on $INPUT_FILE" >&2; cat "$WORK_DIR/ipfixprobe.log" >&2; exit 1; }

# Give the last datagrams time to reach tcpdump.
sleep 1
kill "$TCPDUMP_PID"
wait "$TCPDUMP_PID" || true
TCPDUMP_PID=""

if grep -qE "^[1-9][0-9]* packets? dropped by kernel" "$WORK_DIR/tcpdump.log"; then
  echo "error: tcpdump dropped packets" >&2; cat "$WORK_DIR/tcpdump.log" >&2; exit 1
fi

cat "$WORK_DIR/ipfix.pcap"
