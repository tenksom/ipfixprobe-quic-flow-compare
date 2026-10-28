#!/bin/bash
# Exports the fields used by compare_flows.py as parquet.
# Requires a tshark version that supports "-T parquet".
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <input.pcap> <output.parquet>" >&2; exit 1; }
INPUT_FILE="$1"
OUTPUT_FILE="$2"
TSHARK="${TSHARK:-tshark}"
[ -f "$INPUT_FILE" ] || { echo "error: '$INPUT_FILE' not found" >&2; exit 1; }

# Write to a temp file first so an aborted run never leaves a partial parquet
# that make would consider up to date.
trap 'rm -f "$OUTPUT_FILE.tmp"' EXIT

"$TSHARK" -r "$INPUT_FILE" -T parquet \
  --only-protocols eth,ip,ipv6,udp,quic,tls \
  --parquet-file "$OUTPUT_FILE.tmp" \
  -e frame.number -e frame.time_epoch -e ip.len -e ipv6.plen \
  -e ip.src -e ip.dst -e ip.proto \
  -e udp.srcport -e udp.dstport -e udp.stream -e udp.payload \
  -e tcp.srcport -e tcp.dstport -e tcp.stream \
  -e tcp.flags.syn -e tcp.flags.fin -e tcp.flags.reset \
  -e quic.dcid -e quic.scid -e quic.odcid \
  -e quic.connection.number -e quic.long.packet_type \
  -e quic.long.packet_type_v2 \
  -e quic.payload -e ipv6.src -e ipv6.dst \
  -e tls.handshake.extensions_server_name \
  -e quic.version -e quic.token_length \
  -e quic.retry_token \
  -e tls.handshake.extension.type \
  -e tls.handshake.extension.len \
  -e tls.handshake.extension.data \
  -e tls.handshake.type

mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
