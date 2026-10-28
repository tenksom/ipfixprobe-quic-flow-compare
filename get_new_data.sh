#!/bin/bash
# Downloads the pcaps of a QUIC interop runner run into <dest>/<date>/.
#
#   ./get_new_data.sh [run-id|latest] [dest]
#
# Run ids are listed in https://interop.seemann.io/logs/quic/logs.json.
#
# WAIT_TIMEOUT (seconds, default 0): keep retrying until the run is complete.
# TESTCASES (space separated, default: all): only download these test cases,
#   e.g. "handshake retry". A full run is >20 GB, mostly transfer-like tests.
# Exits with 3 if the run is not available. Prints the target directory.
set -euo pipefail

RUN="${1:-latest}"
DEST="${2:-.}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-0}"
TESTCASES="${TESTCASES:-}"
URL="https://interop.seemann.io/logs/quic/$RUN"

# result.json only exists once a run has finished.
deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
until curl -sf -o /dev/null "$URL/result.json"; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "run '$RUN' not available" >&2
    exit 3
  fi
  sleep 300
done

# "latest" is the last completed run, its id is in result.json.
RESULT=$(curl -sf "$URL/result.json")
RUN_ID=$(grep -oE '"log_dir": *"[^"]+"' <<< "$RESULT" | sed -E 's/.*"([^"]+)"$/\1/')
# Run ids contain ":", which breaks make, so only the date is used.
DIR="$DEST/${RUN_ID%%T*}"
mkdir -p "$DIR"
printf '%s\n' "$RESULT" > "$DIR/result.json"

[ -n "$TESTCASES" ] || TESTCASES=$(python3 -c \
  'import json, sys; print(" ".join(t["name"] for t in json.load(sys.stdin)["tests"].values()))' \
  <<< "$RESULT")

# The pcap paths are fixed, so they are fetched directly. Crawling the
# directory listings with wget -r costs ~50 requests per test case (sort links,
# client/server logs). Test cases a pair did not run are 404 and skipped.
fetch() {  # <pair>/<testcase>/sim/<trace>.pcap
  [ -s "$DIR/$1" ] && return
  mkdir -p "$(dirname "$DIR/$1")"
  curl -sf -o "$DIR/$1.part" "$URL/$1" && mv "$DIR/$1.part" "$DIR/$1" || rm -f "$DIR/$1.part"
}
export -f fetch
export DIR URL

pairs=$(curl -sf "$URL/" | grep -oE 'href="\./[^"/]+_[^"/]+/"' | sed -E 's|^href="\./||; s|/"$||')
for pair in $pairs; do
  for tc in $TESTCASES; do
    for trace in left right; do echo "$pair/$tc/sim/trace_node_$trace.pcap"; done
  done
done | xargs -P 16 -I{} bash -c 'fetch "$1"' _ {}
find "$DIR" -type d -empty -delete

[ -n "$(find "$DIR" -name '*.pcap' -print -quit)" ] || { echo "error: no pcaps downloaded" >&2; exit 1; }
echo "$DIR"
