#!/bin/bash
# Builds tshark with parquet support and flowpipeline with the pcapstdin
# segment into <prefix>. Both features are not upstream yet; once they are,
# install the released versions instead and delete this script.
#
#   ./build-tools.sh /opt/quic-flow-compare-tools
#
# The wireshark fork is private for now. Access, in this order:
#   WIRESHARK_SSH_KEY  private key of a read-only deploy key (the key itself,
#                      not a path), e.g. from a CI secret; fetched via SSH
#   WIRESHARK_TOKEN    GitHub token with read access; fetched via HTTPS
#   neither            git uses your own credentials (HTTPS)
#
# The CI caches <prefix> keyed on the hash of this file, so changing a ref
# below triggers a rebuild.
set -euo pipefail

WIRESHARK_REPO=https://github.com/jmuecke/wireshark-parquet.git
WIRESHARK_SSH_REPO=git@github.com:jmuecke/wireshark-parquet.git
WIRESHARK_REF=865a53da4aa559ab96daaa36d7a4403ea2e9bb33
FLOWPIPELINE_REPO=https://codeberg.org/tenksom/flowpipeline.git
FLOWPIPELINE_REF=c6b58ed05cc463652934a6d4f990be3b5d7e1084

PREFIX="$(realpath -m "${1:?usage: $0 <prefix>}")"
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT

fetch() {  # <repo> <commit> <dir> [git options...]
  git init -q "$3"
  git -C "$3" "${@:4}" fetch -q --depth 1 "$1" "$2"
  git -C "$3" checkout -q FETCH_HEAD
}

WIRESHARK_AUTH=()
if [ -n "${WIRESHARK_SSH_KEY:-}" ]; then
  # Key file lives in $SRC, so the EXIT trap removes it. The trailing newline
  # matters: secrets often lose it, and ssh rejects the key without one.
  KEY_FILE="$SRC/wireshark_deploy_key"
  (umask 077 && printf '%s\n' "$WIRESHARK_SSH_KEY" > "$KEY_FILE")
  WIRESHARK_REPO=$WIRESHARK_SSH_REPO
  # IdentitiesOnly: use only this key, not whatever an ssh-agent offers.
  WIRESHARK_AUTH=(-c "core.sshCommand=ssh -i $KEY_FILE -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new")
elif [ -n "${WIRESHARK_TOKEN:-}" ]; then
  # Header instead of a token in the URL, so it is not stored in .git/config.
  WIRESHARK_AUTH=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $(
    printf 'x-access-token:%s' "$WIRESHARK_TOKEN" | base64 -w0)")
fi
fetch "$WIRESHARK_REPO" "$WIRESHARK_REF" "$SRC/wireshark" "${WIRESHARK_AUTH[@]}"
# Only tshark (and its parquet-helper); every other program is switched off.
NO_PROGRAMS=()
for p in wireshark stratoshark sharkd dumpcap rawshark text2pcap mergecap reordercap \
         editcap capinfos captype randpkt dftest mmdbresolve androiddump sshdump sshdig \
         ciscodump dpauxmon randpktdump wifidump udpdump falcodump; do
  NO_PROGRAMS+=("-DBUILD_$p=OFF")
done
cmake -S "$SRC/wireshark" -B "$SRC/wireshark/build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  "${NO_PROGRAMS[@]}" -DENABLE_PLUGINS=OFF -DENABLE_PARQUET=ON
cmake --build "$SRC/wireshark/build" -j "$(nproc)"
cmake --install "$SRC/wireshark/build"

fetch "$FLOWPIPELINE_REPO" "$FLOWPIPELINE_REF" "$SRC/flowpipeline"
# The distribution Go can be older than go.mod requires; fetch the right toolchain.
(cd "$SRC/flowpipeline" && GOTOOLCHAIN=auto go build -o "$PREFIX/bin/flowpipeline" .)

# -T '?' always exits with 1 after listing the formats.
{ "$PREFIX/bin/tshark" -T '?' 2>&1 || true; } | grep -q parquet
echo "tools installed to $PREFIX/bin"