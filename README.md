 # QUIC flow compare

Checks the flow records exported by ipfixprobe's QUIC plugin against tshark as
the reference. For every pcap, both tools export the flows, and
`compare_flows.py` compares them field by field (timestamps, packet/byte
counts, SNI, connection IDs, version, client version, token length, TLS
extensions, Retry, multiplexing, 0-RTT).

```
pcap ─► ipfixprobe ─(IPFIX/UDP on lo)─► tcpdump ─► flowpipeline ─► parquet ┐
pcap ─► tshark ─────────────────────────────────────────────────► parquet ┴► compare_flows.py ─► results/*.json
```

ipfixprobe can only export IPFIX over the network, so `pipeline.sh` captures
the export on loopback with tcpdump and hands it to flowpipeline (segment
`pcapstdin`), which turns it into parquet.

## Test data

- `pcaps/`: regression cases. Each one triggered a bug that was fixed in the
  QUIC plugin; the commit message of the fix names the file. These must pass.
- [QUIC interop runner](https://interop.seemann.io) traces, downloaded with
  `get_new_data.sh`. Informational only, see [Known limitations](#known-limitations).

To add a regression case, put the (ideally small, see `editcap`) pcap into
`pcaps/` and mention its name in the commit message of the fix.

## Running locally

Requirements (see `install-deps.sh` for the exact packages on Oracle Linux 10):

- ipfixprobe with pcap input (`-DENABLE_INPUT_PCAP=ON`)
- tcpdump, run via sudo (or `sudo setcap cap_net_raw=eip $(which tcpdump)` and `SUDO=`)
- tshark with `-T parquet` and flowpipeline with the `pcapstdin` segment:
  neither is upstream yet, `build-tools.sh <prefix>` builds both from the forks
- Python 3 with `pip install -r requirements.txt`

```sh
cd tests/quic-flow-compare
make check-tools
make -j$(nproc) check                     # regression pcaps, fails on any failure
make summary                              # pass rates of the last run

# ipfixprobe from a build tree instead of $PATH:
make -j$(nproc) check IPFIXPROBE=../../build/src/core/ipfixprobe PLUGIN_DIR=../../build/src/plugins

# interop runner data (TESTCASES optional, a full run is >20 GB):
TESTCASES="handshake retry" ./get_new_data.sh latest interop
make -j$(nproc) compare PCAP_DIR=interop OUT_DIR=interop_processed RESULT_DIR=interop_results
python3 summarize.py interop interop_results
```

All Makefile variables (`PCAP_DIR`, `IPFIXPROBE`, `PLUGIN_DIR`, `TSHARK`,
`FLOWPIPELINE`, `SUDO`, ...) can be overridden on the command line or via the
environment. `PCAP_DIR` must not contain spaces or `:`. `make clean` removes
all generated files.

Each result JSON has one entry per check with `"result": "passed"`,
`"failed"` or `"skipped"`; failed and skipped checks include the mismatching
flows. A check is skipped instead of failed if tshark needs the TLS secrets
for it (`NEEDS_SECRETS` in `compare_flows.py`) and the pcap has no pcapng
Decryption Secrets Block. `summarize.py` excludes skipped checks from the pass
rates and from `--strict`.

## Known limitations

- **Interop runner availability:** `latest` points to the last completed run,
  older runs are listed in `logs/quic/logs.json`. A run in progress has no
  `result.json` yet; `WAIT_TIMEOUT=<seconds> ./get_new_data.sh <run-id>` waits
  for it to complete. If the runner is down, the interop step is skipped.
- **Forked tools:** `build-tools.sh` pins commits of the tshark and
  flowpipeline forks. Once parquet output and `pcapstdin` are upstream,
  install the released versions in `install-deps.sh` and delete `build-tools.sh`.
- **pcaps without TLS secrets:** most interop runner pcaps embed the keys,
  some do not (e.g. most handshakeloss/handshakecorruption traces of
  2026-08-10). Without them tshark cannot read the server's `grease_quic_bit`
  transport parameter and drops coalesced packets with a greased fixed bit as
  padding, so `quic_packets` and `quic_zero_rtt` are skipped for these pcaps.
- **Retry token used (`0x40`):** the reference takes the sender of the first
  packet as the client, ipfixprobe uses the server port. ipfixprobe also only
  remembers 4 Retries per flow (`MAX_RETRY_CANDIDATES`), the reference has no
  limit. Both only differ for unusual traces.
- Regression pcaps must keep passing; interop results vary between runs, as
  the implementations under test change.
