#!/usr/bin/env python3
"""Summarizes the compare_flows.py results of a run as Markdown:
pass rate per check (and per interop testcase), plus the failing pcaps.
Skipped checks (see NEEDS_SECRETS in compare_flows.py) count neither as
passed nor as failed.

With --strict, exits with 1 if any check failed or a pcap has no result
(e.g. because ipfixprobe, flowpipeline or tshark failed on it).
"""
import argparse
import json
from pathlib import Path

import polars as pl

MAX_LISTED_PCAPS = 50


def testcase(pcap: Path) -> str:
    # Interop runner layout: <pair>/<testcase>/sim/<trace>.pcap
    return pcap.parts[-3] if len(pcap.parts) >= 3 else ""


def load(pcap_dir: Path, result_dir: Path) -> pl.DataFrame:
    rows = []
    for pcap in sorted(p.relative_to(pcap_dir) for p in pcap_dir.rglob("*.pcap")):
        result_file = result_dir / pcap.with_suffix(".json")
        if not result_file.exists():
            rows.append({"pcap": str(pcap), "testcase": testcase(pcap), "check": "no result", "result": "failed"})
            continue
        for check, value in json.loads(result_file.read_text()).items():
            rows.append({"pcap": str(pcap), "testcase": testcase(pcap), "check": check, "result": value["result"]})
    return pl.DataFrame(rows, schema=["pcap", "testcase", "check", "result"])


def pass_rates(df: pl.DataFrame, by: str) -> pl.DataFrame:
    return (
        df.group_by(by)
        .agg(
            (pl.col("result") == "passed").sum().alias("passed"),
            (pl.col("result") == "skipped").sum().alias("skipped"),
            pl.len().alias("total"),
        )
        .with_columns((pl.col("passed") / (pl.col("total") - pl.col("skipped")) * 100).round(1)
                      .alias("pass_rate_%"))
        .sort("pass_rate_%", by)
    )


def markdown(df: pl.DataFrame) -> str:
    lines = ["| " + " | ".join(df.columns) + " |", "|" + "---|" * df.width]
    lines += ["| " + " | ".join(str(v) for v in row) + " |" for row in df.iter_rows()]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap_dir", type=Path)
    ap.add_argument("result_dir", type=Path)
    ap.add_argument("--strict", action="store_true", help="exit 1 on any failure")
    args = ap.parse_args()

    df = load(args.pcap_dir, args.result_dir)
    failing = (
        df.filter(pl.col("result") == "failed")
        .group_by("pcap", maintain_order=True)
        .agg(pl.col("check").str.join(", ").alias("failed checks"))
    )
    n_pcaps = df["pcap"].n_unique()

    print(f"### {n_pcaps - failing.height}/{n_pcaps} pcaps passed all checks\n")
    if df.is_empty():
        return 1 if args.strict else 0

    print(markdown(pass_rates(df, "check")) + "\n")
    if df["testcase"].ne("").any():
        per_pcap = df.group_by("pcap", "testcase").agg(
            pl.when((pl.col("result") == "failed").any()).then(pl.lit("failed")).otherwise(pl.lit("passed")).alias("result"))
        print(markdown(pass_rates(per_pcap, "testcase").rename({"passed": "pcaps passed"})) + "\n")
    if failing.height:
        print(f"<details><summary>Failing pcaps ({failing.height})</summary>\n")
        print(markdown(failing.head(MAX_LISTED_PCAPS)))
        if failing.height > MAX_LISTED_PCAPS:
            print(f"\n... and {failing.height - MAX_LISTED_PCAPS} more, see the results artifact.")
        print("\n</details>")

    return 1 if args.strict and (failing.height or df.is_empty()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
