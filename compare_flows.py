import argparse
import json
import struct
from pathlib import Path
import polars as pl
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)


def load_and_normalize(path: Path) -> pl.DataFrame:
    try:
        df = pl.read_parquet(path)
    except pl.exceptions.ComputeError:
        print(f"Could not load tshark file {path}!")
        exit(2)

    # Add missing columns (e.g. trace without QUIC packets)
    for col, dtype in [
        ("tcp.stream", pl.Int64), ("udp.stream", pl.Int64),
        ("tcp.srcport", pl.Int64), ("tcp.dstport", pl.Int64),
        ("udp.srcport", pl.Int64), ("udp.dstport", pl.Int64),
        ("tcp.flags.syn", pl.Int64), ("tcp.flags.fin", pl.Int64), ("tcp.flags.reset", pl.Int64),
        ("ipv6.plen", pl.Int64),
    ]:
        if col not in df.columns:
            df = df.with_columns(pl.lit(None).cast(dtype).alias(col))
    # Needs -e quic.retry_token in the tshark export to get the retry token length
    if "quic.retry_token" not in df.columns:
        df = df.with_columns(pl.lit(None).cast(pl.List(pl.Binary)).alias("quic.retry_token"))

    # Normalize column types
    spalten = [
        ("frame.number", pl.Int64), ("ip.len", pl.Int64), ("ip.proto", pl.Int64), ("tcp.flags.syn", pl.Boolean),
        ("tcp.flags.fin", pl.Boolean), ("tcp.flags.reset", pl.Boolean), ("quic.connection.number", pl.Int64),
        ("udp.srcport", pl.Int64), ("udp.dstport", pl.Int64),
        ("tcp.srcport", pl.Int64), ("tcp.dstport", pl.Int64),
        ("ipv6.plen", pl.Int64),
        ("quic.token_length", pl.Int64)
    ]

    for col, dtype in spalten:
        df = df.with_columns(pl.col(col).list.get(0).cast(dtype).alias(col))

    df = df.with_columns(pl.col("quic.dcid").list.eval(pl.element().bin.encode("hex")).alias("quic.dcid"))
    df = df.with_columns(pl.col("quic.payload").list.eval(pl.element().bin.encode("hex")).alias("quic.payload"))
    df = df.with_columns(pl.col("quic.scid").list.eval(pl.element().bin.encode("hex")).alias("quic.scid"))
    # Retry token length in bytes
    df = df.with_columns(
        pl.col("quic.retry_token").list.get(-1, null_on_oob=True).bin.size().cast(pl.Int64)
        .alias("quic.retry_token_length")
    )

    # Needs -e udp.payload: ipfixprobe takes the QUIC bit from the first payload byte,
    # also for packets tshark does not dissect as QUIC. Only first byte and length are kept.
    if "udp.payload" not in df.columns:
        df = df.with_columns(pl.lit(None).cast(pl.List(pl.Binary)).alias("udp.payload"))
    udp_payload = pl.col("udp.payload").list.get(0, null_on_oob=True)
    df = df.with_columns([
        udp_payload.bin.encode("hex").str.slice(0, 2).str.to_integer(base=16).cast(pl.Int64)
        .alias("udp.first_byte"),
        udp_payload.bin.size().cast(pl.Int64).alias("udp.payload_len"),
    ]).drop("udp.payload")

    # ip.src/ip.dst are IPv4 only, so fall back to ipv6.src/ipv6.dst
    for col in ("ipv6.src", "ipv6.dst"):
        if col not in df.columns:
            df = df.with_columns(pl.lit([""]).alias(col))
    df = df.with_columns([
        pl.coalesce([pl.col("ip.src").list.get(0), pl.col("ipv6.src").list.get(0)]).alias("ip.src"),
        pl.coalesce([pl.col("ip.dst").list.get(0), pl.col("ipv6.dst").list.get(0)]).alias("ip.dst"),
    ])

    df = df.with_columns(
        pl.coalesce([pl.col("ip.len"), pl.col("ipv6.plen") + 40]).alias("ip.len")
    )

    # Unified ports/stream ID for TCP and UDP
    df = df.with_columns([
        pl.coalesce(["tcp.srcport", "udp.srcport"]).alias("srcport"),
        pl.coalesce(["tcp.dstport", "udp.dstport"]).alias("dstport"),
        pl.coalesce(["tcp.stream", "udp.stream"]).alias("l4_stream"),
    ])

    # Transport protocol label
    df = df.with_columns(
        pl.when(pl.col("tcp.stream").is_not_null()).then(pl.lit("tcp"))
        .when(pl.col("udp.stream").is_not_null()).then(pl.lit("udp"))
        .otherwise(pl.lit("other"))
        .alias("l4_proto")
    )

    return df


def normalize_pipeline(df: pl.DataFrame) -> pl.DataFrame:
    """
    Convert the flowpipeline parquet output into the format main() expects.
    """
    df = df.rename({
        "SourceIP": "src_addr",
        "DestinationIP": "dst_addr",
        "BytesRev": "bytes_rev",
        "PacketsRev": "packets_rev",
        "QuicSni": "quic_sni",
        "QuicVersion": "quic_version",
        "QuicClientVersion": "quic_client_version",
        "QuicZeroRtt": "quic_zero_rtt",
        "QuicTokenLength": "quic_token_length",
        "QuicChParsed": "quic_ch_parsed",
        "QuicMultiplexed": "quic_multiplexed",
        "QuicScid": "quic_scid",
        "QuicOccid": "quic_occid",
        "QuicOscid": "quic_oscid",
        "QuicRetryScid": "quic_retry_scid",
        "QuicTlsExtType": "quic_tls_ext_type",
        "QuicTlsExtLen": "quic_tls_ext_len",
        "QuicPackets": "quic_packets"
    }, strict=False)
    # Connection IDs as hex strings
    df = df.with_columns(
        pl.col(c).bin.encode("hex")
        for c in ("quic_scid", "quic_occid", "quic_oscid", "quic_retry_scid") if c in df.columns
    )
    # TLS extensions as "0,16,43"
    df = df.with_columns(
        pl.col(c).list.eval(pl.element().cast(pl.Utf8)).list.join(",")
        for c in ("quic_tls_ext_type", "quic_tls_ext_len", "quic_packets") if c in df.columns
    )
    # Unsigned -> Int64 to avoid overflow in diffs
    unsigned = (pl.UInt8, pl.UInt16, pl.UInt32, pl.UInt64)
    return df.with_columns(
        pl.col(c).cast(pl.Int64) for c, dtype in df.schema.items() if dtype in unsigned
    )


def split_flow_vs_nonflow(df: pl.DataFrame) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Split TCP/UDP packets from non-flow traffic (ARP, ICMPv6, ...).
    Non-flow packets are returned separately instead of being dropped.
    """
    # Also filter on the outer ip.proto: ICMP errors carry an inner UDP header,
    # which would otherwise create phantom flows. ip.proto is empty for IPv6.
    has_flow = (
        pl.col("l4_stream").is_not_null()
        & pl.col("ip.proto").is_in([6, 17]).fill_null(True)
    )
    flow_df = df.filter(has_flow)
    nonflow_df = df.filter(~has_flow)
    return flow_df, nonflow_df


def canonical_key(proto, a, b):
    lo, hi = sorted([a, b])
    return f"{proto}|{lo}|{hi}"


def add_flow_key(df: pl.DataFrame) -> pl.DataFrame:
    """
    Build a direction-independent flow key: smaller (ip, port) is "endpoint_a".
    Also store each packet's direction (a->b or b->a).
    """
    df = df.with_columns([
        pl.concat_str(["ip.src", pl.col("srcport").cast(pl.Utf8)], separator=":").alias("ep_src"),
        pl.concat_str(["ip.dst", pl.col("dstport").cast(pl.Utf8)], separator=":").alias("ep_dst"),
    ])

    df = df.with_columns([
        pl.min_horizontal(["ep_src", "ep_dst"]).alias("endpoint_a"),
        pl.max_horizontal(["ep_src", "ep_dst"]).alias("endpoint_b"),
        (pl.col("ep_src") == pl.min_horizontal(["ep_src", "ep_dst"])).alias("is_a_to_b"),
    ])

    # Flow key: protocol + sorted endpoints
    df = df.with_columns(
        pl.struct(["l4_proto", "endpoint_a", "endpoint_b"])
        .map_elements(lambda r: canonical_key(r["l4_proto"], r["endpoint_a"], r["endpoint_b"]))
        .alias("flow_key")
    )
    return df


def compute_quic_multiplexed(df: pl.DataFrame) -> pl.DataFrame:
    """
    Per flow_key, check whether more than one QUIC connection was seen.

    Time overlap is ignored on purpose: ipfixprobe does not split a flow on
    CONNECTION_CLOSE, so >1 connection on the 5-tuple => multiplexed.
    """
    return (
        df.filter(pl.col("quic.connection.number").is_not_null())
        .group_by("flow_key")
        .agg((pl.col("quic.connection.number").n_unique().max() - 1) .alias("quic_multiplexed")) # tshark starts at 1
        .select(["flow_key", "quic_multiplexed"])
    )


QUIC_MAX_ELEMCOUNT = 30  # quic.hpp
QUIC_MIN_PACKET_LENGTH = 8  # quic_parser.hpp


def add_quic_packet_flags(df: pl.DataFrame, frame_has_valid_version: pl.Expr) -> pl.DataFrame:
    """
    Per frame the QUIC_PACKETS value of ipfixprobe (QUICParser::PACKET_TYPE_FLAG):
    0x80 = QUIC bit of the first byte, OR'ed with one flag per coalesced long header packet
    (Initial 0x01, 0-RTT 0x02, Handshake 0x04, Retry 0x08, Version Negotiation 0x10).
    0x40 (Retry token used) is not a packet type and is added by add_retry_token_used().
    """
    # Long header packet types -> flags, v2 uses different type numbers (RFC 9369)
    flags_v1 = pl.col("quic.long.packet_type").list.eval(
        pl.element().cast(pl.Int64).replace_strict({0: 0x01, 1: 0x02, 2: 0x04, 3: 0x08}, default=0)
    ).list.unique().list.sum().fill_null(0)
    flags_v2 = pl.col("quic.long.packet_type_v2").list.eval(
        pl.element().cast(pl.Int64).replace_strict({1: 0x01, 2: 0x02, 3: 0x04, 0: 0x08}, default=0)
    ).list.unique().list.sum().fill_null(0)
    # tshark has no packet type for Version Negotiation, only version 0
    is_vn = pl.col("quic.version").list.contains(0).fill_null(False)
    type_flags = flags_v1 | flags_v2 | pl.when(is_vn).then(0x10).otherwise(0)

    first_byte = pl.col("udp.first_byte").fill_null(0)
    quic_bit = (first_byte & 0x40) * 2
    # QUICParser::quic_long_header_packet(): long header, min length, supported version
    long_header = (
        ((first_byte & 0x80) != 0)
        & (pl.col("udp.payload_len").fill_null(0) >= QUIC_MIN_PACKET_LENGTH)
        & (frame_has_valid_version.fill_null(False) | is_vn)
    )
    type_flags = pl.when(long_header).then(type_flags).otherwise(0)

    return df.with_columns([
        (quic_bit | type_flags).alias("_quic_pkt_flags"),
        # ipfixprobe creates the QUIC extension on the first detected packet,
        # earlier packets stay 0 in the array
        (type_flags != 0).alias("_quic_detected"),
    ])


QUIC_F_RETRY_TOKEN_USED = 0x40  # QUICParser::F_RETRY_TOKEN_USED


def add_retry_token_used(
    df: pl.DataFrame, frame_is_retry: pl.Expr, frame_is_client_initial: pl.Expr
) -> pl.DataFrame:
    """
    Sets 0x40 in _quic_pkt_flags on the first client Initial whose DCID is the SCID of an
    earlier Retry of the flow, i.e. the Initial that adopted the Retry (RFC 9000 §17.2.5.2).
    Like ipfixprobe, only the DCID is checked, not the token bytes.
    """
    df = df.with_columns(pl.col("quic.dcid").list.get(0, null_on_oob=True).alias("_dcid0"))
    # Earliest frame per Retry SCID, a retransmitted Retry must not duplicate rows in the join
    retries = (
        df.filter(frame_is_retry)
        .select("flow_key", pl.col("_scid0").alias("_retry_scid"), pl.col("frame.number").alias("_retry_frame"))
        .drop_nulls()
        .group_by("flow_key", "_retry_scid")
        .agg(pl.col("_retry_frame").min())
    )
    df = (
        df.join(retries, left_on=["flow_key", "_dcid0"], right_on=["flow_key", "_retry_scid"], how="left")
        .sort("frame.number")  # join does not keep order
    )
    adopts_retry = (
        frame_is_client_initial
        & (pl.col("_retry_frame") < pl.col("frame.number")).fill_null(False)
    )
    # Only the first adopting Initial, ipfixprobe stops looking once the Retry is confirmed
    first_adopting = adopts_retry & (adopts_retry.cast(pl.Int64).cum_sum().over("flow_key") == 1)
    return df.with_columns(
        (pl.col("_quic_pkt_flags") | pl.when(first_adopting).then(QUIC_F_RETRY_TOKEN_USED).otherwise(0))
        .alias("_quic_pkt_flags")
    ).drop("_dcid0", "_retry_frame")


def aggregate_flows(df: pl.DataFrame) -> pl.DataFrame:
    df = df.sort("frame.number")
    multiplexed_df = compute_quic_multiplexed(df)

    pt_v1 = pl.col("quic.long.packet_type")
    pt_v2 = pl.col("quic.long.packet_type_v2")
    ver = pl.col("quic.version")

    valid_ver = pl.col("quic.version").list.eval(
        pl.when(
            (pl.element() == 1)  # QUIC v1
            | (pl.element() == 0x6b3343cf)  # QUIC v2
            | (pl.element().floordiv(256) == 0xff0000)  # IETF Draft (0xff0000xx)
            | ((pl.element() & 0x0f0f0f0f) == 0x0a0a0a0a)  # Grease version
        ).then(pl.element()).otherwise(None)
    ).list.drop_nulls()

    # Does the frame contain a long header QUIC packet?
    frame_has_long = (
                             pt_v1.list.drop_nulls().list.len().fill_null(0)
                             + pt_v2.list.drop_nulls().list.len().fill_null(0)
                     ) > 0

    # Exclude 0-RTT, it still carries the client version, not the negotiated one
    frame_has_zerortt = (
            pt_v1.list.contains(1).fill_null(False)
            | pt_v2.list.contains(2).fill_null(False)
    )

    # Last version in the frame (for coalesced packets)
    frame_ver = valid_ver.list.drop_nulls().list.last()

    negotiated_version = (
        frame_ver
        .filter(frame_has_long & ~frame_has_zerortt & frame_ver.is_not_null())
        .last()  # capture order, not max()
        .alias("quic_version")
    ).replace(1798521807, 2)

    # Only count Retries with a valid version; corrupted packets can look like a Retry
    frame_has_valid_version = valid_ver.list.len() > 0

    # Version of the first ClientHello. Differs from quic_version with compatible version
    # negotiation (RFC 9368), e.g. client Initial v1, server switches to v2.
    frame_has_ch = (
        pl.col("tls.handshake.type").list.eval(pl.element().cast(pl.Int64))
        .list.contains(1).fill_null(False)
    )
    client_version = (
        frame_ver
        .filter(frame_has_long & frame_has_valid_version.fill_null(False) & frame_has_ch)
        .first()
        .alias("quic_client_version")
    ).replace(1798521807, 2)

    # Number of 0-RTT packets, coalesced ones count individually. ipfixprobe saturates at 0xFF.
    zero_rtt_per_frame = (
        pt_v1.list.eval((pl.element().cast(pl.Int64) == 1).cast(pl.Int64)).list.sum().fill_null(0)
        + pt_v2.list.eval((pl.element().cast(pl.Int64) == 2).cast(pl.Int64)).list.sum().fill_null(0)
    )
    zero_rtt = (
        zero_rtt_per_frame.filter(frame_has_valid_version.fill_null(False))
        .sum()
        .clip(upper_bound=0xFF)
        .alias("quic_zero_rtt")
    )

    frame_is_retry = (
            (pt_v1.list.contains(3).fill_null(False)
             | pt_v2.list.contains(0).fill_null(False))
            & frame_has_valid_version
    )

    # Retry SCID. With multiple Retries, use the one the client accepted
    # (its SCID becomes the client's DCID, RFC 9000 §7.2), otherwise the last one.
    df = df.with_columns(pl.col("quic.scid").list.get(0, null_on_oob=True).alias("_scid0"))
    client_dcids = (
        df.filter(pl.col("is_a_to_b") == pl.col("is_a_to_b").first().over("flow_key"))
        .select("flow_key", pl.col("quic.dcid").alias("_dcid"))
        .explode("_dcid")
        .drop_nulls()
        .unique()
        .with_columns(pl.lit(True).alias("_retry_adopted"))
    )
    df = (
        df.join(client_dcids, left_on=["flow_key", "_scid0"], right_on=["flow_key", "_dcid"], how="left")
        .with_columns(pl.col("_retry_adopted").fill_null(False))
        .sort("frame.number")  # join does not keep order
    )
    retry_adopted = frame_is_retry & pl.col("_retry_adopted")

    # --- QUIC Token Length -------------------------------------------------------
    # Token length is defined per client Initial, so a flow can have several valid values.
    # The reference is the set of all client Initial token lengths.
    first_is_initial = (
        (pt_v1.list.get(0, null_on_oob=True) == 0)
        | (pt_v2.list.get(0, null_on_oob=True) == 1)
    ).fill_null(False) & frame_has_valid_version.fill_null(False)

    # Client = sender of the first packet in the flow
    from_client = pl.col("is_a_to_b") == pl.col("is_a_to_b").first()

    client_initial = first_is_initial & from_client & pl.col("quic.token_length").is_not_null()

    df = add_quic_packet_flags(df, frame_has_valid_version)
    df = add_retry_token_used(
        df, frame_is_retry, first_is_initial & (from_client.over("flow_key"))
    )
    quic_packets = (
        pl.when(pl.col("_quic_detected").cum_sum() > 0)
        .then(pl.col("_quic_pkt_flags"))
        .otherwise(0)
        .head(QUIC_MAX_ELEMCOUNT)
        .alias("quic_packets")
    )

    retry_scid = pl.coalesce(
        pl.col("_scid0").filter(retry_adopted).drop_nulls().first(),
        pl.col("_scid0").filter(frame_is_retry).drop_nulls().last(),
    ).alias("quic_retry_scid")
    # All Retry SCIDs (for debugging)
    retry_scids = (
        pl.col("_scid0").filter(frame_is_retry).drop_nulls()
        .unique(maintain_order=True).alias("quic_retry_scids")
    )

    # Like ipfixprobe: if there was a Retry, use its token length (same choice as
    # quic_retry_scid), otherwise the client Initial set.
    retry_token_length = pl.coalesce(
        pl.col("quic.retry_token_length").filter(retry_adopted).drop_nulls().first(),
        pl.col("quic.retry_token_length").filter(frame_is_retry).drop_nulls().last(),
    ).alias("quic_retry_token_length")
    token_lengths = (
        pl.col("quic.token_length").filter(client_initial)
        .unique().sort()
        .alias("quic_token_lengths")
    )
    # Stricter variant: last client Initial value (optional, breaks on reordering)
    token_length_final = (
        pl.col("quic.token_length").filter(client_initial)
        .last()
        .alias("quic_token_length_final")
    )

    flows = (
        df.group_by("flow_key", maintain_order=True)
        .agg([
            pl.first("l4_proto").alias("proto"),
            pl.first("endpoint_a").alias("endpoint_a"),
            pl.first("endpoint_b").alias("endpoint_b"),

            pl.len().alias("packet_count"),
            pl.col("ip.len").sum().alias("bytes_total"),

            # Per-direction counters
            pl.col("ip.len").filter(pl.col("is_a_to_b")).sum().alias("bytes_a_to_b"),
            pl.col("ip.len").filter(~pl.col("is_a_to_b")).sum().alias("bytes_b_to_a"),
            pl.len().filter(pl.col("is_a_to_b")).alias("packets_a_to_b"),
            pl.len().filter(~pl.col("is_a_to_b")).alias("packets_b_to_a"),

            # Flow time window
            pl.col("frame.time_epoch").list.get(0).first().alias("t_start"), # the largest timestamp is not always the last packet,
            pl.col("frame.time_epoch").list.get(0).last().alias("t_end"), # e.g. data/raw/2026-10-04/lsquic_msquic_handshakeloss_sim_trace_node_left.pcap

            # TCP flags
            (pl.col("tcp.flags.syn").fill_null(False).sum() > 0).alias("has_syn"),
            (pl.col("tcp.flags.fin").fill_null(False).sum() > 0).alias("has_fin"),
            (pl.col("tcp.flags.reset").fill_null(False).sum() > 0).alias("has_rst"),
            (pl.col("tls.handshake.extensions_server_name").drop_nulls().list.first().first()).alias("quic_sni"),
            negotiated_version,
            client_version,
            zero_rtt,
            token_lengths,
            token_length_final,
            retry_token_length,
            pl.col("tls.handshake.extension.type").drop_nulls().unique().list.eval(
                pl.element().cast(pl.Utf8)).list.join(",").alias("tls_extension_types"),
            pl.col("tls.handshake.extension.len").drop_nulls().unique().list.eval(
                pl.element().cast(pl.Utf8)).list.join(",").alias("tls_extension_lens"),

            pl.col("tls.handshake.type").drop_nulls().unique().list.explode().alias("tls_handshake_types"),
            pl.col("quic.connection.number").drop_nulls().unique().alias("quic_connection_numbers"),
            pl.col("quic.connection.number").drop_nulls().n_unique().alias("quic_connection_count"),
            # All QUIC connection IDs
            pl.col("quic.dcid").drop_nulls().explode().drop_nulls().unique(maintain_order=True).alias("quic_dcids_seen"),
            pl.col("quic.scid").drop_nulls().explode().drop_nulls().unique(maintain_order=True).alias("quic_scids_seen"),
            pl.col("quic.odcid").drop_nulls().explode().drop_nulls().unique(maintain_order=True).alias("quic_odcids_seen"),
            retry_scid,
            retry_scids,
            quic_packets,
            pl.col("_quic_detected").any().alias("_quic_detected"),
            pl.col("frame.number").first().alias("first_frame"),
            pl.col("frame.number").last().alias("last_frame"),
        ])
        .with_columns([
            (pl.col("t_end") - pl.col("t_start")).alias("duration_s"),
            pl.when(pl.col("quic_retry_token_length").is_not_null())
            .then(pl.concat_list(pl.col("quic_retry_token_length")))
            .otherwise(pl.col("quic_token_lengths"))
            .alias("quic_token_lengths"),
            # Same format as normalize_pipeline: "129,133,128", null without QUIC
            pl.when(pl.col("_quic_detected"))
            .then(pl.col("quic_packets").list.eval(pl.element().cast(pl.Utf8)).list.join(","))
            .alias("quic_packets"),
            ]
        )
        .drop("_quic_detected")
        .join(multiplexed_df, on="flow_key", how="left")
        .with_columns(
            pl.col("quic_multiplexed").fill_null(False)
        )
        .sort("bytes_total", descending=True)
    )
    return flows


def prefix_columns(df: pl.DataFrame, prefix, exclude):
    return df.rename({
        col: f"{prefix}_{col}" for col in df.columns if col not in exclude
    })

META_COLS = [
    "flow_key",
    "tshark_first_frame",
    "tshark_last_frame",
    "tshark_t_start",
    "tshark_packet_count",
    "tshark_quic_connection_numbers",
]


def failed_report(failed: pl.DataFrame, *cols) -> dict:
    meta = [c for c in META_COLS if c in failed.columns and c not in cols]
    return {
        "result": "failed",
        "count": failed.height,
        "df": json.loads(failed.select(*meta, *cols).write_json()),
    }

# Checks that tshark can only get right with the TLS secrets: without them it cannot decrypt
# the server's transport parameters, misses grease_quic_bit (RFC 9287) and treats coalesced
# packets with a greased fixed bit as padding.
NEEDS_SECRETS = {"quic_packets", "quic_zero_rtt"}


def has_decryption_secrets(path: Path) -> bool:
    """True if the pcapng file contains a Decryption Secrets Block (TLS keys)."""
    data = path.read_bytes()
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        return False  # classic pcap cannot carry secrets
    offset, endian = 0, "<"
    while offset + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, offset)[0]
        if block_type == 0x0A0D0D0A:  # Section Header Block, sets the byte order
            endian = "<" if data[offset + 8:offset + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        elif block_type == 0x0000000A:  # Decryption Secrets Block
            return True
        block_len = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if block_len < 12:
            break
        offset += block_len
    return False


def skip_without_secrets(results: dict, pcap: Path) -> dict:
    """A failed check from NEEDS_SECRETS on a pcap without secrets is reported as skipped."""
    for name in NEEDS_SECRETS & results.keys():
        if results[name]["result"] == "failed":
            results[name] = {
                **results[name],
                "result": "skipped",
                "reason": f"{pcap.name} has no decryption secrets, tshark cannot decrypt the handshake",
            }
    return results


def test_dataframe(df: pl.DataFrame, col_ipfix, col_tshark, threshold=0):
    if df[col_ipfix].dtype == pl.String and df[col_tshark].dtype == pl.String:
        diff = df[col_ipfix].ne(df[col_tshark])
        failed = df.filter(diff)
    else:
        diff = (df[col_ipfix] - df[col_tshark]).abs()
        mismatch_null = df[col_ipfix].is_null() != df[col_tshark].is_null()
        failed = df.filter((diff > threshold) | mismatch_null)

    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_time(df: pl.DataFrame, col_ipfix, col_tshark, threshold=0):
    diff = (df[col_ipfix].cast(pl.Int64) - df[col_tshark].cast(pl.Int64)).abs()
    failed = df.filter(diff > threshold)
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_str_isin(df: pl.DataFrame, col_ipfix, col_tshark, place=-1):
    relevant = df.filter(
        pl.col(col_ipfix).is_not_null() & (pl.col(col_ipfix) != "")
    )
    if place == -1:
        failed = relevant.filter(~pl.col(col_tshark).list.contains(pl.col(col_ipfix)))
    else:
        failed = relevant.filter(~pl.col(col_tshark).list.get(place, null_on_oob=True).eq(pl.col(col_ipfix)))
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)

def test_dataframe_int_isin(df: pl.DataFrame, col_ipfix, col_tshark, drop_number_null=False):
    relevant = df
    if drop_number_null:
        relevant = relevant.with_columns(pl.col(col_ipfix).replace(0, None))

    relevant = relevant.filter(
        pl.col(col_ipfix).is_not_null()
    )

    failed = relevant.filter(~pl.col(col_tshark).list.contains(pl.col(col_ipfix)))

    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_integer(df: pl.DataFrame, col_ipfix, col_tshark):
    # compare raw numbers
    diff = df[col_ipfix].ne(df[col_tshark])
    failed = df.filter(diff)
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_integer_null_as_zero(df: pl.DataFrame, col_ipfix, col_tshark):
    # ipfixprobe exports 0 for unset QUIC fields and null without QUIC extension,
    # tshark has null if the value never occurred. Treat all of them as 0.
    filled = df.with_columns(pl.col(col_ipfix).fill_null(0), pl.col(col_tshark).fill_null(0))
    return test_dataframe_integer(filled, col_ipfix, col_tshark)


def test_dataframe_lists(df: pl.DataFrame, col_ipfix, col_tshark):
    relevant = df.filter(
        pl.col(col_ipfix).is_not_null() & (pl.col(col_ipfix) != "")
    )
    failed = relevant.filter(~pl.col(col_tshark).list.contains(pl.col(col_ipfix)))
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)

def test_token_length(df: pl.DataFrame, col_ipfix, col_tshark_set):
    # Passes if the ipfixprobe value is in the tshark set
    relevant = df.filter(pl.col(col_ipfix).is_not_null())
    # 0 without any client Initial means "no token"
    relevant = relevant.filter(
        ~((pl.col(col_ipfix) == 0) & (pl.col(col_tshark_set).list.len().fill_null(0) == 0))
    )
    # cast UInt16 to Int64
    failed = relevant.filter(
        ~pl.col(col_tshark_set).list.contains(pl.col(col_ipfix).cast(pl.Int64)).fill_null(False)
    )
    if failed.is_empty():
        return {"result": "passed"}
    return failed_report(failed, col_ipfix, col_tshark)


def test_multiplexed(df: pl.DataFrame, col_ipfix, col_tshark):
    # If ipfixprobe reports multiplexing (>0), tshark must confirm it. 0 is not checked.
    relevant = df.filter(pl.col(col_ipfix).cast(pl.Int64).fill_null(0) > 0)
    failed = relevant.filter(pl.col(col_tshark).cast(pl.Int64).fill_null(0) <= 0)
    if failed.is_empty():
        return {"result": "passed"}
    return {"result": "failed",
            "df": json.loads(failed.select(col_ipfix, col_tshark).write_json())}

def main():
    ap = argparse.ArgumentParser(
        description="Vergleicht eine tshark-Referenz-Parquet-Datei mit einer "
                    "ipfixprobe/flowpipeline-Parquet-Datei auf Flow-Ebene."
    )
    ap.add_argument("--tshark-file", required=True, help="Pfad zur tshark-Parquet-Datei (Referenz)")
    ap.add_argument("--pipeline-file", required=True, help="Pfad zur ipfixprobe/flowpipeline-Parquet-Datei")
    ap.add_argument("--out", required=True, help="Pfad für das Ergebnis-JSON")
    ap.add_argument("--pcap", help="Pfad zur Original-pcap, um eingebettete TLS-Secrets zu prüfen")
    args = ap.parse_args()

    tshark_path = Path(args.tshark_file)
    pipeline_path = Path(args.pipeline_file)
    out_path = Path(args.out)

    tshark_original = load_and_normalize(tshark_path)

    flow_df, nonflow_df = split_flow_vs_nonflow(tshark_original)
    # print(f"Pakete gesamt: {len(tshark_original)} | mit L4-Flow (TCP/UDP): {len(flow_df)} "
    #      f"| ohne (ARP/ICMPv6/...): {len(nonflow_df)}")

    flows_with_key = add_flow_key(flow_df)
    flows_tshark = aggregate_flows(flows_with_key)

    IANA_PROTO = {
        1: "icmp",
        6: "tcp",
        17: "udp",
        41: "ipv6",
        58: "icmpv6",
    }
    try:
        # use pyarrow, polars misreads the flowpipeline list columns
        df_loaded = pl.read_parquet(pipeline_path, use_pyarrow=True)
    except pl.exceptions.ComputeError:
        print(f"Could not load pipeline file {pipeline_path}!")
        exit(2)
    df_loaded = normalize_pipeline(df_loaded)
    df_sum = (df_loaded
              .with_columns(pl.sum_horizontal(pl.col("bytes"), pl.col("bytes_rev")).alias("bytes_total"))
              .with_columns(pl.sum_horizontal(pl.col("packets"), pl.col("packets_rev")).alias("packets_count"))
              )
    df_duration = (df_sum
                   .with_columns(
        (pl.col("time_flow_end_ns") - pl.col("time_flow_start_ns")).alias("duration_s")
    )
                   .with_columns(pl.from_epoch(pl.col("time_flow_start_ns"), time_unit="ns"))
                   .with_columns(pl.from_epoch(pl.col("time_flow_end_ns"), time_unit="ns"))
                   )
    df_only_udp_tcp = df_duration.filter(pl.col("proto").is_in([6, 17]))
    df_mapped = df_only_udp_tcp.with_columns(
        pl.col("proto").replace(IANA_PROTO, default=pl.col("proto").cast(pl.Utf8)).alias("proto"))
    df_mapped = df_mapped.with_columns(
        pl.col(c).replace(1798521807, 2)  # QUIC v2 = 0x6B3343CF
        for c in ("quic_version", "quic_client_version")
    )
    df_concat_ip_ports = (df_mapped
                          .with_columns(
        pl.concat_str([pl.col("src_addr"), pl.col("src_port")], separator=":").alias("endpoint_a"))
                          .with_columns(
        pl.concat_str([pl.col("dst_addr"), pl.col("dst_port")], separator=":").alias("endpoint_b"))
                          )
    flows_pipeline = df_concat_ip_ports.with_columns(
        pl.struct(["proto", "endpoint_a", "endpoint_b"])
        .map_elements(lambda r: canonical_key(r["proto"], r["endpoint_a"], r["endpoint_b"]))
        .alias("flow_key")
    )

    df_pipeline = prefix_columns(flows_pipeline, "ipfixprobe", ["flow_key"])
    df_tshark = prefix_columns(flows_tshark, "tshark", ["flow_key"])

    joined = df_pipeline.join(df_tshark, on="flow_key", suffix="_ref", how="inner")
    THRESHOLD_TIME_NS = 1000
    results = {
        "start_times": test_dataframe_time(joined, "ipfixprobe_time_flow_start_ns", "tshark_t_start", 1000),
        "end_times": test_dataframe_time(joined, "ipfixprobe_time_flow_end_ns", "tshark_t_end", 1000),
        "packet_counts": test_dataframe(joined, "ipfixprobe_packets_count", "tshark_packet_count"),
        "total_bytes": test_dataframe(joined, "ipfixprobe_bytes_total", "tshark_bytes_total"),
        "quic_sni": test_dataframe(joined, "ipfixprobe_quic_sni", "tshark_quic_sni"),
        "quic_occid": test_dataframe_str_isin(joined, "ipfixprobe_quic_occid", "tshark_quic_scids_seen", 0),
        "quic_scid": test_dataframe_str_isin(joined, "ipfixprobe_quic_scid", "tshark_quic_scids_seen"),
        "quic_oscid": test_dataframe_str_isin(joined, "ipfixprobe_quic_oscid", "tshark_quic_dcids_seen", 0),
        "quic_version": test_dataframe_integer(joined, "ipfixprobe_quic_version", "tshark_quic_version"),
        "quic_client_version": test_dataframe_integer_null_as_zero(joined, "ipfixprobe_quic_client_version", "tshark_quic_client_version"),
        "quic_zero_rtt": test_dataframe_integer_null_as_zero(joined, "ipfixprobe_quic_zero_rtt", "tshark_quic_zero_rtt"),
        "quic_token_length": test_token_length(joined, "ipfixprobe_quic_token_length", "tshark_quic_token_lengths"),
        "quic_tls_ext_types": test_dataframe_lists(joined, "ipfixprobe_quic_tls_ext_type", "tshark_tls_extension_types"),
        "quic_tls_ext_len": test_dataframe_lists(joined, "ipfixprobe_quic_tls_ext_len", "tshark_tls_extension_lens"),
        "quic_ch_parsed": test_dataframe_int_isin(joined, "ipfixprobe_quic_ch_parsed", "tshark_tls_handshake_types", drop_number_null=True),
        "quic_retry_scid": test_dataframe(joined, "ipfixprobe_quic_retry_scid", "tshark_quic_retry_scid", 0),
        "quic_multiplexed": test_multiplexed(joined, "ipfixprobe_quic_multiplexed", "tshark_quic_multiplexed"),
        "quic_packets": test_dataframe(joined, "ipfixprobe_quic_packets", "tshark_quic_packets"),
    }
    if args.pcap and not has_decryption_secrets(Path(args.pcap)):
        results = skip_without_secrets(results, Path(args.pcap))
    with open(out_path, "w") as file:
        file.write(json.dumps(results))


if __name__ == "__main__":
    main()