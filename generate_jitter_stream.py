#!/usr/bin/env python
"""
Generate jittered JSONL events from dataset rows for Logstash streaming.

This script:
1. Loads rows from a CSV dataset.
2. Drops label/target columns so inference does not leak ground truth.
3. Applies controlled jitter to numeric feature columns.
4. Writes one JSON event per line for file-based ingestion.
"""

import argparse
import json
import random
import re
import sys
import time
from typing import Any

import pandas as pd


DEFAULT_DROP_COLUMNS = {
    "attack_cat",
    "AttackCategory",
    "Label",
    "label",
}

# Columns that are commonly binary/state-like in network datasets.
DEFAULT_NO_JITTER_COLUMNS = {
    "dwin",
    "swin",
    "sttl",
    "dttl",
    "trans_depth",
    "is_ftp_login",
    "ct_ftp_cmd",
    "is_sm_ips_ports",
}


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_integer_like_number(value: Any) -> bool:
    return is_number(value) and float(value).is_integer()


NUMERIC_STRING_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")


def maybe_parse_numeric_string(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    if not NUMERIC_STRING_RE.match(text):
        return value

    try:
        number = float(text)
        if number.is_integer():
            return int(number)
        return number
    except Exception:
        return value


def jitter_numeric(value: Any, jitter_pct: float, preserve_integer: bool = False) -> Any:
    if not is_number(value):
        return value

    factor = 1.0 + random.uniform(-jitter_pct, jitter_pct)
    out = float(value) * factor
    if out < 0:
        out = 0.0
    if preserve_integer:
        return int(round(out))
    return out


def to_json_safe(value: Any) -> Any:
    value = maybe_parse_numeric_string(value)
    if pd.isna(value):
        return 0
    if is_number(value):
        if isinstance(value, float):
            return round(float(value), 6)
        return int(value)
    return str(value)


def detect_low_cardinality_numeric_columns(
    df: pd.DataFrame,
    drop_columns: set[str],
    max_unique_values: int = 4,
) -> set[str]:
    """Detect integer-like numeric columns that behave like discrete states/categories."""
    detected: set[str] = set()

    for col in df.columns:
        if col in drop_columns:
            continue

        series = pd.to_numeric(df[col], errors="coerce").dropna()
        if series.empty:
            continue

        unique_values = series.nunique(dropna=True)
        if unique_values > max_unique_values:
            continue

        # Only protect integer-like low-cardinality fields; continuous features still get jitter.
        all_integer_like = (series % 1 == 0).all()
        if not all_integer_like:
            continue

        detected.add(col)

    return detected


def build_event(
    row: pd.Series,
    jitter_pct: float,
    drop_columns: set[str],
    no_jitter_columns: set[str],
) -> dict[str, Any]:
    event: dict[str, Any] = {}
    for col, raw_value in row.items():
        if col in drop_columns:
            continue
        value = to_json_safe(raw_value)
        if col not in no_jitter_columns:
            value = jitter_numeric(value, jitter_pct, preserve_integer=is_integer_like_number(value))
        event[col] = to_json_safe(value)
    return event


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate jittered JSONL events from dataset rows")
    parser.add_argument("--input", default="merged_dataset.csv", help="Input CSV path")
    parser.add_argument("--output", default="simulated_stream.jsonl", help="Output JSONL path")
    parser.add_argument("--rows", type=int, default=500, help="Number of rows to emit")
    parser.add_argument(
        "--jitter_pct",
        type=float,
        default=0.12,
        help="Numeric jitter percentage as a decimal (0.12 means +/-12%%)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--interval_sec",
        type=float,
        default=0.0,
        help="Sleep duration between emitted events (for live streaming demo)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to output file instead of overwriting",
    )
    parser.add_argument(
        "--no_jitter_columns",
        default="",
        help="Comma-separated extra columns to exclude from jitter",
    )
    parser.add_argument(
        "--forever",
        action="store_true",
        help="Continuously emit events until interrupted (Ctrl+C)",
    )
    args = parser.parse_args()

    if args.rows <= 0:
        print("ERROR: --rows must be > 0", file=sys.stderr)
        sys.exit(1)
    if args.jitter_pct < 0 or args.jitter_pct > 1:
        print("ERROR: --jitter_pct must be between 0 and 1", file=sys.stderr)
        sys.exit(1)
    if args.interval_sec < 0:
        print("ERROR: --interval_sec must be >= 0", file=sys.stderr)
        sys.exit(1)

    random.seed(args.seed)

    try:
        df = pd.read_csv(args.input, low_memory=False)
    except Exception as exc:
        print(f"ERROR: failed to load input CSV '{args.input}': {exc}", file=sys.stderr)
        sys.exit(1)

    if df.empty:
        print("ERROR: input CSV is empty", file=sys.stderr)
        sys.exit(1)

    sample_size = min(args.rows, len(df))
    sampled = df.sample(n=sample_size, random_state=args.seed)

    manual_no_jitter = {
        col.strip() for col in args.no_jitter_columns.split(",") if col.strip()
    }
    auto_no_jitter = detect_low_cardinality_numeric_columns(df, DEFAULT_DROP_COLUMNS)
    no_jitter_columns = DEFAULT_NO_JITTER_COLUMNS | auto_no_jitter | manual_no_jitter

    mode = "a" if args.append else "w"
    with open(args.output, mode, encoding="utf-8") as out_file:
        written = 0
        if args.forever:
            try:
                while True:
                    row = sampled.sample(n=1).iloc[0]
                    event = build_event(
                        row,
                        args.jitter_pct,
                        DEFAULT_DROP_COLUMNS,
                        no_jitter_columns,
                    )
                    out_file.write(json.dumps(event, ensure_ascii=True) + "\n")
                    out_file.flush()
                    written += 1
                    if args.interval_sec > 0:
                        time.sleep(args.interval_sec)
            except KeyboardInterrupt:
                print(f"Stopped by user after writing {written} events to {args.output}")
        else:
            for _, row in sampled.iterrows():
                event = build_event(
                    row,
                    args.jitter_pct,
                    DEFAULT_DROP_COLUMNS,
                    no_jitter_columns,
                )
                out_file.write(json.dumps(event, ensure_ascii=True) + "\n")
                out_file.flush()
                written += 1
                if args.interval_sec > 0:
                    time.sleep(args.interval_sec)

    if not args.forever:
        print(f"Wrote {sample_size} jittered events to {args.output}")
    print(f"Dropped label columns: {sorted(DEFAULT_DROP_COLUMNS)}")
    print(f"Default no-jitter columns ({len(DEFAULT_NO_JITTER_COLUMNS)}): {sorted(DEFAULT_NO_JITTER_COLUMNS)}")
    print(f"Auto-detected low-cardinality no-jitter columns ({len(auto_no_jitter)}): {sorted(auto_no_jitter)}")
    print(f"Manual no-jitter columns ({len(manual_no_jitter)}): {sorted(manual_no_jitter)}")
    print(f"Effective no-jitter columns ({len(no_jitter_columns)}): {sorted(no_jitter_columns)}")


if __name__ == "__main__":
    main()
