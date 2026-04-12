#!/usr/bin/env python
"""Standalone Groq LLM smoke test for SOC report generation.

This script bypasses the model/pipeline and calls the LLM helper directly.
"""

import argparse
import json
import os
import sys

from predict_soc import generate_soc_report, get_groq_client


DEFAULT_SAMPLE = {
    "Protocol": "tcp",
    "Service": "http",
    "SourceBytes": 1540,
    "DestinationBytes": 220,
    "FlowDuration": 0.42,
    "State": "CON",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone LLM-only SOC smoke test")
    parser.add_argument("--prediction", default="Exploits", help="Predicted class label")
    parser.add_argument("--confidence", type=float, default=0.91, help="Prediction confidence")
    parser.add_argument(
        "--log",
        default=None,
        help="Optional JSON string for the raw log sample",
    )
    args = parser.parse_args()

    raw_log = DEFAULT_SAMPLE
    if args.log:
        try:
            raw_log = json.loads(args.log)
        except json.JSONDecodeError as exc:
            print(json.dumps({"error": f"Invalid JSON in --log: {exc}"}, indent=2))
            sys.exit(1)

    api_key_present = bool(os.getenv("GROQ_API_KEY"))
    groq_client = get_groq_client()

    print(
        json.dumps(
            {
                "groq_package_available": groq_client is not None,
                "groq_api_key_present": api_key_present,
                "prediction": args.prediction,
                "confidence": round(args.confidence, 4),
            },
            indent=2,
        )
    )

    report = generate_soc_report(raw_log, args.prediction, args.confidence)
    print("\nLLM Report:\n")
    print(report)


if __name__ == "__main__":
    main()
