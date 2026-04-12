#!/usr/bin/env python
"""
Flask API wrapper for the AI SOC helper.

This service loads the model once at startup and exposes a JSON endpoint
for Logstash or any other producer to send individual flow events to.
"""

import logging
import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict

from flask import Flask, jsonify, request

from predict_soc import generate_soc_report, load_model_artifacts, predict_attack, should_call_llm


logging.getLogger("werkzeug").setLevel(logging.ERROR)

app = Flask(__name__)

# Keep API output clean by default; set SOC_DEBUG=1 to see full predictor logs.
QUIET_INFERENCE = os.environ.get("SOC_DEBUG", "0") != "1"
# 5.0 seconds = 12 API calls/minute (60% safety margin below 30/min Groq limit; prioritizes stability over throughput)
LLM_MIN_INTERVAL_SEC = float(os.environ.get("SOC_LLM_MIN_INTERVAL_SEC", "5.0"))
_LLM_LOCK = threading.Lock()
_LAST_LLM_CALL_AT = 0.0
_LLM_COOLDOWN_UNTIL = 0.0

# Load once at startup so we do not re-read the model for every request.
ARTIFACTS = load_model_artifacts("soc_model.pkl")


def run_predict(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    return predict_attack(raw_data, ARTIFACTS, verbose=not QUIET_INFERENCE)


def run_llm(raw_data: Dict[str, Any], prediction: str, confidence: float) -> Dict[str, str]:
    global _LAST_LLM_CALL_AT
    global _LLM_COOLDOWN_UNTIL

    with _LLM_LOCK:
        now = time.time()
        if now < _LLM_COOLDOWN_UNTIL:
            wait_s = max(0.0, _LLM_COOLDOWN_UNTIL - now)
            return {
                "executive_summary": f"LLM skipped due to cooldown ({wait_s:.1f}s remaining).",
                "mitre_technique": "Unknown",
                "firewall_rule_recommendation": "Retry after cooldown or keep current controls.",
            }

        if _LAST_LLM_CALL_AT and now - _LAST_LLM_CALL_AT < LLM_MIN_INTERVAL_SEC:
            wait_s = LLM_MIN_INTERVAL_SEC - (now - _LAST_LLM_CALL_AT)
            return {
                "executive_summary": f"LLM throttled to protect token budget ({wait_s:.1f}s wait).",
                "mitre_technique": "Unknown",
                "firewall_rule_recommendation": "Delay additional LLM calls and continue ML-based triage.",
            }

        _LAST_LLM_CALL_AT = now

    report = generate_soc_report(raw_data, prediction, confidence)

    report_text = json.dumps(report, ensure_ascii=True).lower()
    if "rate_limit_exceeded" in report_text or "error code: 429" in report_text:
        retry_match = re.search(r"try again in\s+([0-9.]+)s", report_text, flags=re.IGNORECASE)
        retry_after = float(retry_match.group(1)) if retry_match else 2.0
        with _LLM_LOCK:
            # Minimal cooldown: only respect the API's retry_after period
            _LLM_COOLDOWN_UNTIL = max(_LLM_COOLDOWN_UNTIL, time.time() + retry_after)

    return report


@app.route("/analyze_log", methods=["POST"])
def analyze_log():
    raw_data = request.get_json(silent=True)
    if not isinstance(raw_data, dict):
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    result = run_predict(raw_data)

    llm_called = should_call_llm(result)
    if llm_called:
        result["llm_analysis"] = run_llm(
            raw_data,
            result["prediction"],
            float(result["confidence"]),
        )
    else:
        result["llm_analysis"] = {
            "executive_summary": "Traffic normal. LLM bypassed.",
            "mitre_technique": "None",
            "firewall_rule_recommendation": "No immediate block action required.",
        }

    print(
        "[SOC] pred={pred} conf={conf:.4f} risk={risk} anomaly={anom:.4f} llm={llm}".format(
            pred=result.get("prediction", "Unknown"),
            conf=float(result.get("confidence", 0.0) or 0.0),
            risk=result.get("risk_level", "Unknown"),
            anom=float(result.get("anomaly_score", 0.0) or 0.0),
            llm="ON" if llm_called else "OFF",
        ),
        file=sys.stdout,
        flush=True,
    )

    if llm_called:
        print("[SOC][LLM]", file=sys.stdout, flush=True)
        print(json.dumps(result["llm_analysis"], ensure_ascii=True), file=sys.stdout, flush=True)

    return jsonify(result), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    print("AI SOC Engine starting...")
    print("Listening on http://127.0.0.1:5000/analyze_log")
    if QUIET_INFERENCE:
        print("Summary mode: ON (set SOC_DEBUG=1 for full predictor logs)")
    app.run(host="127.0.0.1", port=5000)
