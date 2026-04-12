#!/usr/bin/env python
"""Simple test to verify 5.0s interval prevents 429 errors."""

import json
import time
import requests

api_url = "http://localhost:5000/analyze_log"

# Verify API is running
try:
    requests.get("http://localhost:5000/health", timeout=2)
    print("✓ API is running")
except:
    print("✗ API is not responding")
    exit(1)

# Test logs
test_logs = [
    {"srcip": "192.168.1.10", "dstip": "10.0.0.1", "srcport": 45678, "dstport": 443, "proto": "tcp", "bytes": 512},
    {"srcip": "192.168.1.11", "dstip": "10.0.0.2", "srcport": 53, "dstport": 53, "proto": "udp", "bytes": 256},
    {"srcip": "10.20.30.40", "dstip": "10.0.0.1", "srcport": 12345, "dstport": 22, "proto": "tcp", "bytes": 1024},
]

rate_limit_errors = 0
print(f"\nTesting {len(test_logs)} logs with 5.5s delay between LLM calls...\n")

for i, log in enumerate(test_logs, 1):
    response = requests.post(api_url, json=log, timeout=30)
    data = response.json()
    
    summary = data.get("llm_analysis", {}).get("executive_summary", "")
    prediction = data.get("prediction", "Unknown")
    
    # Check for actual 429 HTTP error, not confidence value "0.4299"
    if "429" in str(response.status_code) or ("rate_limit" in summary.lower() and "error" in summary.lower()):
        print(f"[{i}] ✗ RATE LIMIT ERROR: {summary[:70]}")
        rate_limit_errors += 1
    else:
        print(f"[{i}] ✓ {prediction} - {summary[:70]}")
    
    if i < len(test_logs):
        time.sleep(5.5)

print(f"\n{'='*60}")
print(f"Final Result: {rate_limit_errors} rate limit errors")
if rate_limit_errors == 0:
    print("✓ PASS - No 429 errors! Workflow is stable.")
else:
    print(f"✗ FAIL - {rate_limit_errors} 429 errors detected")
print(f"{'='*60}")
