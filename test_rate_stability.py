#!/usr/bin/env python
"""Test pipeline stability with new 5.0s LLM interval."""

import json
import time
import requests
import subprocess
import sys
import os

def test_rate_stability():
    """Generate events and check for 429 errors."""
    
    # Verify API is running
    api_url = "http://localhost:5000/analyze_log"
    max_retries = 5
    retries = 0
    
    print("Waiting for API to start...")
    while retries < max_retries:
        try:
            requests.get("http://localhost:5000/health", timeout=1)
            print("✓ API is ready")
            break
        except:
            retries += 1
            if retries < max_retries:
                time.sleep(1)
    
    if retries == max_retries:
        print("✗ API failed to start. Make sure soc_api.py is running.")
        return False
    
    # Test with controlled stream
    test_logs = [
        {"srcip": "192.168.1.10", "dstip": "10.0.0.1", "srcport": 45678, "dstport": 443, "proto": "tcp", "bytes": 512},
        {"srcip": "192.168.1.11", "dstip": "10.0.0.2", "srcport": 53, "dstport": 53, "proto": "udp", "bytes": 256},
        {"srcip": "10.20.30.40", "dstip": "10.0.0.1", "srcport": 12345, "dstport": 22, "proto": "tcp", "bytes": 1024},
    ]
    
    rate_limit_count = 0
    success_count = 0
    throttle_count = 0
    
    print(f"\nPosting {len(test_logs)} logs with 5.5s delay between LLM calls...")
    
    for i, log in enumerate(test_logs):
        try:
            response = requests.post(api_url, json=log, timeout=30)
            data = response.json()
            
            llm_analysis = data.get("llm_analysis", {})
            summary = llm_analysis.get("executive_summary", "")
            
            if "429" in str(data) or "rate_limit" in summary.lower():
                print(f"  [{i+1}] ✗ RATE LIMIT ERROR: {summary[:80]}")
                rate_limit_count += 1
            elif "throttled" in summary.lower():
                print(f"  [{i+1}] ~ THROTTLED: {summary[:80]}")
                throttle_count += 1
            else:
                print(f"  [{i+1}] ✓ OK: {data.get('prediction', 'Unknown')} ({data.get('confidence', 0):.2f})")
                success_count += 1
            
            # Wait 5.5 seconds (slightly longer than 5.0s interval for safety)
            if i < len(test_logs) - 1:
                print(f"       Waiting 5.5s before next LLM call...")
                time.sleep(5.5)
        
        except Exception as e:
            print(f"  [{i+1}] ✗ ERROR: {e}")
    
    # Results
    print(f"\n{'='*60}")
    print(f"Test Results:")
    print(f"  Successful calls (no errors):   {success_count}")
    print(f"  Throttled calls (within timing): {throttle_count}")
    print(f"  Rate limit errors (429):         {rate_limit_count}")
    print(f"{'='*60}")
    
    if rate_limit_count == 0:
        print("✓ PASS: No rate limit errors detected!")
        return True
    else:
        print(f"✗ FAIL: {rate_limit_count} rate limit errors detected")
        return False

if __name__ == "__main__":
    success = test_rate_stability()
    sys.exit(0 if success else 1)
