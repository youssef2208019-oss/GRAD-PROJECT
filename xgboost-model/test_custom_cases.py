#!/usr/bin/env python3
"""
Custom Test Cases - Real-World Network Scenarios
Tests 4 specific cases: 2 benign, 2 malicious
"""

import json
from production_ids import ProductionIDSDetector
from wazuh_agent_integration import WazuhFileIntegration

print("=" * 90)
print("🧪 CUSTOM TEST CASES - REAL-WORLD NETWORK SCENARIOS")
print("=" * 90)

# Load AI detector
print("\n1️⃣ Loading AI Models...")
detector = ProductionIDSDetector(
    model_path='xgboost_model_calibrated.pkl',
    features_path='feature_columns.pkl',
    iso_model_path='anomaly_iforest.pkl'
)
print("✅ Models loaded")

# Load Wazuh integration
wazuh = WazuhFileIntegration()

# Define test cases with expected behavior
test_cases = [
    # CASE A: Normal Video Streaming (Safe)
    {
        "name": "CASE A: Normal Video Streaming (Netflix/YouTube)",
        "expected": "BENIGN",
        "flow": {
            "FlowDuration": 58400,           # Lasted 1 minute (convert to ms)
            "TotalFwdPackets": 450,          # Sent a lot
            "TotalBwdPackets": 800,          # Received even more (video data)
            "SourceBytes": 24000,            # Small request
            "DestinationBytes": 1500000,     # Huge reply (video chunks)
            "SourceTTL": 64,                 # Normal Linux/Mac
            "DestinationTTL": 60,            # Normal Server
            "FlowRate": 25000.0,             # Normal speed
            "Protocol": "tcp",
            "Service": "http",
            "State": "FIN"                   # Finished cleanly
        }
    },
    
    # CASE B: UDP Flood DoS Attack (Malicious)
    {
        "name": "CASE B: UDP Flood DoS Attack",
        "expected": "MALICIOUS (DoS)",
        "flow": {
            "FlowDuration": 0.02,            # Instant (microsecond -> ms)
            "TotalFwdPackets": 200,          # Spamming packets
            "TotalBwdPackets": 0,            # Server is too busy to reply
            "SourceBytes": 1000,             # Tiny garbage data
            "DestinationBytes": 0,           # No reply
            "SourceTTL": 254,                # Often indicates spoofed IP
            "DestinationTTL": 0,             # No destination reached
            "FlowRate": 10000000.0,          # Impossible speed (Attack)
            "Protocol": "udp",
            "Service": "dns",
            "State": "INT"                   # Interrupted/Timeout
        }
    },
    
    # CASE C: Normal Web Browsing (Safe)
    {
        "name": "CASE C: Normal Web Browsing (HTTPS)",
        "expected": "BENIGN",
        "flow": {
            "FlowDuration": 500,             # half a second (convert to ms)
            "TotalFwdPackets": 12,
            "TotalBwdPackets": 14,
            "SourceBytes": 1200,
            "DestinationBytes": 4500,        # Loading a webpage
            "SourceTTL": 128,                # Normal Windows PC
            "DestinationTTL": 128,           # Normal Windows Server
            "FlowRate": 52.0,
            "Protocol": "tcp",
            "Service": "-",
            "State": "FIN"
        }
    },
    
    # CASE D: Port Scanning / Probing (Malicious)
    {
        "name": "CASE D: Port Scanning / Reconnaissance",
        "expected": "MALICIOUS (Reconnaissance)",
        "flow": {
            "FlowDuration": 0.01,            # Very short (convert to ms)
            "TotalFwdPackets": 2,            # "Hello?" (SYN)
            "TotalBwdPackets": 0,            # No reply
            "SourceBytes": 0,                # Empty probe
            "DestinationBytes": 0,
            "SourceTTL": 254,                # Suspicious
            "DestinationTTL": 0,
            "FlowRate": 200000.0,
            "Protocol": "tcp",
            "Service": "-",
            "State": "REQ"                   # Request sent, no answer
        }
    },

    # CASE E: FTP Data Transfer (Ambiguous)
    {
        "name": "CASE E: FTP Data Transfer (ftp-data)",
        "expected": "BENIGN",
        "flow": {
            "FlowDuration": 0.005,
            "TotalFwdPackets": 4.0,
            "TotalBwdPackets": 4.0,
            "SourceBytes": 568.0,
            "DestinationBytes": 312.0,
            "SourceTTL": 31.0,
            "DestinationTTL": 29.0,
            "FlowRate": 1400.0,
            "Protocol": "tcp",
            "Service": "ftp-data",
            "State": "FIN"
        }
    },

    # CASE F: UDP Spike with Zero Response (Suspicious)
    {
        "name": "CASE F: UDP Spike (Zero Response)",
        "expected": "MALICIOUS (DoS)",
        "flow": {
            "FlowDuration": 0.000003,
            "TotalFwdPackets": 2.0,
            "TotalBwdPackets": 0.0,
            "SourceBytes": 114.0,
            "DestinationBytes": 0.0,
            "SourceTTL": 254.0,
            "DestinationTTL": 0.0,
            "FlowRate": 333333.0,
            "Protocol": "udp",
            "Service": "dns",
            "State": "INT"
        }
    },

    # CASE G: Normal Short TCP Flow (Benign)
    {
        "name": "CASE G: Normal Short TCP Flow",
        "expected": "BENIGN",
        "flow": {
            "FlowDuration": 1.25,
            "TotalFwdPackets": 10.0,
            "TotalBwdPackets": 8.0,
            "SourceBytes": 1024.0,
            "DestinationBytes": 850.0,
            "SourceTTL": 62.0,
            "DestinationTTL": 252.0,
            "FlowRate": 14.4,
            "Protocol": "tcp",
            "Service": "-",
            "State": "FIN"
        }
    },

    # CASE H: Minimal TCP Probe (Reconnaissance)
    {
        "name": "CASE H: Minimal TCP Probe",
        "expected": "MALICIOUS (Reconnaissance)",
        "flow": {
            "FlowDuration": 0.000009,
            "TotalFwdPackets": 2.0,
            "TotalBwdPackets": 0.0,
            "SourceBytes": 0.0,
            "DestinationBytes": 0.0,
            "SourceTTL": 254.0,
            "DestinationTTL": 0.0,
            "FlowRate": 111111.0,
            "Protocol": "tcp",
            "Service": "-",
            "State": "REQ"
        }
    }
]

print(f"\n2️⃣ Testing {len(test_cases)} Custom Scenarios")
print("=" * 90)

results = []
correct_detections = 0

for idx, test_case in enumerate(test_cases, 1):
    print(f"\n{'='*90}")
    print(f"TEST CASE {idx}: {test_case['name']}")
    print(f"{'='*90}")
    print(f"Expected: {test_case['expected']}")
    
    # Analyze the flow
    alert = detector.predict(test_case['flow'])
    
    # Display results
    print(f"\n📊 DETECTION RESULTS:")
    print(f"   Attack Type:     {alert['attack_type']}")
    
    # Severity with emoji
    severity_emoji = {
        'CRITICAL': '🔥',
        'HIGH': '🔴',
        'MEDIUM': '🟠',
        'LOW': '🟡',
        'NORMAL': '⚪'
    }
    emoji = severity_emoji.get(alert['severity'], '❓')
    print(f"   Severity:        {emoji} {alert['severity']}")
    print(f"   Confidence:      {alert['ensemble_confidence']:.1%}")
    print(f"   Is Attack:       {'YES ⚠️' if alert['is_attack'] else 'NO ✅'}")
    
    print(f"\n🔍 ENSEMBLE BREAKDOWN:")
    print(f"   XGBoost:         {alert.get('xgboost_confidence', 0):.1%} × 0.65 = {alert.get('xgb_contribution', 0):.1%}")
    print(f"   Anomaly Score:   {alert.get('anomaly_score', 0):.1%} × 0.25 = {alert.get('anomaly_contribution', 0):.1%}")
    print(f"   Behavioral Flags: {alert.get('num_flags', 0)}/15 × 0.10 = {alert.get('flags_contribution', 0):.1%}")
    
    if alert.get('flags'):
        print(f"\n🚩 BEHAVIORAL FLAGS DETECTED ({len(alert['flags'])}):")
        for flag in alert['flags']:
            print(f"   • {flag}")
    else:
        print(f"\n🚩 BEHAVIORAL FLAGS: None")
    
    print(f"\n📝 ATTACK DESCRIPTION:")
    print(f"   {alert.get('attack_description', 'N/A')}")
    
    # Determine if detection is correct
    expected_lower = test_case['expected'].lower()
    actual_type = alert['attack_type'].lower()
    
    is_correct = False
    if 'benign' in expected_lower:
        # For benign cases, check if detected as Benign or low confidence
        is_correct = (actual_type == 'benign' or 
                     alert['severity'] == 'NORMAL' or 
                     alert['ensemble_confidence'] < 0.30)
    elif 'dos' in expected_lower:
        is_correct = actual_type == 'dos' or 'dos' in alert.get('attack_description', '').lower()
    elif 'reconnaissance' in expected_lower or 'scan' in expected_lower:
        is_correct = actual_type == 'reconnaissance' or 'scan' in alert.get('attack_description', '').lower()
    
    if is_correct:
        correct_detections += 1
        print(f"\n✅ VERDICT: CORRECT DETECTION!")
    else:
        print(f"\n⚠️  VERDICT: Unexpected result (expected {test_case['expected']})")
    
    results.append({
        'case': test_case['name'],
        'expected': test_case['expected'],
        'detected': alert['attack_type'],
        'severity': alert['severity'],
        'confidence': alert['ensemble_confidence'],
        'correct': is_correct,
        'alert': alert
    })

# Summary
print(f"\n{'='*90}")
print("📊 SUMMARY OF CUSTOM TEST CASES")
print(f"{'='*90}")

accuracy = (correct_detections / len(test_cases)) * 100
print(f"\n🎯 Accuracy: {correct_detections}/{len(test_cases)} ({accuracy:.0f}%)")

print(f"\n📋 Detailed Results:")
for idx, result in enumerate(results, 1):
    status = "✅ PASS" if result['correct'] else "❌ FAIL"
    print(f"\n{idx}. {result['case'][:50]}")
    print(f"   Expected:  {result['expected']}")
    print(f"   Detected:  {result['detected']} ({result['severity']}) - {result['confidence']:.1%}")
    print(f"   Status:    {status}")

# Ask to send to Wazuh
print(f"\n{'='*90}")
send = input("\n📤 Send all test cases to Wazuh Dashboard? (y/n): ").strip().lower()

if send == 'y':
    print("\n3️⃣ SENDING TO WAZUH...")
    for result in results:
        wazuh.send_alert(result['alert'])
    
    print(f"✅ Sent {len(results)} alerts to Wazuh")
    print(f"\n📊 Check Wazuh Dashboard:")
    print(f"   • Navigate to: Security Events")
    print(f"   • Filter: agent.id: \"001\"")
    print(f"   • Time: Last 15 minutes")
    print(f"\n   Expected alerts:")
    for result in results:
        print(f"   • {result['detected']:20s} ({result['severity']:8s}) - {result['case'][:40]}")
else:
    print("\n⏭️  Skipped Wazuh integration")

print(f"\n{'='*90}")
print("✅ CUSTOM TEST CASES COMPLETE!")
print(f"{'='*90}")
