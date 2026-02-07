#!/usr/bin/env python3
"""
Comprehensive Scenario Testing v4.0
Uses REAL attack samples from dataset + synthetic normal traffic
Tests all 4 severity levels and diverse attack types
"""

import json
import pandas as pd
import numpy as np
from production_ids import ProductionIDSDetector
from wazuh_agent_integration import WazuhFileIntegration
from collections import defaultdict

print("=" * 90)
print("🎯 COMPREHENSIVE SCENARIO TESTING V4.0")
print("=" * 90)

# Load AI model
print("\n1️⃣ Loading Enhanced AI Models...")
detector = ProductionIDSDetector(
    model_path='xgboost_model_calibrated.pkl',
    features_path='feature_columns.pkl',
    iso_model_path='anomaly_iforest.pkl'
)

print(f"✅ Models loaded")
print(f"   Thresholds: CRITICAL≥{detector.SEVERITY_CRITICAL} | HIGH≥{detector.SEVERITY_HIGH} | MEDIUM≥{detector.SEVERITY_MEDIUM} | LOW≥{detector.SEVERITY_LOW}")

# Load Wazuh
wazuh = WazuhFileIntegration()

# Load real attack dataset
print("\n2️⃣ Loading Real Attack Dataset...")
df = pd.read_json('test.json', lines=True)
print(f"✅ Loaded {len(df)} samples")

attack_categories = df['AttackCategory'].value_counts()
print(f"\n📊 Attack Categories Available:")
for cat, count in attack_categories.items():
    if str(cat) not in ['Normal', 'attack_cat']:
        print(f"   • {str(cat):20s}: {count:5d} samples")

print("\n3️⃣ Selecting Representative Samples...")
print("=" * 90)

# Select diverse samples from real attacks
selected_samples = []

# Strategy: Pick samples with varying characteristics for each category
for category in attack_categories.index:
    cat_str = str(category)
    if cat_str in ['Normal', 'attack_cat']:
        continue
    
    cat_df = df[df['AttackCategory'] == category]
    
    # Sample different confidence levels by selecting diverse flows
    # Get samples with varying packet counts
    sorted_by_packets = cat_df.sort_values('TotalFwdPackets')
    
    indices = []
    n_samples = min(3, len(sorted_by_packets))
    
    if n_samples == 3:
        # Low, medium, high packet count samples
        indices = [0, len(sorted_by_packets)//2, len(sorted_by_packets)-1]
    elif n_samples == 2:
        indices = [0, len(sorted_by_packets)-1]
    elif n_samples == 1:
        indices = [len(sorted_by_packets)//2]
    
    for idx in indices:
        sample = sorted_by_packets.iloc[idx].to_dict()
        sample['original_category'] = cat_str
        selected_samples.append(sample)

print(f"✅ Selected {len(selected_samples)} real attack samples")

# Add synthetic normal traffic that should NOT trigger
print(f"\n4️⃣ Adding Synthetic Normal Traffic Baseline...")

normal_samples = [
    {
        'FlowDuration': 5000, 'TotalFwdPackets': 15, 'TotalBwdPackets': 12,
        'SourceBytes': 2400, 'DestinationBytes': 18500, 'FlowRate': 5400,
        'Protocol': 'tcp', 'State': 'FIN', 'synack': 1, 'ackdat': 1,
        'original_category': 'Normal-HTTPBrowsing', 'scenario': 'Normal HTTP browsing'
    },
    {
        'FlowDuration': 120000, 'TotalFwdPackets': 85, 'TotalBwdPackets': 1200,
        'SourceBytes': 12000, 'DestinationBytes': 985000, 'FlowRate': 8208,
        'Protocol': 'tcp', 'State': 'CON', 'synack': 1, 'ackdat': 1,
        'original_category': 'Normal-Streaming', 'scenario': 'Video streaming'
    },
    {
        'FlowDuration': 250, 'TotalFwdPackets': 1, 'TotalBwdPackets': 1,
        'SourceBytes': 68, 'DestinationBytes': 152, 'FlowRate': 880,
        'Protocol': 'udp', 'State': 'INT',
        'original_category': 'Normal-DNS', 'scenario': 'DNS lookup'
    },
]

selected_samples.extend(normal_samples)

print(f"✅ Added {len(normal_samples)} normal traffic samples")
print(f"\n📋 Total Test Scenarios: {len(selected_samples)}")

# ============================================================================
# ANALYZE ALL SAMPLES
# ============================================================================
print("\n" + "=" * 90)
print("5️⃣ ANALYZING ALL SAMPLES")
print("=" * 90)

# Track results by severity
severity_counts = defaultdict(int)
attack_type_counts = defaultdict(int)
category_mapping = defaultdict(list)

detailed_results = []

for idx, sample in enumerate(selected_samples, 1):
    # Analyze
    alert = detector.predict(sample)
    
    original_cat = sample.get('original_category', 'Unknown')
    scenario = sample.get('scenario', original_cat)
    
    severity_counts[alert['severity']] += 1
    attack_type_counts[alert['attack_type']] += 1
    category_mapping[original_cat].append({
        'detected': alert['attack_type'],
        'severity': alert['severity'],
        'confidence': alert['ensemble_confidence']
    })
    
    # Detailed result
    detailed_results.append({
        'id': idx,
        'original': original_cat,
        'scenario': scenario,
        'detected_type': alert['attack_type'],
        'severity': alert['severity'],
        'confidence': alert['ensemble_confidence'],
        'xgb': alert.get('xgb_contribution', 0),
        'anomaly': alert.get('anomaly_contribution', 0),
        'flags': alert.get('flags_contribution', 0),
        'alert': alert
    })
    
    # Print with color coding
    severity_emoji = {
        'NORMAL': '⚪',
        'LOW': '🟡',
        'MEDIUM': '🟠',
        'HIGH': '🔴',
        'CRITICAL': '🔥'
    }
    
    emoji = severity_emoji.get(alert['severity'], '❓')
    
    print(f"\n{idx:2d}. {scenario[:60]}")
    print(f"    Original: {original_cat}")
    print(f"    Detected: {alert['attack_type']:20s} | {emoji} {alert['severity']:8s} ({alert['ensemble_confidence']:.1%})")
    print(f"    Ensemble: XGB={alert.get('xgb_contribution', 0):.1%} | Anomaly={alert.get('anomaly_contribution', 0):.1%} | Flags={alert.get('flags_contribution', 0):.1%}")

# ============================================================================
# SUMMARY STATISTICS
# ============================================================================
print("\n" + "=" * 90)
print("📊 DETECTION SUMMARY")
print("=" * 90)

print(f"\n🎯 Severity Distribution:")
for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL']:
    count = severity_counts[severity]
    percentage = (count / len(selected_samples) * 100) if len(selected_samples) > 0 else 0
    bar = '█' * int(percentage / 2)
    print(f"  {severity:10s}: {count:3d} ({percentage:5.1f}%) {bar}")

print(f"\n🔍 Attack Types Detected:")
for attack_type, count in sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True):
    percentage = (count / len(selected_samples) * 100) if len(selected_samples) > 0 else 0
    print(f"  • {attack_type:20s}: {count:3d} ({percentage:5.1f}%)")

print(f"\n📋 Original Category → Detection Mapping:")
for original_cat, detections in sorted(category_mapping.items()):
    if len(detections) > 0:
        detected_types = [d['detected'] for d in detections]
        severities = [d['severity'] for d in detections]
        
        # Most common detection
        most_common_type = max(set(detected_types), key=detected_types.count)
        most_common_sev = max(set(severities), key=severities.count)
        
        print(f"  {original_cat:25s} → {most_common_type:20s} ({most_common_sev:8s}) [{len(detections)} samples]")

# ============================================================================
# DIVERSITY CHECK
# ============================================================================
print("\n" + "=" * 90)
print("✅ DIVERSITY VERIFICATION")
print("=" * 90)

has_critical = severity_counts['CRITICAL'] > 0
has_high = severity_counts['HIGH'] > 0
has_medium = severity_counts['MEDIUM'] > 0
has_low = severity_counts['LOW'] > 0
has_normal = severity_counts['NORMAL'] > 0

diverse_attacks = len(attack_type_counts) - (1 if 'Benign' in attack_type_counts else 0)

print(f"\n✓ Severity Levels Found:")
print(f"  {'✅' if has_critical else '❌'} CRITICAL: {severity_counts['CRITICAL']} samples")
print(f"  {'✅' if has_high else '❌'} HIGH:     {severity_counts['HIGH']} samples")
print(f"  {'✅' if has_medium else '❌'} MEDIUM:   {severity_counts['MEDIUM']} samples")
print(f"  {'✅' if has_low else '❌'} LOW:      {severity_counts['LOW']} samples")
print(f"  {'✅' if has_normal else '❌'} NORMAL:   {severity_counts['NORMAL']} samples")

print(f"\n✓ Attack Diversity:")
print(f"  {'✅' if diverse_attacks >= 4 else '⚠️ '} {diverse_attacks} different attack types detected")
print(f"  {'✅' if has_normal else '❌'} Normal traffic classification working")

all_severity_levels = has_critical and has_high and has_medium and has_low
diversity_good = diverse_attacks >= 4

if all_severity_levels and diversity_good:
    print(f"\n🎉 EXCELLENT: All 4 severity levels present with diverse attack types!")
elif has_medium or has_high:
    print(f"\n⚠️  NEEDS IMPROVEMENT: Missing some severity levels or diversity")
else:
    print(f"\n❌ POOR: Model not detecting attacks properly - needs retuning")

# ============================================================================
# SEND TO WAZUH
# ============================================================================
print("\n" + "=" * 90)
send = input("\n📤 Send all scenarios to Wazuh Dashboard? (y/n): ").strip().lower()

if send == 'y':
    print("\n6️⃣ SENDING TO WAZUH...")
    for result in detailed_results:
        wazuh.send_alert(result['alert'])
    
    print(f"✅ Sent {len(detailed_results)} alerts to Wazuh")
    print(f"\n📊 Check Wazuh Dashboard:")
    print(f"   • Navigate to: Security Events")
    print(f"   • Filter: agent.name = 'macos-xgboost-ids'")
    print(f"   • Look for rule IDs: 100100-100202")
    print(f"   • Expected distribution:")
    for severity, count in sorted(severity_counts.items(), key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','NORMAL'].index(x[0]) if x[0] in ['CRITICAL','HIGH','MEDIUM','LOW','NORMAL'] else 99):
        if count > 0:
            print(f"      - {severity:10s}: ~{count} alerts")
else:
    print("\n⏭️  Skipped Wazuh integration")

print("\n" + "=" * 90)
print("✅ COMPREHENSIVE SCENARIO TESTING COMPLETE!")
print("=" * 90)
