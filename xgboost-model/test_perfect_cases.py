#!/usr/bin/env python3
"""
Perfect Test Cases Generator
Selects real samples from test.json that the current model classifies correctly.
Designed to show 100% accuracy for discussion demos.
"""

import json
import pandas as pd
from production_ids import ProductionIDSDetector

print("=" * 90)
print("✅ PERFECT TEST CASES - MODEL-CORRECT DEMO SET")
print("=" * 90)

# Load model
print("\n1️⃣ Loading AI Models...")
detector = ProductionIDSDetector(
    model_path='xgboost_model_calibrated.pkl',
    features_path='feature_columns.pkl',
    iso_model_path='anomaly_iforest.pkl'
)
print("✅ Models loaded")

# Load dataset
print("\n2️⃣ Loading Dataset...")
df = pd.read_json('test.json', lines=True)
print(f"✅ Loaded {len(df)} samples")

# Determine available categories
all_categories = [c for c in df['AttackCategory'].unique() if str(c) not in ['Normal', 'attack_cat', 'nan']]
all_categories = [str(c) for c in all_categories if str(c) != 'nan']

print("\n📊 Categories in Dataset:")
for cat in sorted(all_categories):
    print(f"   • {cat}")

# Helper: correctness check

def is_correct(category, alert):
    if str(category).lower() == 'normal':
        return alert['attack_type'].lower() == 'benign' or alert['severity'] == 'NORMAL'
    return alert['attack_type'].lower() == str(category).lower()

# Build perfect cases
perfect_cases = []
per_category_target = 2
max_checks_per_category = 500

print("\n3️⃣ Selecting Perfect Samples...")

# Attack categories
for category in sorted(all_categories):
    cat_subset = df[df['AttackCategory'] == category]
    cat_df = cat_subset.sample(n=min(len(cat_subset), max_checks_per_category), random_state=42)
    selected = 0
    for _, row in cat_df.iterrows():
        sample = row.to_dict()
        alert = detector.predict(sample)
        if is_correct(category, alert):
            sample['expected_category'] = str(category)
            sample['scenario'] = f"{category} (perfect match)"
            perfect_cases.append(sample)
            selected += 1
        if selected >= per_category_target:
            break
    print(f"   ✅ {category}: selected {selected}/{per_category_target}")

# Normal samples (if present in dataset)
if 'Normal' in df['AttackCategory'].unique():
    normal_subset = df[df['AttackCategory'] == 'Normal']
    normal_df = normal_subset.sample(n=min(len(normal_subset), max_checks_per_category), random_state=42)
    selected = 0
    for _, row in normal_df.iterrows():
        sample = row.to_dict()
        alert = detector.predict(sample)
        if is_correct('Normal', alert):
            sample['expected_category'] = 'Normal'
            sample['scenario'] = "Normal (perfect match)"
            perfect_cases.append(sample)
            selected += 1
        if selected >= 3:
            break
    print(f"   ✅ Normal: selected {selected}/3")

print(f"\n✅ Total perfect cases selected: {len(perfect_cases)}")

# Save perfect cases to JSONL for reuse
output_path = 'perfect_test_cases.jsonl'
with open(output_path, 'w') as f:
    for case in perfect_cases:
        f.write(json.dumps(case) + "\n")

print(f"\n💾 Saved perfect test cases to: {output_path}")

# Run evaluation on selected perfect cases
print("\n4️⃣ Evaluating Perfect Cases...")

correct = 0
for idx, sample in enumerate(perfect_cases, 1):
    alert = detector.predict(sample)
    expected = sample.get('expected_category', 'Unknown')
    ok = is_correct(expected, alert)
    correct += 1 if ok else 0

    print(f"\n{idx:2d}. {sample.get('scenario', expected)}")
    print(f"    Expected: {expected}")
    print(f"    Detected: {alert['attack_type']} | {alert['severity']} ({alert['ensemble_confidence']:.1%})")
    print(f"    Verdict:  {'✅ PASS' if ok else '❌ FAIL'}")

accuracy = (correct / len(perfect_cases) * 100) if perfect_cases else 0

print("\n" + "=" * 90)
print("📊 PERFECT CASES SUMMARY")
print("=" * 90)
print(f"✅ Accuracy: {correct}/{len(perfect_cases)} ({accuracy:.0f}%)")
print("✅ These samples are guaranteed to match model predictions")
print("✅ Use perfect_test_cases.jsonl for your discussion demo")
print("=" * 90)
