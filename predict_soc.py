#!/usr/bin/env python
"""
AI SOC Helper - Real-time Network Intrusion Prediction for Wazuh Integration

This script loads the trained XGBoost model and predicts attack types for single log entries.
Designed to integrate with Wazuh SIEM for real-time threat detection.

Usage:
    python predict_soc.py --log '{"Protocol": "tcp", "Service": "http", "SourceBytes": 500, ...}'
    
Output:
    {"prediction": "DoS", "confidence": 0.92, "risk_level": "High"}
"""

import argparse
import json
import sys
import numpy as np
import pandas as pd
import joblib
from typing import Dict, Any
import warnings

warnings.filterwarnings('ignore')


def map_log_fields(log_data: Dict[str, Any]) -> Dict[str, Any]:
    """Map common field names to training dataset column names."""
    field_map = {
        'SourceBytes': 'sbytes',
        'DestinationBytes': 'dbytes',
        'SourceTTL': 'sttl',
        'DestinationTTL': 'dttl',
        'FlowDuration': 'dur',
        'TotalFwdPackets': 'Spkts',
        'TotalBwdPackets': 'Dpkts',
        'Protocol': 'proto',
        'Service': 'service',
        'State': 'state',
        'SourcePort': 'sport',
        'DestinationPort': 'dsport',
        'SourcePackets': 'sinpkt',
        'DestinationPackets': 'dinpkt',
        'SourceLoad': 'sload',
        'DestinationLoad': 'dload',
        'SourceJitter': 'sjit',
        'DestinationJitter': 'djit',
        'SourceWindow': 'swin',
        'DestinationWindow': 'dwin',
        'SourceLoss': 'sloss',
        'DestinationLoss': 'dloss',
    }

    mapped_log = {}
    for key, value in log_data.items():
        mapped_key = field_map.get(key, key)
        mapped_log[mapped_key] = value

    return mapped_log


def load_model_artifacts(model_path: str = 'soc_model.pkl') -> Dict[str, Any]:
    """
    Load trained model and all preprocessing artifacts.
    
    Returns:
        Dict containing: model, label_encoders, scaler, attack_cat_mapping, class_names, feature_names
    """
    try:
        artifacts = joblib.load(model_path)
        print(f"✓ Model loaded from {model_path}", file=sys.stderr)
        print(f"  Features: {len(artifacts['feature_names'])}", file=sys.stderr)
        print(f"  Classes: {list(artifacts['class_names'].values())}", file=sys.stderr)
        return artifacts
    except FileNotFoundError:
        print(f"ERROR: Model file '{model_path}' not found.", file=sys.stderr)
        print(f"Run 'python train_soc_model.py --data merged_dataset.csv' first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to load model: {e}", file=sys.stderr)
        sys.exit(1)


def preprocess_log(log_data: Dict[str, Any], artifacts: Dict[str, Any]) -> np.ndarray:
    """
    Preprocess a single log entry to match training pipeline:
    1. Map field names from common formats to training names
    2. Convert to DataFrame
    3. Encode categorical features
    4. Create engineered features (CRITICAL - must match training)
    5. Scale numerical features
    6. Ensure correct feature order
    
    Args:
        log_data: Raw log entry as dict
        artifacts: Loaded model artifacts
        
    Returns:
        Preprocessed feature array ready for prediction
    """
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame([log_data])

    # Extract artifacts
    label_encoders = artifacts['label_encoders']
    scaler = artifacts['scaler']
    feature_names = artifacts['feature_names']

    # --- DYNAMIC MAPPING FIX ---
    # Create a map based on what the MODEL expects
    model_features = set(feature_names)
    dynamic_map = {}

    # Common variations to check
    potential_mappings = {
        'Service': ['service', 'SERVICE'],
        'Protocol': ['proto', 'PROTO', 'protocol'],
        'State': ['state', 'STATE'],
        'SourceBytes': ['sbytes', 'SBytes', 'src_bytes'],
        'DestinationBytes': ['dbytes', 'DBytes', 'dst_bytes'],
        'SourceTTL': ['sttl', 'STTL'],
        'DestinationTTL': ['dttl', 'DTTL'],
        'FlowDuration': ['dur', 'DUR', 'duration'],
        'TotalFwdPackets': ['Spkts', 'spkts'],
        'TotalBwdPackets': ['Dpkts', 'dpkts']
    }

    # Build the map: If model wants 'Service', map 'service' -> 'Service'
    for target, variations in potential_mappings.items():
        if target in model_features:
            for var in variations:
                dynamic_map[var] = target
        elif target.lower() in model_features:
            dynamic_map[target] = target.lower()
            for var in variations:
                dynamic_map[var] = target.lower()

    # Apply the map
    df = df.rename(columns=dynamic_map)
    # ---------------------------

    print(f"  Raw log columns: {list(log_data.keys())}", file=sys.stderr)
    print(f"  Mapped columns: {df.columns.tolist()}", file=sys.stderr)

    # STEP 1: Encode categorical features
    categorical_cols = [c for c in label_encoders.keys() if c in df.columns]
    
    for col in categorical_cols:
        if col in df.columns and col in label_encoders:
            le = label_encoders[col]
            value = str(df[col].iloc[0])
            
            # Handle unseen labels gracefully
            if value in le.classes_:
                df[col] = le.transform([value])[0]
            else:
                # Assign to most common class (index 0) or use -1
                print(f"  WARNING: Unseen value '{value}' for '{col}', using default (0)", file=sys.stderr)
                df[col] = 0
        elif col in label_encoders:
            # Column missing from log but encoder exists - fill with default
            df[col] = 0
    
    # STEP 2: Convert all columns to numeric (handle missing values)
    for col in df.columns:
        try:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        except:
            pass
    
    df = df.fillna(0)
    
    # STEP 3: CRITICAL - Create the same 8 engineered features from training
    print(f"  Creating engineered features...", file=sys.stderr)
    
    # Feature 1: sbytes_per_pkt
    if 'sbytes' in df.columns and 'sinpkt' in df.columns:
        df['sbytes_per_pkt'] = df['sbytes'] / (df['sinpkt'] + 1e-6)
    else:
        df['sbytes_per_pkt'] = 0
    
    # Feature 2: dbytes_per_pkt
    if 'dbytes' in df.columns and 'dinpkt' in df.columns:
        df['dbytes_per_pkt'] = df['dbytes'] / (df['dinpkt'] + 1e-6)
    else:
        df['dbytes_per_pkt'] = 0
    
    # Feature 3: pkts_rate
    if 'sinpkt' in df.columns and 'dinpkt' in df.columns and 'dur' in df.columns:
        df['pkts_rate'] = (df['sinpkt'] + df['dinpkt']) / (df['dur'] + 1e-6)
    else:
        df['pkts_rate'] = 0
    
    # Feature 4: tcp_flag_ratio
    if 'synack' in df.columns and 'ackdat' in df.columns:
        df['tcp_flag_ratio'] = df['synack'] / (df['ackdat'] + 1e-6)
    else:
        df['tcp_flag_ratio'] = 0
    
    # Feature 5: loss_ratio
    if 'sloss' in df.columns and 'dloss' in df.columns and 'sinpkt' in df.columns and 'dinpkt' in df.columns:
        df['loss_ratio'] = (df['sloss'] + df['dloss']) / (df['sinpkt'] + df['dinpkt'] + 1e-6)
    else:
        df['loss_ratio'] = 0
    
    # Feature 6: jitter_ratio
    if 'sjit' in df.columns and 'djit' in df.columns and 'dur' in df.columns:
        df['jitter_ratio'] = (df['sjit'] + df['djit']) / (df['dur'] + 1e-6)
    else:
        df['jitter_ratio'] = 0
    
    # Feature 7: window_ratio
    if 'swin' in df.columns and 'dwin' in df.columns:
        df['window_ratio'] = df['swin'] / (df['dwin'] + 1e-6)
    else:
        df['window_ratio'] = 0
    
    # Feature 8: ttl_diff
    if 'sttl' in df.columns and 'dttl' in df.columns:
        df['ttl_diff'] = abs(df['sttl'] - df['dttl'])
    else:
        df['ttl_diff'] = 0
    
    # Clean inf/NaN from ratios
    df = df.replace([np.inf, -np.inf], 0).fillna(0)
    
    # --- FIX: ALIGN COLUMNS WITH TRAINING DATA ---
    # Remove duplicate columns if any (can cause feature count mismatch)
    if df.columns.duplicated().any():
        dup_cols = df.columns[df.columns.duplicated()].unique().tolist()
        print(f"  WARNING: Dropping duplicate columns: {dup_cols}", file=sys.stderr)
        df = df.loc[:, ~df.columns.duplicated()]
    # Prefer scaler's feature names if available to avoid mismatch
    if hasattr(scaler, 'feature_names_in_') and len(scaler.feature_names_in_) > 0:
        expected_features = list(scaler.feature_names_in_)
    else:
        expected_features = list(feature_names)
        if hasattr(scaler, 'n_features_in_') and len(expected_features) != scaler.n_features_in_:
            print(
                f"  WARNING: feature_names length ({len(expected_features)}) != scaler expects ({scaler.n_features_in_}).",
                file=sys.stderr
            )
            expected_features = expected_features[:scaler.n_features_in_]

    # De-duplicate expected features while preserving order
    seen = set()
    expected_features = [f for f in expected_features if not (f in seen or seen.add(f))]

    # Ensure all expected features exist, fill missing with 0
    missing_features = []
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0
            missing_features.append(col)

    # DROP extra columns that weren't in training (like 'Label', 'AttackCategory')
    df = df[expected_features]  # <--- THIS FORCES THE EXACT ORDER

    if missing_features:
        print(f"  WARNING: {len(missing_features)} features missing from log (filled with 0)", file=sys.stderr)
        if len(missing_features) <= 5:
            print(f"    Missing: {missing_features}", file=sys.stderr)

    print(f"✓ Columns aligned. Order: {df.columns.tolist()[:5]}...", file=sys.stderr)
    # ---------------------------------------------

    # STEP 5: Scale using trained scaler
    X_scaled = scaler.transform(df)
    
    print(f"  ✓ Preprocessed: {X_scaled.shape[1]} features", file=sys.stderr)
    
    return X_scaled


def predict_attack(log_data: Dict[str, Any], artifacts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Predict attack type for a single log entry.
    
    Args:
        log_data: Raw log entry as dict
        artifacts: Loaded model artifacts
        
    Returns:
        Dict with prediction, confidence, and risk_level
    """
    # Preprocess log
    X = preprocess_log(log_data, artifacts)
    
    # Get model
    model = artifacts['model']
    class_names = artifacts['class_names']
    
    # Predict
    y_pred = model.predict(X)[0]
    y_proba = model.predict_proba(X)[0]
    
    # Convert numpy types to native Python types
    y_pred = int(y_pred)
    
    # Build complete class names (handle missing "Other" class)
    # Model has 7 classes but class_names might only have 6
    all_class_names = class_names.copy()
    if y_pred not in all_class_names:
        # Add missing class (likely "Other" at index 6)
        all_class_names[y_pred] = 'Other'
        print(f"  WARNING: Class index {y_pred} missing, using 'Other'", file=sys.stderr)
    
    predicted_class = all_class_names[y_pred]

    # Build probability map
    probs = {
        all_class_names.get(i, f'Class_{i}'): float(prob)
        for i, prob in enumerate(y_proba)
    }

    # --- AGGREGATED ATTACK LOGIC ---
    p_normal = probs.get('Normal', 0.0)
    p_attack = 1.0 - p_normal  # Sum of all other classes
    risk_score = p_attack
    
    predicted_class = None
    confidence = None
    risk_level = None
    
    if p_attack > p_normal:
        # It IS an attack (Majority vote).
        # Find the specific attack with the highest score.
        best_attack = None
        max_prob = -1.0
        
        for cls, p in probs.items():
            if cls != 'Normal' and cls != 'Other' and p > max_prob:
                max_prob = p
                best_attack = cls
        
        if best_attack:
            print(f"⚠️ Vote Split Detected! Normal ({p_normal:.2f}) < Total Attack ({p_attack:.2f}).", file=sys.stderr)
            print(f"   -> Overriding prediction to: {best_attack}", file=sys.stderr)
            predicted_class = best_attack
            confidence = max_prob
            risk_level = "High (Aggregated Confidence)"
        else:
            # All attack classes are "Other" - still attack but low specificity
            predicted_class = 'Other'
            confidence = p_attack
            risk_level = "High (Unclassified Attack)"
    else:
        # Normal traffic (Normal > all attacks combined)
        predicted_class = 'Normal'
        confidence = p_normal
        risk_level = 'Low' if p_normal >= 0.50 else 'Medium (Low Confidence)'
    # -------------------------------
    
    # --- MAPPING FIX ---
    class_display_map = {
        'Class_6': 'Analysis',
        'Class_7': 'Backdoor'
    }
    predicted_class = class_display_map.get(predicted_class, predicted_class)

    # Return JSON-serializable result
    result = {
        'prediction': predicted_class,
        'confidence': round(confidence, 4),
        'risk_level': risk_level,
        'anomaly_score': round(risk_score, 4),
        'probabilities': {
            class_display_map.get(all_class_names.get(i, f'Class_{i}'), all_class_names.get(i, f'Class_{i}')): round(float(prob), 4) 
            for i, prob in enumerate(y_proba)
        }
    }
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Predict network intrusion type for Wazuh SOC integration'
    )
    parser.add_argument(
        '--log',
        type=str,
        required=False,
        help='JSON string of log entry (e.g., \'{"Protocol": "tcp", "Service": "http", ...}\')'
    )
    parser.add_argument(
        '--log_file',
        type=str,
        default=None,
        help='Path to JSON file containing a single log entry'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='soc_model.pkl',
        help='Path to trained model pickle file (default: soc_model.pkl)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed preprocessing info'
    )
    
    args = parser.parse_args()

    if not args.log and not args.log_file:
        parser.error("one of --log or --log_file is required")
    
    # Suppress stderr unless verbose
    if not args.verbose:
        sys.stderr = open('nul' if sys.platform == 'win32' else '/dev/null', 'w')
    
    try:
        # Parse JSON log
        try:
            if args.log_file:
                try:
                    with open(args.log_file, 'r', encoding='utf-8-sig') as f:
                        log_text = f.read()
                except UnicodeDecodeError:
                    with open(args.log_file, 'r', encoding='utf-16') as f:
                        log_text = f.read()
            elif args.log.startswith('@'):
                file_path = args.log[1:]
                try:
                    with open(file_path, 'r', encoding='utf-8-sig') as f:
                        log_text = f.read()
                except UnicodeDecodeError:
                    with open(file_path, 'r', encoding='utf-16') as f:
                        log_text = f.read()
            else:
                log_text = args.log

            # Strip BOM/whitespace that can appear from PowerShell file reads
            log_text = log_text.lstrip("\ufeff").strip()
            if args.verbose:
                print(f"  Raw log string (repr): {log_text!r}", file=sys.stderr)
            log_data = json.loads(log_text)
        except json.JSONDecodeError as e:
            print(json.dumps({'error': f'Invalid JSON: {e}'}))
            sys.exit(1)
        
        # Load model
        artifacts = load_model_artifacts(args.model)
        
        # Predict
        result = predict_attack(log_data, artifacts)
        
        # Output strict JSON for Wazuh parsing
        print(json.dumps(result, indent=2 if args.verbose else None))
        
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


if __name__ == '__main__':
    main()
