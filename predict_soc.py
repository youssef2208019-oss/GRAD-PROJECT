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
import os
import sys
import numpy as np
import pandas as pd
import joblib
from typing import Dict, Any
import warnings

warnings.filterwarnings('ignore')

try:
    from groq import Groq
except Exception:
    Groq = None


# --- MITRE ATT&CK MAPPING ---
mitre_mapping = {
    "Reconnaissance": {
        "tactic": "Reconnaissance (TA0043)",
        "technique": "Active Scanning (T1595)",
        "url": "https://attack.mitre.org/techniques/T1595/"
    },
    "Exploits": {
        "tactic": "Initial Access (TA0001)",
        "technique": "Exploit Public-Facing Application (T1190)",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "DoS": {
        "tactic": "Impact (TA0040)",
        "technique": "Network Denial of Service (T1498)",
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "Fuzzers": {
        "tactic": "Impact (TA0040)",
        "technique": "Endpoint Denial of Service (T1499)",
        "url": "https://attack.mitre.org/techniques/T1499/"
    },
    "Generic": {
        "tactic": "Execution (TA0002)",
        "technique": "Command and Scripting Interpreter (T1059)",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "Analysis": {
        "tactic": "Discovery (TA0007)",
        "technique": "Network Service Discovery (T1046)",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "Normal": {
        "tactic": "None",
        "technique": "None",
        "url": "None"
    }
}

# Keep the LLM for genuinely uncertain normal cases so we do not burn quota.
# Thresholds are conservative to stay well below 30 calls/minute Groq limit.
NORMAL_LLM_CONFIDENCE_THRESHOLD = 0.90  # Raised from 0.85 for stricter filtering
NORMAL_LLM_ANOMALY_THRESHOLD = 0.15  # Raised from 0.10 for stricter filtering


def get_groq_client():
    """Create a Groq client only when the package and API key are available."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not Groq or not api_key:
        return None

    try:
        return Groq(api_key=api_key)
    except Exception:
        return None


def generate_soc_report(raw_log: Dict[str, Any], prediction: str, confidence: float) -> Dict[str, str]:
    """Generate a strict JSON SOC report for the predicted event."""
    groq_client = get_groq_client()
    if not groq_client:
        return {
            "executive_summary": "LLM integration disabled: API key or groq package not available.",
            "mitre_technique": "Unknown",
            "firewall_rule_recommendation": "No recommendation generated.",
        }

    ml_hint_map = {
        "Fuzzers": "MITRE T1499 (Endpoint Denial of Service). Focus on malformed data injection.",
        "DoS": "MITRE T1498 (Network Denial of Service). Focus on volumetric traffic and rate limits.",
        "Reconnaissance": "MITRE T1595 (Active Scanning). Focus on port scanning and host discovery.",
        "Exploits": "MITRE T1190 (Exploit Public-Facing Application). Focus on payload delivery.",
        "Generic": "MITRE T1071 (Application Layer Protocol). Focus on anomalous protocol usage.",
        "Analysis": "MITRE T1046 (Network Service Discovery). Focus on host/service probing behavior.",
        "Normal": "No confirmed ATT&CK technique. Validate against baseline behavior.",
    }

    system_prompt = """You are an elite Tier-3 SOC Analyst. 
Your objective is to analyze network flow data and provide a structured JSON incident report.

CRITICAL FIREWALL RULE INSTRUCTIONS:
Never write blanket rules that block entire ports or protocols for all users (e.g., do not just block --dport 53). 
You MUST extract the attacker's Source IP address from the provided log data (look for 'srcip', 'saddr', or 'src').
Your recommended iptables rule MUST target only that specific malicious Source IP using the '-s' flag.

Your JSON must exactly match this schema:
{
    "executive_summary": "A 2-sentence summary of the threat.",
    "mitre_technique": "The specific MITRE ATT&CK Tactic and ID.",
    "firewall_rule_recommendation": "The targeted iptables rule blocking the specific Source IP."
}"""

    user_prompt = (
        f"The Machine Learning Detection Engine has classified the following network log as a '{prediction}' "
        f"attack with {confidence * 100:.2f}% confidence.\n"
        f"Analyst Context: {ml_hint_map.get(prediction, 'Analyze for general network anomalies.')}\n\n"
        f"Raw Network Log:\n{json.dumps(raw_log, ensure_ascii=True)}"
    )

    def normalize_report(parsed: Dict[str, Any]) -> Dict[str, str]:
        return {
            "executive_summary": str(parsed.get("executive_summary", "No summary produced.")),
            "mitre_technique": str(parsed.get("mitre_technique", ml_hint_map.get(prediction, "Unknown"))),
            "firewall_rule_recommendation": str(
                parsed.get("firewall_rule_recommendation", "Apply temporary block/rate-limit and investigate source.")
            ),
        }

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        parsed = json.loads(chat_completion.choices[0].message.content)
        return normalize_report(parsed)
    except Exception as e:
        try:
            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.1,
            )
            parsed = json.loads(chat_completion.choices[0].message.content)
            return normalize_report(parsed)
        except Exception as fallback_error:
            return {
                "executive_summary": f"LLM Generation Failed: {fallback_error}",
                "mitre_technique": ml_hint_map.get(prediction, "Unknown"),
                "firewall_rule_recommendation": "Apply temporary block/rate-limit and investigate source.",
            }


def should_call_llm(result: Dict[str, Any]) -> bool:
    """Return True only when the event is risky enough to justify an LLM call."""
    prediction = result.get("prediction", "")
    confidence = float(result.get("confidence", 0.0) or 0.0)
    anomaly_score = float(result.get("anomaly_score", 0.0) or 0.0)
    risk_level = str(result.get("risk_level", "")).lower()

    if risk_level.startswith("high") or risk_level.startswith("medium"):
        return True

    return prediction == "Normal" and (
        confidence < NORMAL_LLM_CONFIDENCE_THRESHOLD
        or anomaly_score > NORMAL_LLM_ANOMALY_THRESHOLD
    )


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


def preprocess_log(log_data: Dict[str, Any], artifacts: Dict[str, Any], verbose: bool = True) -> np.ndarray:
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

    if verbose:
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
                if verbose:
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
    if verbose:
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
        if verbose:
            print(f"  WARNING: Dropping duplicate columns: {dup_cols}", file=sys.stderr)
        df = df.loc[:, ~df.columns.duplicated()]
    # Prefer scaler's feature names if available to avoid mismatch
    if hasattr(scaler, 'feature_names_in_') and len(scaler.feature_names_in_) > 0:
        expected_features = list(scaler.feature_names_in_)
    else:
        expected_features = list(feature_names)
        if hasattr(scaler, 'n_features_in_') and len(expected_features) != scaler.n_features_in_:
            if verbose:
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
        if verbose:
            print(f"  WARNING: {len(missing_features)} features missing from log (filled with 0)", file=sys.stderr)
        if len(missing_features) <= 5:
            if verbose:
                print(f"    Missing: {missing_features}", file=sys.stderr)

    if verbose:
        print(f"✓ Columns aligned. Order: {df.columns.tolist()[:5]}...", file=sys.stderr)
    # ---------------------------------------------

    # STEP 5: Scale using trained scaler
    X_scaled = scaler.transform(df)
    
    if verbose:
        print(f"  ✓ Preprocessed: {X_scaled.shape[1]} features", file=sys.stderr)
    
    return X_scaled


def predict_attack(log_data: Dict[str, Any], artifacts: Dict[str, Any], verbose: bool = True) -> Dict[str, Any]:
    """
    Predict attack type for a single log entry.
    
    Args:
        log_data: Raw log entry as dict
        artifacts: Loaded model artifacts
        
    Returns:
        Dict with prediction, confidence, and risk_level
    """
    # Preprocess log
    X = preprocess_log(log_data, artifacts, verbose=verbose)
    
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
        if verbose:
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
            if verbose:
                print(f"Vote Split Detected: Normal ({p_normal:.2f}) < Total Attack ({p_attack:.2f}).", file=sys.stderr)
                print(f"  Overriding prediction to: {best_attack}", file=sys.stderr)
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
    parser.add_argument(
        '--report',
        action='store_true',
        help='Add an optional Groq SOC report to the JSON output'
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

        prediction = result['prediction']
        confidence = result['confidence']
        risk_level = result['risk_level']

        # --- LLM TRIGGER LOGIC ---
        # Generate the report only for clearly risky events or genuinely uncertain normal traffic.
        llm_report = None
        if args.report and should_call_llm(result):
            print("\n🤖 Waking up LLM (Llama 3) for Second Opinion...", file=sys.stderr)
            llm_report = generate_soc_report(log_data, prediction, confidence)

            if args.verbose:
                print("\n🚨 --- AI INCIDENT REPORT --- 🚨", file=sys.stderr)
                print(llm_report, file=sys.stderr)
                print("---------------------------------\n", file=sys.stderr)

        # Look up the MITRE info based on the ML prediction.
        # If prediction is unknown, default to Generic.
        mitre_info = mitre_mapping.get(prediction, mitre_mapping["Generic"])
        mitre_summary = (
            f"MITRE Tactic: {mitre_info['tactic']}\n"
            f"MITRE Technique: {mitre_info['technique']}\n"
            f"MITRE URL: {mitre_info['url']}"
        )
        if llm_report:
            llm_analysis_payload: Dict[str, Any] = {
                "mitre_summary": mitre_summary,
                "report": llm_report,
            }
        else:
            llm_analysis_payload = {
                "mitre_summary": mitre_summary,
                "report": {
                    "executive_summary": "Traffic normal. LLM bypassed.",
                    "mitre_technique": mitre_info['technique'],
                    "firewall_rule_recommendation": "No immediate block action required.",
                },
            }

        anomaly_score = float(result.get('anomaly_score', 0.0) or 0.0)

        final_result = {
            'prediction': prediction,
            'confidence': round(float(confidence), 4),
            'risk_level': risk_level,
            'anomaly_score': round(float(anomaly_score), 4),
            'mitre_tactic': mitre_info['tactic'],
            'mitre_technique': mitre_info['technique'],
            'mitre_url': mitre_info['url'],
            'probabilities': result.get('probabilities'),
            'llm_analysis': llm_analysis_payload
        }

        # Output strict JSON for Wazuh parsing
        print(json.dumps(final_result, indent=2 if args.verbose else None))
        
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


if __name__ == '__main__':
    main()
