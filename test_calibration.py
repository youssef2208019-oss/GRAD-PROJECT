#!/usr/bin/env python
"""
Calibration test and Platt scaling for the AI SOC Helper model.

This script:
1. Loads the existing trained model artifact.
2. Loads the dataset and builds the same feature matrix expected by the model.
3. Evaluates calibration for binary Attack vs Normal probabilities.
4. Fits CalibratedClassifierCV (sigmoid / Platt scaling) on a validation split.
5. Saves a calibrated model artifact that can be used by predict_soc.py.
"""

import argparse
import sys
import warnings
from typing import Any, Dict, Tuple

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, CalibrationDisplay
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import brier_score_loss
from sklearn.model_selection import train_test_split

warnings.filterwarnings('ignore')


ATTACK_CAT_MAPPING = {
    'Normal': 0,
    'DoS': 1,
    'Exploits': 2,
    'Fuzzers': 3,
    'Generic': 4,
    'Reconnaissance': 5,
}


def load_artifacts(model_path: str) -> Dict[str, Any]:
    try:
        return joblib.load(model_path)
    except FileNotFoundError:
        print(f"ERROR: Model file '{model_path}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to load model artifact: {exc}", file=sys.stderr)
        sys.exit(1)


def load_dataset(data_path: str, sample_size: int | None = None, random_state: int = 42) -> pd.DataFrame:
    try:
        df = pd.read_csv(data_path)
        if sample_size is None or sample_size <= 0 or sample_size >= len(df):
            return df

        target_col = _find_target_column(df)
        classes = list(df[target_col].dropna().unique())
        per_class = max(1, sample_size // max(1, len(classes)))

        sampled_parts = []
        for class_name in classes:
            class_rows = df[df[target_col] == class_name]
            take = min(len(class_rows), per_class)
            sampled_parts.append(class_rows.sample(n=take, random_state=random_state))

        sampled_df = pd.concat(sampled_parts, ignore_index=True)
        if len(sampled_df) < sample_size:
            remainder = df.drop(sampled_df.index, errors='ignore')
            extra_needed = min(sample_size - len(sampled_df), len(remainder))
            if extra_needed > 0:
                sampled_df = pd.concat(
                    [sampled_df, remainder.sample(n=extra_needed, random_state=random_state)],
                    ignore_index=True,
                )

        return sampled_df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    except Exception as exc:
        print(f"ERROR: Failed to load dataset '{data_path}': {exc}", file=sys.stderr)
        sys.exit(1)


def _find_target_column(df: pd.DataFrame) -> str:
    for candidate in ('attack_cat', 'AttackCategory', 'Label'):
        if candidate in df.columns:
            return candidate
    raise ValueError("No target column found (expected attack_cat, AttackCategory, or Label)")


def _encode_categorical_features(df: pd.DataFrame, artifacts: Dict[str, Any]) -> pd.DataFrame:
    label_encoders = artifacts['label_encoders']
    for col, encoder in label_encoders.items():
        if col not in df.columns:
            df[col] = 0
            continue

        series = df[col].astype(str)
        df[col] = series.apply(lambda value: encoder.transform([value])[0] if value in encoder.classes_ else 0)
    return df


def _first_present(df: pd.DataFrame, *candidates: str) -> str | None:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    return None


def _engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    source_bytes = _first_present(df, 'SourceBytes', 'sbytes')
    destination_bytes = _first_present(df, 'DestinationBytes', 'dbytes')
    sinpkt = _first_present(df, 'sinpkt')
    dinpkt = _first_present(df, 'dinpkt')
    flow_duration = _first_present(df, 'FlowDuration', 'dur')
    synack = _first_present(df, 'synack')
    ackdat = _first_present(df, 'ackdat')
    sloss = _first_present(df, 'sloss')
    dloss = _first_present(df, 'dloss')
    sjit = _first_present(df, 'sjit')
    djit = _first_present(df, 'djit')
    swin = _first_present(df, 'swin')
    dwin = _first_present(df, 'dwin')
    source_ttl = _first_present(df, 'SourceTTL', 'sttl')
    destination_ttl = _first_present(df, 'DestinationTTL', 'dttl')

    df['sbytes_per_pkt'] = 0
    if source_bytes and sinpkt:
        df['sbytes_per_pkt'] = df[source_bytes] / (df[sinpkt] + 1e-6)

    df['dbytes_per_pkt'] = 0
    if destination_bytes and dinpkt:
        df['dbytes_per_pkt'] = df[destination_bytes] / (df[dinpkt] + 1e-6)

    df['pkts_rate'] = 0
    if sinpkt and dinpkt and flow_duration:
        df['pkts_rate'] = (df[sinpkt] + df[dinpkt]) / (df[flow_duration] + 1e-6)

    df['tcp_flag_ratio'] = 0
    if synack and ackdat:
        df['tcp_flag_ratio'] = df[synack] / (df[ackdat] + 1e-6)

    df['loss_ratio'] = 0
    if sloss and dloss and sinpkt and dinpkt:
        df['loss_ratio'] = (df[sloss] + df[dloss]) / (df[sinpkt] + df[dinpkt] + 1e-6)

    df['jitter_ratio'] = 0
    if sjit and djit and flow_duration:
        df['jitter_ratio'] = (df[sjit] + df[djit]) / (df[flow_duration] + 1e-6)

    df['window_ratio'] = 0
    if swin and dwin:
        df['window_ratio'] = df[swin] / (df[dwin] + 1e-6)

    df['ttl_diff'] = 0
    if source_ttl and destination_ttl:
        df['ttl_diff'] = (df[source_ttl] - df[destination_ttl]).abs()

    return df


def preprocess_dataset(df: pd.DataFrame, artifacts: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray]:
    df = df.copy()

    target_col = _find_target_column(df)
    y = df[target_col].map(ATTACK_CAT_MAPPING).fillna(6).astype(int).to_numpy()

    cols_to_drop = [
        'id', 'ID', 'Unnamed: 0', 'attack_cat', 'AttackCategory', 'Label', 'label',
        'attack_cat_encoded', '@timestamp', 'stcpb', 'dtcpb'
    ]
    cols_to_drop = [col for col in cols_to_drop if col in df.columns]
    df = df.drop(columns=cols_to_drop)

    df = _encode_categorical_features(df, artifacts)

    for col in df.columns:
        if df[col].dtype == object:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    df = df.fillna(0)
    df = _engineer_features(df)
    df = df.replace([np.inf, -np.inf], 0).fillna(0)

    if df.columns.duplicated().any():
        df = df.loc[:, ~df.columns.duplicated()]

    expected_features = list(artifacts['feature_names'])
    if hasattr(artifacts['scaler'], 'feature_names_in_') and len(artifacts['scaler'].feature_names_in_) > 0:
        expected_features = list(artifacts['scaler'].feature_names_in_)

    seen = set()
    expected_features = [feature for feature in expected_features if not (feature in seen or seen.add(feature))]

    for feature in expected_features:
        if feature not in df.columns:
            df[feature] = 0

    df = df[expected_features]
    X = artifacts['scaler'].transform(df)
    return X, y


def attack_probability(model: Any, X: np.ndarray, class_names: Dict[int, str]) -> np.ndarray:
    probabilities = model.predict_proba(X)

    normal_index = 0
    for index, name in class_names.items():
        if name == 'Normal':
            normal_index = int(index)
            break

    if probabilities.ndim == 1:
        return probabilities

    if probabilities.shape[1] == 2:
        return probabilities[:, 1]

    return 1.0 - probabilities[:, normal_index]


def evaluate_brier_and_plot(y_true_binary: np.ndarray, original_prob: np.ndarray, calibrated_prob: np.ndarray, output_path: str) -> None:
    original_brier = brier_score_loss(y_true_binary, original_prob)
    calibrated_brier = brier_score_loss(y_true_binary, calibrated_prob)

    print(f"Brier Score (Original):   {original_brier:.4f}")
    print(f"Brier Score (Calibrated): {calibrated_brier:.4f}")

    plt.figure(figsize=(8, 6))
    CalibrationDisplay.from_predictions(
        y_true_binary,
        original_prob,
        n_bins=10,
        name='Original',
    )
    CalibrationDisplay.from_predictions(
        y_true_binary,
        calibrated_prob,
        n_bins=10,
        name='Calibrated',
    )
    plt.plot([0, 1], [0, 1], 'k--', label='Perfect calibration')
    plt.title('XGBoost Calibration Curve')
    plt.legend(loc='best')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Calibration curve saved to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description='Evaluate calibration and save a calibrated SOC model')
    parser.add_argument('--data', type=str, default='merged_dataset.csv', help='Dataset CSV used for calibration testing')
    parser.add_argument('--model', type=str, default='soc_model.pkl', help='Path to the trained model artifact')
    parser.add_argument('--calibrated_out', type=str, default='soc_model_calibrated.pkl', help='Output path for the calibrated artifact')
    parser.add_argument('--plot_out', type=str, default='calibration_curve.png', help='Output path for the calibration plot')
    parser.add_argument('--sample_size', type=int, default=5000, help='Balanced sample size to use for calibration testing')
    parser.add_argument('--show', action='store_true', help='Display the calibration plot interactively')
    args = parser.parse_args()

    print('=' * 70)
    print('AI SOC HELPER - CALIBRATION TEST')
    print('=' * 70)
    print(f'Loading a balanced sample of up to {args.sample_size} rows from dataset for calibration testing...')

    artifacts = load_artifacts(args.model)
    df = load_dataset(args.data, sample_size=args.sample_size)

    X, y = preprocess_dataset(df, artifacts)
    print(f'Prepared calibration matrix: X={X.shape}, y={y.shape}')

    X_temp, X_test, y_temp, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    X_train, X_val, y_train, y_val = train_test_split(
        X_temp,
        y_temp,
        test_size=0.25,
        random_state=42,
        stratify=y_temp,
    )

    print(f'Train split: {X_train.shape[0]} samples')
    print(f'Validation split: {X_val.shape[0]} samples')
    print(f'Test split: {X_test.shape[0]} samples')

    original_model = artifacts['model']
    class_names = artifacts.get('class_names', {0: 'Normal'})

    calibrated_model = CalibratedClassifierCV(FrozenEstimator(original_model), method='sigmoid', cv=2)
    calibrated_model.fit(X_val, y_val)

    y_test_binary = (y_test != 0).astype(int)
    original_attack_prob = attack_probability(original_model, X_test, class_names)
    calibrated_attack_prob = attack_probability(calibrated_model, X_test, class_names)

    evaluate_brier_and_plot(y_test_binary, original_attack_prob, calibrated_attack_prob, args.plot_out)

    calibrated_artifacts = dict(artifacts)
    calibrated_artifacts['model'] = calibrated_model
    calibrated_artifacts['calibration_method'] = 'sigmoid'
    calibrated_artifacts['calibrated_on'] = 'validation split from dataset'
    joblib.dump(calibrated_artifacts, args.calibrated_out)
    print(f'Calibrated artifact saved to {args.calibrated_out}')

    if args.show:
        plt.show()


if __name__ == '__main__':
    main()