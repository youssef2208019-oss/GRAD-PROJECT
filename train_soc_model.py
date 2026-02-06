"""
AI SOC Helper - XGBoost Network Intrusion Detection Model Trainer

This script trains an XGBoost classifier for multi-class network intrusion detection
on the UNSW-NB15 dataset. It handles preprocessing, stratified splitting, training,
evaluation, and exports model artifacts for real-time SOC pipelines (Wazuh/Logstash).

Usage:
    python train_soc_model.py --data UNSW-NB15_sample.csv --model_out soc_model.pkl
"""

import argparse
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
import joblib
import warnings

warnings.filterwarnings('ignore')


def load_data(data_path: str) -> pd.DataFrame:
    """Load UNSW-NB15 dataset from CSV."""
    print(f"Loading dataset from {data_path}...", flush=True)
    sys.stdout.flush()
    df = pd.read_csv(data_path)
    print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns", flush=True)
    sys.stdout.flush()
    return df


def preprocess_data(df: pd.DataFrame) -> tuple:
    """
    Preprocess UNSW-NB15 dataset:
    - Remove ID-like columns with high cardinality (TCP sequence numbers, etc.)
    - Convert numerical columns to numeric types
    - Handle categorical features with LabelEncoder
    - Map attack categories to 7 classes
    - Normalize numerical features
    
    Returns:
        Tuple: (X_processed, y_encoded, label_encoders, scaler, attack_cat_mapping, feature_names)
    """
    print("\n=== PREPROCESSING ===")
    
    # Create a copy to avoid modifying original
    df = df.copy()
    
    # Find the target column (could be 'attack_cat', 'AttackCategory', or 'Label')
    target_col = None
    if 'attack_cat' in df.columns:
        target_col = 'attack_cat'
    elif 'AttackCategory' in df.columns:
        target_col = 'AttackCategory'
    elif 'Label' in df.columns:
        target_col = 'Label'
    else:
        raise ValueError("No target column found (looking for 'attack_cat', 'AttackCategory', or 'Label')")
    
    print(f"Using target column: {target_col}")
    
    # Define target mapping: 7 classes
    attack_cat_mapping = {
        'Normal': 0,
        'DoS': 1,
        'Exploits': 2,
        'Fuzzers': 3,
        'Generic': 4,
        'Reconnaissance': 5
        # All others map to 6 ('Other')
    }
    
    print(f"Target mapping: {attack_cat_mapping}")
    
    # Encode target: map known classes, else 'Other' -> 6
    df['attack_cat_encoded'] = df[target_col].map(attack_cat_mapping)
    df['attack_cat_encoded'] = df['attack_cat_encoded'].fillna(6).astype(int)
    
    y = df['attack_cat_encoded'].values
    print(f"Target distribution:\n{pd.Series(y).value_counts().sort_index()}")
    
    # DROP ID-like columns with high cardinality (DATA LEAKAGE PREVENTION)
    # stcpb, dtcpb are TCP sequence numbers that act as unique identifiers
    # Unnamed: 0 is pandas index that was accidentally saved
    cols_to_drop = ['id', 'ID', 'Unnamed: 0', 'attack_cat', 'attack_cat_encoded',
                    'AttackCategory', 'Label', 'label', '@timestamp', 'stcpb', 'dtcpb']
    cols_to_drop = [col for col in cols_to_drop if col in df.columns]
    print(f"Dropping columns to prevent data leakage: {cols_to_drop}")
    df = df.drop(columns=cols_to_drop)
    
    # Print final feature list for verification
    print(f"Final feature list: {df.columns.tolist()}")
    print(f"Total features: {len(df.columns)}")
    
    # Explicitly define known categorical columns (only actual string features)
    categorical_cols = ['Protocol', 'Service', 'State']
    categorical_cols = [col for col in categorical_cols if col in df.columns]
    
    print(f"Categorical columns (to be encoded): {categorical_cols}")
    
    # Encode categorical features with LabelEncoder
    label_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le
        print(f"  Encoded '{col}': {len(le.classes_)} unique values")
    
    # Force convert all remaining columns to numeric BEFORE feature engineering
    print(f"\nForce converting all columns to numeric...")
    for col in df.columns:
        if col not in categorical_cols:
            try:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            except Exception as e:
                print(f"  Warning: Could not convert {col}: {e}")
    
    # Fill NaN values from coercion
    df = df.fillna(0)
    
    # FEATURE ENGINEERING: Create interaction features to distinguish normal vs attack traffic
    print(f"\nCreating engineered features...")
    
    # Create ratio features that help distinguish DoS attacks
    if 'SourceBytes' in df.columns and 'sinpkt' in df.columns:
        df['sbytes_per_pkt'] = df['SourceBytes'] / (df['sinpkt'] + 1e-6)
        print(f"  ✓ Created 'sbytes_per_pkt' (SourceBytes per packet)")
    
    if 'DestinationBytes' in df.columns and 'dinpkt' in df.columns:
        df['dbytes_per_pkt'] = df['DestinationBytes'] / (df['dinpkt'] + 1e-6)
        print(f"  ✓ Created 'dbytes_per_pkt' (DestinationBytes per packet)")
    
    if 'sinpkt' in df.columns and 'dinpkt' in df.columns and 'FlowDuration' in df.columns:
        df['pkts_rate'] = (df['sinpkt'] + df['dinpkt']) / (df['FlowDuration'] + 1e-6)
        print(f"  ✓ Created 'pkts_rate' (packets per second)")
    
    # Network-specific features for attack detection
    if 'synack' in df.columns and 'ackdat' in df.columns:
        df['tcp_flag_ratio'] = df['synack'] / (df['ackdat'] + 1e-6)
        print(f"  ✓ Created 'tcp_flag_ratio' (SYN-ACK to ACK ratio)")
    
    if 'sloss' in df.columns and 'dloss' in df.columns and 'sinpkt' in df.columns and 'dinpkt' in df.columns:
        df['loss_ratio'] = (df['sloss'] + df['dloss']) / (df['sinpkt'] + df['dinpkt'] + 1e-6)
        print(f"  ✓ Created 'loss_ratio' (packet loss rate)")
    
    if 'sjit' in df.columns and 'djit' in df.columns and 'FlowDuration' in df.columns:
        df['jitter_ratio'] = (df['sjit'] + df['djit']) / (df['FlowDuration'] + 1e-6)
        print(f"  ✓ Created 'jitter_ratio' (jitter per second)")
    
    if 'swin' in df.columns and 'dwin' in df.columns:
        df['window_ratio'] = df['swin'] / (df['dwin'] + 1e-6)
        print(f"  ✓ Created 'window_ratio' (TCP window size ratio)")
    
    if 'SourceTTL' in df.columns and 'DestinationTTL' in df.columns:
        df['ttl_diff'] = abs(df['SourceTTL'] - df['DestinationTTL'])
        print(f"  ✓ Created 'ttl_diff' (TTL difference)")
    
    # Replace any inf or NaN values from division
    df = df.replace([np.inf, -np.inf], 0).fillna(0)
    print(f"  Cleaned inf/NaN values from ratio features")
    
    # Verify data types
    numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    print(f"\nNumerical columns: {len(numerical_cols)} features")
    print(f"  Sample numerical columns: {numerical_cols[:5]}...")
    print(f"  Engineered features included: {[col for col in numerical_cols if col in ['sbytes_per_pkt', 'dbytes_per_pkt', 'pkts_rate']]}")
    
    # Store feature names before converting to numpy array
    feature_names = df.columns.tolist()
    
    # Print final feature list for verification
    print(f"\nFinal feature list ({len(feature_names)} features):")
    print(f"  {feature_names}")
    print(f"  Engineered features present: {'sbytes_per_pkt' in feature_names}, {'dbytes_per_pkt' in feature_names}, {'pkts_rate' in feature_names}")
    
    # Store feature names before converting to numpy array
    feature_names = df.columns.tolist()
    
    # Separate features and target
    X = df.values
    
    # Normalize numerical features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    
    print(f"\nNormalized all features using StandardScaler")
    print(f"Feature matrix shape: {X.shape}")
    print(f"Feature names preserved: {len(feature_names)} features")
    
    return X, y, label_encoders, scaler, attack_cat_mapping, feature_names


def split_data(X: np.ndarray, y: np.ndarray, test_size: float = 0.3, random_state: int = 42) -> tuple:
    """
    Split data into train and test sets with stratification.
    
    Returns:
        Tuple: (X_train, X_test, y_train, y_test)
    """
    print("\n=== DATA SPLITTING ===")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )
    
    print(f"Training set: {X_train.shape[0]} samples (70%)")
    print(f"Test set: {X_test.shape[0]} samples (30%)")
    print(f"Class distribution preserved in both sets")
    
    return X_train, X_test, y_train, y_test


def train_model(X_train: np.ndarray, y_train: np.ndarray) -> XGBClassifier:
    """
    Train XGBoost classifier with hyperparameter tuning using RandomizedSearchCV.
    Optimizes for best F1-weighted score across all attack classes.
    """
    print("\n=== MODEL TRAINING WITH HYPERPARAMETER TUNING ===")
    
    # Define parameter distribution for random search
    param_dist = {
        'n_estimators': [100, 200, 300, 400],
        'max_depth': [3, 5, 6, 10],
        'learning_rate': [0.01, 0.05, 0.1, 0.2],
        'subsample': [0.6, 0.8, 1.0],
        'colsample_bytree': [0.6, 0.8, 1.0],
        'gamma': [0, 0.1, 0.5, 1]
    }
    
    # Base XGBoost model (n_jobs=1 for Windows stability)
    base_model = XGBClassifier(
        objective='multi:softprob',
        num_class=7,
        random_state=42,
        eval_metric='mlogloss',
        verbosity=0,
        n_jobs=1  # Disable threading to prevent Windows access violations
    )
    
    print("Starting RandomizedSearchCV...")
    print(f"  Parameter grid size: {len(param_dist)} parameters")
    print(f"  Total combinations: {4*4*4*3*3*4} possible")
    print(f"  Testing: 10 random combinations with 3-fold CV")
    print(f"  Optimization metric: f1_weighted")
    print(f"  Training samples: {X_train.shape[0]}")
    
    # Compute sample weights for class balancing
    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)
    
    # RandomizedSearchCV (n_jobs=1 to avoid Windows multiprocessing crashes)
    random_search = RandomizedSearchCV(
        estimator=base_model,
        param_distributions=param_dist,
        n_iter=10,
        scoring='f1_weighted',
        cv=3,
        verbose=2,
        n_jobs=1,  # Disable parallel processing to prevent Windows access violations
        random_state=42
    )
    
    # Fit with sample weights
    print("\nFitting RandomizedSearchCV (this may take a few minutes)...")
    random_search.fit(X_train, y_train, sample_weight=sample_weights)
    
    print(f"\n✓ Hyperparameter tuning complete!")
    print(f"\nBest Parameters Found:")
    for param, value in random_search.best_params_.items():
        print(f"  {param}: {value}")
    
    print(f"\nBest CV F1-Weighted Score: {random_search.best_score_:.4f}")
    
    # Return the best model
    return random_search.best_estimator_


def evaluate_model(model: XGBClassifier, X_test: np.ndarray, y_test: np.ndarray, 
                   attack_cat_mapping: dict) -> None:
    """
    Evaluate model on test set and print classification report.
    """
    print("\n=== MODEL EVALUATION ===")
    
    y_pred = model.predict(X_test)
    
    # Create reverse mapping for class names
    reverse_mapping = {v: k for k, v in attack_cat_mapping.items()}
    reverse_mapping[6] = 'Other'
    
    target_names = [reverse_mapping[i] for i in sorted(reverse_mapping.keys())]
    
    print("\nClassification Report (7 classes):")
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    
    return y_pred


def plot_confusion_matrix(y_test: np.ndarray, y_pred: np.ndarray, 
                         attack_cat_mapping: dict, output_path: str = 'confusion_matrix.png') -> None:
    """
    Generate and save confusion matrix plot.
    """
    print(f"\nGenerating confusion matrix plot...")
    
    reverse_mapping = {v: k for k, v in attack_cat_mapping.items()}
    reverse_mapping[6] = 'Other'
    
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(12, 10))
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=[reverse_mapping[i] for i in sorted(reverse_mapping.keys())],
        yticklabels=[reverse_mapping[i] for i in sorted(reverse_mapping.keys())],
        cbar_kws={'label': 'Count'}
    )
    plt.title('Confusion Matrix - XGBoost SOC Intrusion Detection Model', fontsize=14, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Confusion matrix saved to {output_path}")
    plt.close()


def plot_feature_importance(model: XGBClassifier, feature_names: list, 
                           output_path: str = 'feature_importance.png') -> None:
    """
    Generate and save feature importance plot with actual feature names.
    
    Args:
        model: Trained XGBClassifier
        feature_names: List of feature column names
        output_path: Path to save the plot
    """
    print(f"\nGenerating feature importance plot...")
    
    importances = model.feature_importances_
    indices = np.argsort(importances)[-20:]  # Top 20 features
    
    # Get feature names for the top 20
    top_feature_names = [feature_names[i] for i in indices]
    
    plt.figure(figsize=(10, 8))
    plt.barh(range(len(indices)), importances[indices], align='center')
    plt.yticks(range(len(indices)), top_feature_names)
    plt.xlabel('XGBoost Feature Importance Score', fontsize=12)
    plt.title('Top 20 Feature Importances - SOC Intrusion Detection Model', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Feature importance plot saved to {output_path}")
    print(f"Top features: {', '.join(top_feature_names[:5])}...")
    plt.close()


def save_artifacts(model: XGBClassifier, label_encoders: dict, scaler: StandardScaler,
                  attack_cat_mapping: dict, feature_names: list, model_path: str = 'soc_model.pkl') -> None:
    """
    Save trained model, encoders, scaler, and feature names using joblib.
    
    Args:
        model: Trained XGBClassifier
        label_encoders: Dict of fitted LabelEncoders
        scaler: Fitted StandardScaler
        attack_cat_mapping: Target class mapping
        feature_names: List of feature column names
        model_path: Path to save the artifact file
    """
    print(f"\n=== SAVING ARTIFACTS ===")
    
    artifacts = {
        'model': model,
        'label_encoders': label_encoders,
        'scaler': scaler,
        'attack_cat_mapping': attack_cat_mapping,
        'class_names': {v: k for k, v in attack_cat_mapping.items()},
        'feature_names': feature_names
    }
    
    joblib.dump(artifacts, model_path)
    print(f"Model and artifacts saved to {model_path}")
    
    # Print model info
    print(f"\nExported artifacts:")
    print(f"  - XGBClassifier (7 classes)")
    print(f"  - LabelEncoders for {len(label_encoders)} categorical features")
    print(f"  - StandardScaler for normalization")
    print(f"  - Attack category mappings")
    print(f"  - Feature names ({len(feature_names)} features)")


def main():
    parser = argparse.ArgumentParser(
        description='Train XGBoost SOC intrusion detection model on UNSW-NB15 dataset'
    )
    parser.add_argument(
        '--data',
        type=str,
        required=True,
        help='Path to UNSW-NB15 CSV dataset'
    )
    parser.add_argument(
        '--model_out',
        type=str,
        default='soc_model.pkl',
        help='Output path for trained model (default: soc_model.pkl)'
    )
    
    args = parser.parse_args()
    
    print("=" * 70, flush=True)
    print("AI SOC HELPER - XGBoost Network Intrusion Detection Model Trainer", flush=True)
    print("=" * 70, flush=True)
    sys.stdout.flush()
    
    try:
        # Load and preprocess
        print("\nStep 1: Loading data...", flush=True)
        sys.stdout.flush()
        df = load_data(args.data)
        X, y, label_encoders, scaler, attack_cat_mapping, feature_names = preprocess_data(df)
        
        # Split data
        X_train, X_test, y_train, y_test = split_data(X, y)
        
        # Apply SMOTE to balance minority classes
        print("\n=== SMOTE OVERSAMPLING ===")
        print(f"Original training distribution:")
        unique, counts = np.unique(y_train, return_counts=True)
        for cls, count in zip(unique, counts):
            print(f"  Class {cls}: {count} samples")
        
        smote = SMOTE(random_state=42, k_neighbors=5)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        
        print(f"\nAfter SMOTE balancing:")
        unique, counts = np.unique(y_train, return_counts=True)
        for cls, count in zip(unique, counts):
            print(f"  Class {cls}: {count} samples")
        print(f"Training set size: {X_train.shape[0]} samples (balanced)")
        
        # Train model
        model = train_model(X_train, y_train)
        
        # Feature Selection: Remove low-importance features
        print("\n=== FEATURE SELECTION ===")
        importances = model.feature_importances_
        low_importance_threshold = 0.001
        low_importance_mask = importances < low_importance_threshold
        num_low_importance = np.sum(low_importance_mask)
        
        if num_low_importance > 0:
            print(f"Found {num_low_importance} low-importance features (< {low_importance_threshold})")
            low_importance_features = [feature_names[i] for i, is_low in enumerate(low_importance_mask) if is_low]
            print(f"Removing features: {low_importance_features[:10]}...")
            
            # Keep only high-importance features
            high_importance_mask = ~low_importance_mask
            X_train_selected = X_train[:, high_importance_mask]
            X_test_selected = X_test[:, high_importance_mask]
            feature_names_selected = [fn for fn, keep in zip(feature_names, high_importance_mask) if keep]
            
            print(f"Feature set reduced: {len(feature_names)} → {len(feature_names_selected)} features")
            print(f"Retraining model with selected features...")
            
            # Retrain with selected features
            model = train_model(X_train_selected, y_train)
            X_train = X_train_selected
            X_test = X_test_selected
            feature_names = feature_names_selected
        else:
            print(f"All features have importance >= {low_importance_threshold}, no removal needed")
        
        # Evaluate
        y_pred = evaluate_model(model, X_test, y_test, attack_cat_mapping)
        
        # Generate plots
        plot_confusion_matrix(y_test, y_pred, attack_cat_mapping)
        plot_feature_importance(model, feature_names)
        
        # Save artifacts
        save_artifacts(model, label_encoders, scaler, attack_cat_mapping, feature_names, args.model_out)
        
        print("\n" + "=" * 70)
        print("TRAINING COMPLETE - Model ready for Wazuh/Logstash SOC pipeline")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n[ERROR] Training failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
