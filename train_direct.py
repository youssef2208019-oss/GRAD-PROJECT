#!/usr/bin/env python
"""Direct training script without complex argument parsing"""
import sys
import os

# Set to use merged_dataset.csv by default
data_file = "merged_dataset.csv"
model_out = "soc_model.pkl"

with open("train_start.log", "w") as log:
    log.write("Training started\n")
    log.write(f"Python: {sys.version}\n")
    log.write(f"CWD: {os.getcwd()}\n")
    log.write(f"Data file: {data_file}\n")

# Now run the main training logic
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

# Import functions from train_soc_model
from train_soc_model import (
    load_data, preprocess_data, split_data, train_model, 
    evaluate_model, plot_confusion_matrix, plot_feature_importance, save_artifacts
)

print("\n" + "=" * 70)
print("AI SOC HELPER - XGBoost Network Intrusion Detection Model Trainer")
print("=" * 70)

try:
    # Load and preprocess
    print("\nStep 1: Loading data...")
    df = load_data(data_file)
    
    print("\nStep 2: Preprocessing...")
    X, y, label_encoders, scaler, attack_cat_mapping, feature_names = preprocess_data(df)
    
    # Split data
    print("\nStep 3: Splitting data...")
    X_train, X_test, y_train, y_test = split_data(X, y)
    
    # Apply SMOTE to balance minority classes
    print("\n=== SMOTE OVERSAMPLING ===")
    print(f"Original training distribution:")
    unique, counts = np.unique(y_train, return_counts=True)
    for cls, count in zip(unique, counts):
        print(f"  Class {cls}: {count} samples")
    
    smote = SMOTE(random_state=42, k_neighbors=5)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    
    print(f"After SMOTE:")
    unique, counts = np.unique(y_train, return_counts=True)
    for cls, count in zip(unique, counts):
        print(f"  Class {cls}: {count} samples")
    
    print(f"Training set size: {X_train.shape[0]} samples (balanced)")
    
    # Train model
    print("\nStep 4: Training model with RandomizedSearchCV...")
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
    print("\nStep 5: Evaluating model...")
    y_pred = evaluate_model(model, X_test, y_test, attack_cat_mapping)
    
    # Generate plots
    print("\nStep 6: Generating plots...")
    plot_confusion_matrix(y_test, y_pred, attack_cat_mapping)
    plot_feature_importance(model, feature_names)
    
    # Save artifacts
    print("\nStep 7: Saving model...")
    save_artifacts(model, label_encoders, scaler, attack_cat_mapping, feature_names, model_out)
    
    print("\n" + "=" * 70)
    print("TRAINING COMPLETE - Model ready for Wazuh/Logstash SOC pipeline")
    print("=" * 70)
    
except Exception as e:
    import traceback
    print(f"\n[ERROR] Training failed: {e}")
    traceback.print_exc()
    sys.exit(1)
