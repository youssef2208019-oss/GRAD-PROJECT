#!/usr/bin/env python
"""Training script with file logging"""
import sys
import os

# Redirect all output to a file
log_file = "training.log"
sys.stdout = open(log_file, 'w', buffering=1)
sys.stderr = sys.stdout

print("=" * 70)
print("AI SOC HELPER - XGBoost Network Intrusion Detection Model Trainer")
print("=" * 70)
print(f"Log file: {log_file}")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Now import and run the actual training
import argparse
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

print("\nAll imports successful!")

# Import from the main training script (reimport its functions)
exec(open('train_soc_model.py').read())

print("\nScript finished!")
