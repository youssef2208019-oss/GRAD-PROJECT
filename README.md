# GRAD-PROJECT - AI SOC Helper

AI SOC Helper: a production-ready Python training pipeline for multi-class network intrusion detection using XGBoost on the UNSW-NB15 dataset. Designed for integration with real-time SOC pipelines (Wazuh/Logstash).

A production-ready Python training pipeline for multi-class network intrusion detection using XGBoost on the UNSW-NB15 dataset. Designed for integration with real-time SOC pipelines (Wazuh/Logstash).

## 📋 System Overview

This project trains a sophisticated machine learning classifier to detect 7 distinct attack categories:
- **Normal** - Benign network traffic
- **DoS** - Denial of Service attacks
- **Exploits** - Exploitation attempts
- **Fuzzers** - Fuzzing/protocol testing
- **Generic** - Generic attack signatures
- **Reconnaissance** - Scanning and probing
- **Other** - Rare or undefined attacks

### Key Features
✅ **Stratified splitting** (70/30) to preserve attack distribution  
✅ **Multi-class XGBoost** with early stopping  
✅ **LabelEncoder + StandardScaler** for categorical and numerical features  
✅ **Comprehensive evaluation** (classification report, confusion matrix, feature importance)  
✅ **Model export** via joblib for real-time inference  
✅ **Visualization** of model performance and feature importance  

---

## 🛠️ Setup Instructions

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**Requirements:**
- pandas >= 1.3.0
- numpy >= 1.21.0
- scikit-learn >= 1.0.0
- xgboost >= 1.5.0
- matplotlib >= 3.4.0
- seaborn >= 0.11.0
- joblib >= 1.1.0

### 2. Prepare Dataset

Download or place your UNSW-NB15 CSV dataset in the project directory. Ensure the dataset contains these columns:

**Expected Columns:**
- Categorical features: `proto`, `service`, `state`
- Target column: `attack_cat` (values: Normal, DoS, Exploits, Fuzzers, Generic, Reconnaissance)
- Numerical features: All other numeric columns

**Example CSV structure:**
```
srcip,srcport,dstip,dstport,proto,state,service,dur,...,attack_cat,label
10.0.0.1,12345,10.0.0.2,80,tcp,ACC,http,100,...,Normal,0
...
```

---

## 🚀 Usage

### Basic Training

```bash
python train_soc_model.py --data UNSW-NB15_sample.csv
```

This will:
1. Load and preprocess the dataset
2. Split 70% training / 30% test with stratification
3. Train XGBoost classifier
4. Evaluate on test set
5. Generate `confusion_matrix.png` and `feature_importance.png`
6. Export model to `soc_model.pkl`

### Custom Model Output Path

```bash
python train_soc_model.py --data UNSW-NB15_sample.csv --model_out my_soc_model.pkl
```

---

## 📊 Output Artifacts

After training completes, the following files are generated:

### 1. **soc_model.pkl** (or custom name)
Serialized joblib object containing:
- `model`: Trained XGBClassifier (7-class)
- `label_encoders`: Dict of fitted LabelEncoders for categorical features
- `scaler`: Fitted StandardScaler for numerical features
- `attack_cat_mapping`: Class mapping (0-6)
- `class_names`: Reverse mapping for inference

### 2. **confusion_matrix.png**
Heatmap visualization of true vs. predicted labels across all 7 classes.

### 3. **feature_importance.png**
Bar plot of top 20 features ranked by XGBoost importance score.

---

## 📈 Model Parameters (Cybersecurity Optimized)

```python
XGBClassifier(
    objective='multi:softprob',      # Multi-class probability output
    num_class=7,                      # 7 attack categories
    max_depth=6,                      # Moderate tree depth
    learning_rate=0.1,                # Balanced learning
    n_estimators=200,                 # 200 boosting rounds
    subsample=0.8,                    # Row sampling
    colsample_bytree=0.8,             # Column sampling
    gamma=1,                          # Min loss reduction
    early_stopping_rounds=10,         # Prevent overfitting
    eval_metric='mlogloss'            # Multi-class loss
)
```

---

## 🔌 Integration with SOC Pipeline (Wazuh/Logstash)

### Loading the Model for Inference

```python
import joblib
import numpy as np

# Load trained artifacts
artifacts = joblib.load('soc_model.pkl')
model = artifacts['model']
scaler = artifacts['scaler']
label_encoders = artifacts['label_encoders']
class_names = artifacts['class_names']

# Prepare real-time data
# 1. Encode categorical features using label_encoders
# 2. Scale numerical features using scaler
# 3. Predict

X_real_time = np.array([[...features...]])  # Shape: (1, n_features)
X_scaled = scaler.transform(X_real_time)
prediction = model.predict(X_scaled)  # Returns class 0-6
class_label = class_names[prediction[0]]
confidence = model.predict_proba(X_scaled).max()

print(f"Detected: {class_label} (confidence: {confidence:.2%})")
```

---

## 📝 Sample Output

```
======================================================================
AI SOC HELPER - XGBoost Network Intrusion Detection Model Trainer
======================================================================

Loading dataset from UNSW-NB15_sample.csv...
Dataset loaded: 220000 rows, 45 columns

=== PREPROCESSING ===
Target mapping: {'Normal': 0, 'DoS': 1, ...}
Target distribution:
0    165000    # Normal
1     28000    # DoS
2      8500    # Exploits
...

Categorical columns: ['proto', 'service', 'state']
Numerical columns: 41 features

=== DATA SPLITTING ===
Training set: 154000 samples (70%)
Test set: 66000 samples (30%)

=== MODEL TRAINING ===
XGBClassifier initialized with parameters: ...
Training on 154000 samples...
Model training complete!

=== MODEL EVALUATION ===
Classification Report (7 classes):
              precision    recall  f1-score   support

      Normal       0.98      0.99      0.99     49500
         DoS       0.96      0.94      0.95      8400
    Exploits       0.92      0.88      0.90      2550
    Fuzzers        0.85      0.80      0.82      1500
     Generic       0.89      0.91      0.90      2070
Reconnaissance     0.94      0.92      0.93      1480
       Other       0.87      0.85      0.86       900

=== SAVING ARTIFACTS ===
Model and artifacts saved to soc_model.pkl
Exported artifacts:
  - XGBClassifier (7 classes)
  - LabelEncoders for 3 categorical features
  - StandardScaler for normalization
  - Attack category mappings

======================================================================
TRAINING COMPLETE - Model ready for Wazuh/Logstash SOC pipeline
======================================================================
```

---

## 📂 Project Structure

```
.
├── train_soc_model.py          # Main training script
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
├── README.md                    # This file
├── UNSW-NB15_sample.csv        # Input dataset (not in repo)
├── soc_model.pkl               # Trained model (generated)
├── confusion_matrix.png        # Evaluation plot (generated)
└── feature_importance.png      # Feature plot (generated)
```

---

## 🔍 Troubleshooting

### "FileNotFoundError: UNSW-NB15_sample.csv"
Ensure the CSV file is in the current directory or provide the full path:
```bash
python train_soc_model.py --data C:\path\to\UNSW-NB15_sample.csv
```

### "ModuleNotFoundError: No module named 'xgboost'"
Install missing dependencies:
```bash
pip install -r requirements.txt
```

### "KeyError: 'attack_cat'"
Verify your CSV has the `attack_cat` column with expected values.

---

## 🎓 Educational Context

This project is part of the **AI SOC Helper Graduation Project**, demonstrating:
- End-to-end ML pipeline design for cybersecurity
- Handling imbalanced multi-class classification
- Feature engineering and preprocessing best practices
- Model evaluation and interpretability (feature importance)
- Production-ready model serialization

---

## 📄 License

Educational use for graduation projects.

---

**Contact:** AI SOC Helper Project | 2026
