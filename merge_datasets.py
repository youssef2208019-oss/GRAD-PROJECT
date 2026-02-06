"""
Merge UNSW-NB15 Training and Testing JSON/CSV files into a single dataset.

This utility script combines separate training and testing JSON/CSV files into one consolidated
dataset that can be used with train_soc_model.py. The script handles column alignment,
duplicate removal, and basic validation.

Usage:
    python merge_datasets.py --train unsw_training_data.json --test unsw_testing_testing.json --output merged_dataset.csv
    python merge_datasets.py --train UNSW-NB15_TRAIN-20.csv --test UNSW-NB15-TEST.csv --output merged_dataset.csv
"""

import argparse
import pandas as pd
import sys
import os


def load_data(file_path: str) -> pd.DataFrame:
    """
    Load data from JSON, JSONL, or CSV file.
    
    Args:
        file_path: Path to JSON, JSONL, or CSV file
        
    Returns:
        DataFrame loaded from file
    """
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext == '.json':
        try:
            # Try standard JSON first
            return pd.read_json(file_path)
        except ValueError as e:
            if "Trailing data" in str(e):
                # If standard JSON fails, try JSONL (JSON Lines)
                print(f"    Standard JSON failed, trying JSONL format...")
                return pd.read_json(file_path, lines=True)
            else:
                raise
    elif file_ext == '.csv':
        return pd.read_csv(file_path)
    else:
        raise ValueError(f"Unsupported file format: {file_ext}")


def merge_datasets(train_path: str, test_path: str, output_path: str) -> None:
    """
    Merge training and testing JSON/CSV files into a single dataset.
    
    Args:
        train_path: Path to training JSON/CSV
        test_path: Path to testing JSON/CSV
        output_path: Path to save merged dataset (as CSV)
    """
    print("=" * 70)
    print("UNSW-NB15 Dataset Merger (JSON/CSV Support)")
    print("=" * 70)
    
    try:
        # Load datasets
        print(f"\nLoading training dataset from {train_path}...")
        df_train = load_data(train_path)
        print(f"  ✓ Loaded: {df_train.shape[0]} rows, {df_train.shape[1]} columns")
        print(f"  Columns: {list(df_train.columns)[:5]}...")
        
        print(f"\nLoading testing dataset from {test_path}...")
        df_test = load_data(test_path)
        print(f"  ✓ Loaded: {df_test.shape[0]} rows, {df_test.shape[1]} columns")
        print(f"  Columns: {list(df_test.columns)[:5]}...")
        
        # Validate columns match
        if set(df_train.columns) != set(df_test.columns):
            print("\n[WARNING] Column mismatch detected!")
            train_only = set(df_train.columns) - set(df_test.columns)
            test_only = set(df_test.columns) - set(df_train.columns)
            
            if train_only:
                print(f"  Columns in train only: {train_only}")
            if test_only:
                print(f"  Columns in test only: {test_only}")
            
            # Use common columns
            common_cols = list(set(df_train.columns) & set(df_test.columns))
            print(f"\n  Using {len(common_cols)} common columns")
            df_train = df_train[common_cols]
            df_test = df_test[common_cols]
        
        # Merge datasets
        print("\nMerging datasets...")
        df_merged = pd.concat([df_train, df_test], ignore_index=True)
        print(f"  ✓ Merged: {df_merged.shape[0]} rows, {df_merged.shape[1]} columns")
        
        # Check for duplicates
        duplicates = df_merged.duplicated().sum()
        if duplicates > 0:
            print(f"\n[INFO] Found {duplicates} duplicate rows")
            print("  Removing duplicates...")
            df_merged = df_merged.drop_duplicates(ignore_index=True)
            print(f"  ✓ After deduplication: {df_merged.shape[0]} rows")
        
        # Check for missing values
        print("\nData Quality Check:")
        missing_summary = df_merged.isnull().sum()
        if missing_summary.sum() > 0:
            print("  Missing values per column:")
            for col, count in missing_summary[missing_summary > 0].items():
                pct = (count / len(df_merged)) * 100
                print(f"    - {col}: {count} ({pct:.2f}%)")
        else:
            print("  ✓ No missing values detected")
        
        # Display target distribution if available
        if 'attack_cat' in df_merged.columns:
            print("\nTarget Distribution (attack_cat):")
            dist = df_merged['attack_cat'].value_counts().sort_values(ascending=False)
            for attack_type, count in dist.items():
                pct = (count / len(df_merged)) * 100
                print(f"  - {attack_type}: {count} ({pct:.2f}%)")
        elif 'label' in df_merged.columns:
            print("\nTarget Distribution (label):")
            dist = df_merged['label'].value_counts().sort_values(ascending=False)
            for attack_type, count in dist.items():
                pct = (count / len(df_merged)) * 100
                print(f"  - {attack_type}: {count} ({pct:.2f}%)")
        
        # Save merged dataset as CSV
        print(f"\nSaving merged dataset to {output_path}...")
        df_merged.to_csv(output_path, index=False)
        print(f"  ✓ Saved: {df_merged.shape[0]} rows, {df_merged.shape[1]} columns")
        
        print("\n" + "=" * 70)
        print("MERGE COMPLETE - Ready for train_soc_model.py")
        print("=" * 70)
        print(f"\nNext step: Run training script")
        print(f"  python train_soc_model.py --data {output_path}")
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Merge failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Merge UNSW-NB15 training and testing JSON/CSV files'
    )
    parser.add_argument(
        '--train',
        type=str,
        required=True,
        help='Path to training JSON/CSV file (e.g., unsw_training_data.json or UNSW-NB15_TRAIN-20.csv)'
    )
    parser.add_argument(
        '--test',
        type=str,
        required=True,
        help='Path to testing JSON/CSV file (e.g., unsw_testing_testing.json or UNSW-NB15-TEST.csv)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='merged_dataset.csv',
        help='Output path for merged dataset (default: merged_dataset.csv)'
    )
    
    args = parser.parse_args()
    merge_datasets(args.train, args.test, args.output)


if __name__ == '__main__':
    main()
