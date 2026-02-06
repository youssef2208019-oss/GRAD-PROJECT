#!/usr/bin/env python
"""Quick test to see where the script hangs"""
import sys
print("START TEST", flush=True)
sys.stdout.flush()

try:
    print("Importing pandas...", flush=True)
    sys.stdout.flush()
    import pandas as pd
    
    print("Loading CSV...", flush=True)
    sys.stdout.flush()
    df = pd.read_csv('merged_dataset.csv', nrows=100)
    
    print(f"Loaded: {df.shape}", flush=True)
    sys.stdout.flush()
    print("SUCCESS", flush=True)
    
except Exception as e:
    print(f"ERROR: {e}", flush=True)
    import traceback
    traceback.print_exc()
    sys.exit(1)
