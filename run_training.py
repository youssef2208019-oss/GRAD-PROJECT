#!/usr/bin/env python
"""Run training and save output to file"""
import subprocess
import sys
import os

os.chdir(r"C:\Users\lenovo\OneDrive\Desktop\GRAD PROJECT")

print(f"Starting training from: {os.getcwd()}")
print(f"Python executable: {sys.executable}")

with open("training_output.txt", "w") as f:
    f.write("Starting training...\n")
    f.flush()
    
    result = subprocess.run(
        [sys.executable, "train_direct.py"],
        stdout=f,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    f.write(f"\nProcess completed with return code: {result.returncode}\n")

print("Training output saved to training_output.txt")
print("=" * 70)

# Read and display the output
with open("training_output.txt", "r") as f:
    content = f.read()
    print(content)
