#!/usr/bin/env python
import argparse
import sys

print("Before argparse", flush=True)
sys.stdout.flush()

parser = argparse.ArgumentParser(description='Test')
parser.add_argument('--data', type=str, required=True, help='Data path')

print("After parser creation", flush=True)
sys.stdout.flush()

args = parser.parse_args()

print(f"Args parsed: {args.data}", flush=True)
sys.stdout.flush()
