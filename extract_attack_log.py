#!/usr/bin/env python
"""Extract a real DoS attack row from merged_dataset.csv and save as JSON."""
import json
import sys
import pandas as pd


def _save_row(row, out_path: str, reason: str = ""):
    row_dict = row.to_dict()

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(row_dict, f, indent=2)

    print(f"Saved {out_path} {f'({reason})' if reason else ''}:")
    print(json.dumps(row_dict, indent=2))


def main():
    data_path = "merged_dataset.csv"
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        print(f"ERROR: Failed to load {data_path}: {e}")
        sys.exit(1)

    if 'AttackCategory' in df.columns:
        target_col = 'AttackCategory'
    elif 'attack_cat' in df.columns:
        target_col = 'attack_cat'
    else:
        print("ERROR: No attack category column found (AttackCategory/attack_cat)")
        sys.exit(1)

    # Exploits: top by dloss
    exploits_df = df[df[target_col].astype(str).str.lower() == 'exploits']
    if exploits_df.empty:
        print(f"ERROR: No Exploits rows found using {target_col}")
    else:
        if 'dloss' in exploits_df.columns:
            exploits_df = exploits_df.copy()
            exploits_df['dloss'] = pd.to_numeric(exploits_df['dloss'], errors='coerce')
            exploit_row = exploits_df.sort_values(by='dloss', ascending=False).iloc[0]
        else:
            exploit_row = exploits_df.iloc[0]
        _save_row(exploit_row, "real_exploit.json", "top dloss")

    # Reconnaissance: top by rate
    recon_df = df[df[target_col].astype(str).str.lower() == 'reconnaissance']
    if recon_df.empty:
        print(f"ERROR: No Reconnaissance rows found using {target_col}")
    else:
        if 'rate' in recon_df.columns:
            recon_df = recon_df.copy()
            recon_df['rate'] = pd.to_numeric(recon_df['rate'], errors='coerce')
            recon_row = recon_df.sort_values(by='rate', ascending=False).iloc[0]
        else:
            recon_row = recon_df.iloc[0]
        _save_row(recon_row, "real_recon.json", "top rate")

    # Generic: top by sttl
    generic_df = df[df[target_col].astype(str).str.lower() == 'generic']
    if generic_df.empty:
        print(f"ERROR: No Generic rows found using {target_col}")
    else:
        if 'sttl' in generic_df.columns:
            generic_df = generic_df.copy()
            generic_df['sttl'] = pd.to_numeric(generic_df['sttl'], errors='coerce')
            generic_row = generic_df.sort_values(by='sttl', ascending=False).iloc[0]
        else:
            generic_row = generic_df.iloc[0]
        _save_row(generic_row, "real_generic.json", "top sttl")

    # Fuzzers: top by sbytes
    fuzz_df = df[df[target_col].astype(str).str.lower() == 'fuzzers']
    if fuzz_df.empty:
        print(f"ERROR: No Fuzzers rows found using {target_col}")
    else:
        if 'sbytes' in fuzz_df.columns:
            fuzz_df = fuzz_df.copy()
            fuzz_df['sbytes'] = pd.to_numeric(fuzz_df['sbytes'], errors='coerce')
            fuzz_row = fuzz_df.sort_values(by='sbytes', ascending=False).iloc[0]
        else:
            fuzz_row = fuzz_df.iloc[0]
        _save_row(fuzz_row, "real_fuzzer.json", "top sbytes")


if __name__ == "__main__":
    main()
