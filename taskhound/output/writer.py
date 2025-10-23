import os
import json
import csv
from typing import List, Dict
from ..utils.logging import good

def write_plain(outdir: str, host: str, lines: List[str]):
    os.makedirs(outdir, exist_ok=True)
    safe = host.replace(":", "_")
    path = os.path.join(outdir, f"{safe}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    good(f"Wrote results to {path}")

def write_json(path: str, rows: List[Dict]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    good(f"Wrote JSON results to {path}")

def write_csv(path: str, rows: List[Dict]):
    fieldnames = ["host","path","type","runas","command","arguments","author","date","logon_type","enabled","trigger_type","start_boundary","interval","duration","days_interval","reason","credentials_hint","credential_guard","password_analysis"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    good(f"Wrote CSV results to {path}")
