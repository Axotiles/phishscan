"""Step 5: run phishscan over a whole folder of .eml files and save a CSV.

Usage:
    python -m phishscan.batch samples/legit    --label legit    --out results.csv
    python -m phishscan.batch samples/phishing --label phishing --out results.csv --append

The summary at the end gives you the accuracy numbers for your README / resume:
  - for a 'legit' folder:    false positives = legit emails that got flagged
  - for a 'phishing' folder: detected        = phishing emails that got flagged
"flagged" means the verdict is SUSPICIOUS or LIKELY PHISHING (not LOW RISK).
"""
import argparse
import csv
from pathlib import Path

from .__main__ import run_all

COLUMNS = ["file", "label", "score", "verdict", "num_findings", "top_findings"]


def scan_folder(folder, label):
    rows = []
    for path in sorted(Path(folder).glob("*.eml")):
        try:
            result = run_all(str(path))
            rows.append(
                {
                    "file": path.name,
                    "label": label,
                    "score": result["score"],
                    "verdict": result["verdict"],
                    "num_findings": len(result["findings"]),
                    "top_findings": ";".join(f["check"] for f in result["findings"][:3]),
                }
            )
        except Exception as error:  # one broken email must not stop the whole run
            rows.append(
                {
                    "file": path.name,
                    "label": label,
                    "score": "",
                    "verdict": "ERROR",
                    "num_findings": "",
                    "top_findings": f"{type(error).__name__}: {error}",
                }
            )
    return rows


def write_csv(rows, out_path, append):
    out = Path(out_path)
    write_header = not (append and out.exists())
    with open(out, "a" if append else "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


def print_summary(rows, label):
    total = len(rows)
    errors = [r for r in rows if r["verdict"] == "ERROR"]
    scored = [r for r in rows if r["verdict"] != "ERROR"]
    flagged = [r for r in scored if r["verdict"] != "LOW RISK"]

    print(f"Scanned {total} emails ({len(errors)} errors)")
    if not scored:
        return
    if label == "legit":
        print(f"False positives: {len(flagged)}/{len(scored)} ({100 * len(flagged) / len(scored):.0f}%)")
        for r in flagged:
            print(f"  {r['file']}: {r['verdict']} ({r['score']}) {r['top_findings']}")
    elif label == "phishing":
        missed = [r for r in scored if r["verdict"] == "LOW RISK"]
        print(f"Detected: {len(flagged)}/{len(scored)} ({100 * len(flagged) / len(scored):.0f}%)")
        for r in missed:
            print(f"  MISSED {r['file']}: score {r['score']} {r['top_findings']}")
    else:
        print(f"Flagged: {len(flagged)}/{len(scored)}")
    for r in errors:
        print(f"  ERROR {r['file']}: {r['top_findings']}")


def main():
    parser = argparse.ArgumentParser(description="Scan a folder of .eml files")
    parser.add_argument("folder", help="folder containing .eml files")
    parser.add_argument("--label", choices=["legit", "phishing", "unknown"], default="unknown",
                        help="what you know these emails to be (used for the accuracy summary)")
    parser.add_argument("--out", default="results.csv", help="CSV file to write")
    parser.add_argument("--append", action="store_true", help="add to the CSV instead of overwriting")
    args = parser.parse_args()

    rows = scan_folder(args.folder, args.label)
    write_csv(rows, args.out, args.append)
    print_summary(rows, args.label)
    print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()
