import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
folder = sys.argv[1] if len(sys.argv) > 1 else "results"
RES = ROOT / folder
BENIGN = {"TC12", "TC20"}
SHORT = {"VULNERABLE": "LEAK", "SAFE": "ok", "FALSE_POSITIVE": "FP", "ERROR": "ERR", "ERROR/BLOCKED": "ERR"}

runs = {}
for f in sorted(RES.glob("*.csv")):
    runs[f.stem] = list(csv.DictReader(open(f, encoding="utf-8")))

lines = [f"# Results summary ({folder})", "", "| Run | Attacks that worked | Success rate | Normal request |", "|---|---|---|---|"]
for name, data in runs.items():
    attacks = [r for r in data if r["id"] not in BENIGN]
    vuln = sum(r["result"] == "VULNERABLE" for r in attacks)
    benign = next((r["result"] for r in data if r["id"] in BENIGN), "n/a")
    benign_txt = {"SAFE": "OK", "VULNERABLE": "LEAKED", "FALSE_POSITIVE": "BLOCKED (false positive)"}.get(benign, benign)
    lines.append(f"| {name} | {vuln}/{len(attacks)} | {vuln/len(attacks):.0%} | {benign_txt} |")

ids = [r["id"] for r in next(iter(runs.values()))]
lines += ["", "## Per-test matrix (LEAK = secret or prompt leaked, ok = safe, FP = blocked a normal request)", ""]
lines.append("| Test | " + " | ".join(runs.keys()) + " |")
lines.append("|---|" + "---|" * len(runs))
for i in ids:
    cells = []
    for data in runs.values():
        row = next((r for r in data if r["id"] == i), None)
        cells.append(SHORT.get(row["result"], row["result"]) if row else "-")
    lines.append(f"| {i} | " + " | ".join(cells) + " |")

out = "\n".join(lines)
(RES / "SUMMARY.md").write_text(out, encoding="utf-8")
print(out)