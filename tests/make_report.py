import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
SHORT = {"VULNERABLE": "LEAK", "SAFE": "ok", "FALSE_POSITIVE": "FP", "ERROR": "ERR", "ERROR/BLOCKED": "ERR"}

runs = {}
for f in sorted(RES.glob("*.csv")):
    runs[f.stem] = list(csv.DictReader(open(f, encoding="utf-8")))

lines = ["# Results summary", "", "| Run | Attacks that worked | Success rate | Normal request (TC12) |", "|---|---|---|---|"]
for name, data in runs.items():
    attacks = [r for r in data if r["id"] != "TC12"]
    vuln = sum(r["result"] == "VULNERABLE" for r in attacks)
    benign = next((r["result"] for r in data if r["id"] == "TC12"), "n/a")
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