"""Run MITRE DCC on SigmaHQ rules tagged with pilot techniques and freeze its claims.

Outputs:
  data/pilot_rules.csv       rules in scope (path, title, status, pilot techniques)
  data/dcc_claims.csv        one row per rule x included catalog implementation: DCC says covered yes/no
  data/manual_baseline.csv   template for the author's should-detect labels (DCC claims NOT shown, to avoid bias)
  analysis/outputs/dcc_pilot.xlsx   raw DCC workbook
"""
from __future__ import annotations

import csv
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
import yaml

from breakpoint import DATA, PILOT_TECHNIQUES, ROOT, SIGMA_RULES, STP_DCC


def rule_techniques(raw: dict) -> list[str]:
    tags = [str(t).lower() for t in raw.get("tags") or []]
    return [t.split(".", 1)[1].upper() for t in tags if t.startswith("attack.t")]


def compact_detection(raw: dict) -> str:
    d = {k: v for k, v in (raw.get("detection") or {}).items()}
    return yaml.safe_dump(d, default_flow_style=True, width=10_000, sort_keys=False).strip()


def main() -> int:
    if not SIGMA_RULES.exists() or not STP_DCC.exists():
        print("run `make fetch` first", file=sys.stderr)
        return 1

    # 1. Rules in scope
    rules = []
    for path in sorted(SIGMA_RULES.rglob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        techs = [t for t in rule_techniques(raw) if t in PILOT_TECHNIQUES]
        if not techs or raw.get("status") == "deprecated":
            continue
        rules.append({"path": path, "raw": raw, "techs": techs})

    with (DATA / "pilot_rules.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rule_file", "rule_path", "title", "status", "level", "logsource", "pilot_techniques"])
        for r in rules:
            ls = r["raw"].get("logsource") or {}
            w.writerow([r["path"].name, r["path"].relative_to(SIGMA_RULES.parent.parent).as_posix(),
                        r["raw"].get("title"), r["raw"].get("status"), r["raw"].get("level"),
                        "/".join(str(ls.get(k)) for k in ("product", "category", "service") if ls.get(k)),
                        ";".join(r["techs"])])

    # 2. Run DCC on exactly these rules
    out_xlsx = ROOT / "analysis" / "outputs" / "dcc_pilot.xlsx"
    out_xlsx.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        for r in rules:
            shutil.copy(r["path"], Path(tmp) / r["path"].name)
        subprocess.run([sys.executable, "-I", str(STP_DCC / "coveragecalculator.py"), tmp,
                        "--out-prefix", str(out_xlsx.with_suffix(""))],
                       cwd=STP_DCC, check=True, stdout=subprocess.DEVNULL)

    cov = pd.read_excel(out_xlsx, sheet_name="Implementation Coverage")
    claimed: dict[tuple[str, str], set[str]] = {}
    for _, row in cov.iterrows():
        if row["Implementation Covered"] != "yes":
            continue
        files = {Path(f.strip()).name for f in str(row["Analytic Files"]).split(";") if f.strip()}
        claimed[(row["ATT&CK Technique ID"], row["Technique Implementation name"])] = files

    # 3. Cells: rule x included catalog implementation of the same technique
    impl = pd.read_csv(DATA / "pilot_implementations.csv")
    included = impl[impl["status"] == "include"]

    dcc_rows, baseline_rows = [], []
    for r in rules:
        for tech in r["techs"]:
            for _, im in included[included["technique_id"] == tech].iterrows():
                cell = {"technique_id": tech, "rule_file": r["path"].name, "implementation": im["implementation"]}
                if im["source"] == "catalog":
                    covered = r["path"].name in claimed.get((tech, im["implementation"]), set())
                    dcc_rows.append({**cell, "dcc_covered": "yes" if covered else "no"})
                ls = r["raw"].get("logsource") or {}
                baseline_rows.append({**cell,
                                      "implementation_source": im["source"],
                                      "rule_title": r["raw"].get("title"),
                                      "logsource": "/".join(str(ls.get(k)) for k in ("product", "category", "service") if ls.get(k)),
                                      "detection": compact_detection(r["raw"]),
                                      "should_detect": "", "rationale": ""})

    for name, rows in (("dcc_claims.csv", dcc_rows), ("manual_baseline.csv", baseline_rows)):
        with (DATA / name).open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

    yes = sum(r["dcc_covered"] == "yes" for r in dcc_rows)
    print(f"rules in scope: {len(rules)}")
    print(f"dcc_claims.csv: {len(dcc_rows)} cells, DCC says covered in {yes} ({100 * yes / len(dcc_rows):.0f}%)")
    print(f"manual_baseline.csv: {len(baseline_rows)} cells to label")
    return 0


if __name__ == "__main__":
    sys.exit(main())
