"""Label data/manual_baseline.csv one rule at a time.

For each rule: shows its logsource and detection, lists the implementations of
its technique, and asks which ones it SHOULD detect, judged from the rule text only.

    python scripts/label_baseline.py

Answer with numbers separated by spaces (e.g. `1 3`), Enter = none, `q` = save and quit.
Progress is saved after every rule; rerun to continue where you stopped.
DCC claims are deliberately not shown.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "data" / "manual_baseline.csv"


def main() -> int:
    csv.field_size_limit(sys.maxsize)
    with PATH.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
        fields = list(rows[0].keys())

    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        groups.setdefault((r["rule_file"], r["technique_id"]), []).append(r)

    todo = [(k, g) for k, g in groups.items() if any(r["should_detect"] == "" for r in g)]
    done = len(groups) - len(todo)
    print(f"{done}/{len(groups)} rule groups labelled, {len(todo)} to go\n")

    for n, ((rule_file, tech), group) in enumerate(todo, start=done + 1):
        first = group[0]
        print("=" * 80)
        print(f"[{n}/{len(groups)}] {tech}  {first['rule_title']}")
        print(f"file:      {rule_file}")
        print(f"logsource: {first['logsource']}")
        det = first["detection"]
        print(f"detection: {det[:1500]}{' ...[truncated]' if len(det) > 1500 else ''}\n")
        for i, r in enumerate(group, start=1):
            src = "  (manual)" if r["implementation_source"] == "manual" else ""
            print(f"  {i}. {r['implementation']}{src}")
        ans = input("\nshould detect (numbers / Enter = none / q): ").strip().lower()
        if ans == "q":
            break
        try:
            picked = {int(x) for x in ans.split()} if ans else set()
        except ValueError:
            print("numbers only, skipping this rule for now\n")
            continue
        note = input("rationale (optional, Enter to skip): ").strip()
        for i, r in enumerate(group, start=1):
            r["should_detect"] = "yes" if i in picked else "no"
            r["rationale"] = note
        with PATH.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print()

    left = sum(r["should_detect"] == "" for r in rows)
    print(f"saved. {left} cells left.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
