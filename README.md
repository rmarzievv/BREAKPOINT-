# BREAKPOINT

**Executed ground truth for detection engineering in the AI era.**

Detection engineering increasingly runs on cheap, AI-generated or AI-scored proxies: LLM-drafted implementation catalogs, analytic coverage calculators, synthetic attack logs, LLM judges. BREAKPOINT executes real implementations of ATT&CK techniques on a Windows lab host, verifies each one with an oracle, and uses the resulting telemetry as ground truth to measure which of those proxies can be trusted.

> Status: **Stage 1a (pilot), pre-registration in draft.** No execution results yet.

## Questions (Stage 1)

| | Question | Proxy under test |
|---|---|---|
| RQ1 | What fraction of each technique's implementations do SigmaHQ rules actually detect? | — |
| RQ2 | How accurate are MITRE's Detection Coverage Calculator (DCC) coverage claims? | [STP 5.0 DCC](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/detection-ttv/detectioncoverage/dcc/) |
| RQ3 | How valid are entries in MITRE's LLM-drafted implementation catalog? | [Implementation Catalog](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/detection-ttv/detectioncoverage/implementationcatalog/) |

Hypotheses, metrics and decision criteria are fixed in [PREREGISTRATION.md](PREREGISTRATION.md) before any execution.

## Early finding (static, from code review)

DCC credits a rule with covering an implementation when the rule's ATT&CK tag and data component match any step of that implementation; the rule's field conditions are not evaluated. Example: a rule for `python.exe … adidnsdump` is counted as covering ARP cache enumeration and ICMP ping sweeps. Details: [docs/recon/2026-10-29-dcc-recon.md](docs/recon/2026-10-29-dcc-recon.md). Whether this matters in practice is what the execution stage measures.

## Layout

| Path | Contents |
|---|---|
| `PREREGISTRATION.md` | Hypotheses, sample, procedure, metrics, pinned versions |
| `data/pilot_implementations.csv` | Catalog entries for the 6 pilot techniques, with inclusion decisions (E1–E4) |
| `data/pilot_rules.csv` | SigmaHQ rules in scope |
| `data/dcc_claims.csv` | DCC "covered" claim per rule × implementation (frozen before execution) |
| `data/manual_baseline.csv` | Author's should-detect labels per cell (filled before execution) |
| `breakpoint/` | Python package: evaluation via the pinned detection-as-code evaluator |
| `harness/` | Execution harness and oracles (Stage 1a, in progress) |
| `scripts/` | Fetch pinned inputs, build pilot list, run DCC |
| `vendor/detection-as-code` | Submodule: [pySigma → SQLite rule evaluator](https://github.com/rmarzievv/detection-as-code) |

## Reproduce

```bash
git clone --recursive https://github.com/rmarzievv/breakpoint.git && cd breakpoint
python -m venv .venv && source .venv/bin/activate
make setup
make            # fetch pinned inputs, rebuild data/, run tests
```

CI re-runs DCC on the pinned inputs and fails if the frozen claims in `data/` change.

## Scope and ethics

Single Windows 11 host without AD, isolated lab, harmless payloads, no credential theft. Evasions of specific commercial EDRs are not published. Findings about MITRE tooling will be shared with the CTID authors before publication.
