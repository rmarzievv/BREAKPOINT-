# BREAKPOINT — Pre-registration (Stage 1a, pilot)

**Status:** DRAFT. Becomes frozen at the commit tagged `prereg-v1`, made before the first execution. After that this file is not edited; any deviation is recorded in `DEVIATIONS.md` with date and reason.
**Author:** Riiad Marziev · **Frozen on:** see tag `prereg-v1`

---

## 1. Research questions

- **RQ1.** What fraction of each technique's implementations do SigmaHQ rules actually detect?
- **RQ2.** How accurate are MITRE DCC's implementation-coverage claims when compared against execution-based measurement?
- **RQ3.** How valid are the entries in MITRE's LLM-drafted implementation catalog: are they executable, distinguishable by telemetry, and does the predicted data component match the observed one?

## 2. Hypotheses and decision criteria

A hypothesis is **supported** only if its criterion is met. Otherwise it is **not supported**, and that result is published.

| ID | Hypothesis | Support criterion |
|---|---|---|
| H1 | DCC systematically **overestimates** implementation coverage, because it credits coverage on matching ATT&CK tag + data component without checking rule conditions | Precision of DCC "covered" claims at the rule × implementation cell level < 0.5, with the upper bound of the 95% bootstrap CI < 0.7 |
| H1b | The overestimate persists against a manual analytic baseline (tag + data component + field-value review) | DCC precision is lower than manual-baseline precision by > 0.2, Wilcoxon p < 0.05 across techniques |
| H2 | Some LLM-catalog entries are not executable on an in-scope Windows host, duplicate other entries, or predict a data component absent from the telemetry | ≥ 20% of sampled entries fall into at least one of the three defect categories |
| H3 | Process-creation rules cover implementations that spawn a new process better than implementations via API, WMI or PowerShell inside an already-running process | Measured coverage is higher in the first group by > 0.2 |

Stage 2–3 hypotheses (synthetic logs, LLM judge, Goodhart) will be pre-registered separately.

## 3. Sample

### 3.1 Pilot techniques
T1018, T1016, T1057, T1082, T1053.005, T1543.003.

### 3.2 Implementations
Source: `implementation_catalog_with_attack_components.xlsx` (Sheet1), branch `stp3`.

**Exclusion criteria** (decided before execution; the reason is recorded per entry):
- E1: not Windows (`/proc`, network-device CLI);
- E2: requires AD, cloud, or a remote host (AD computer query, Azure AD, cloud metadata, Remote *);
- E3: credential theft or a payload with risk outside the lab;
- E4: substantive duplicate of another entry. A duplicate is **executed once**, counted as a catalog defect in RQ3, and treated as a single implementation in RQ1–RQ2.

**Manual implementations** (not from the catalog) are allowed, tagged `source=manual`, and excluded from RQ2–RQ3. Example: T1018 via `Get-NetNeighbor`.

The final implementation list with inclusion status → `data/pilot_implementations.csv`, committed **together with this file**.

### 3.3 Rules
All SigmaHQ rules under `rules/windows/` tagged with a pilot technique at the pinned commit. Rules with status `deprecated` are excluded. Rules the backend cannot convert are reported separately as `unconvertible`.

## 4. Procedure

1. Each implementation is executed **n = 3 times** on PVLAB from a clean snapshot.
2. An **oracle** verifies the effect (output obtained, task created, service created/modified). Outcome: `success`, `fail`, or `blocked` (blocked by Defender).
3. Executions with a non-`success` outcome are excluded from coverage calculation, counted separately, and used in RQ3 (executability).
4. Events are linked to an execution via Sysmon `ProcessGuid`, the process tree rooted at the harness, and a time window. **No command-line markers are used.**
5. Rules are evaluated with two engines: pySigma → SQLite (primary) and <Chainsaw | Hayabusa | Zircolite> (control).

## 5. Definitions

- **Detected (rule × implementation cell):** the rule fires on at least one event linked to a successful execution of the implementation, in at least 2 of 3 repetitions.
- **DCC "covered" claim:** `Implementation Covered = yes` in the `Implementation Coverage` sheet, with the rule listed in that implementation's `Analytic Files`.
- **Manual baseline:** the analyst (author) decides "should detect / should not" from the rule text and the implementation description, **before** seeing execution results. Decisions are committed to `data/manual_baseline.csv` before the run.
- **Technique implementation coverage:** fraction of included implementations detected by at least one rule.

## 6. Metrics and statistics

- Confusion matrix of DCC claims vs. measurement; precision, recall.
- Same for the manual baseline.
- Coverage per rule and per technique.
- Fraction of defective catalog entries by category (RQ3).
- Engine disagreement: number of cells where verdicts differ.
- **Intervals:** cluster bootstrap over techniques, 10,000 resamples, seed = 1337.
- **Paired comparisons:** Wilcoxon signed-rank across techniques.
- With only 6 techniques, the pilot is primarily a test of the setup; strong conclusions wait for Stage 1b (12 techniques).

## 7. Pinned versions

| Component | Version |
|---|---|
| summiting-the-pyramid (`stp3`) | `13f15f4bccc8e33510f281406eb59b542fd34b24` |
| SigmaHQ | `05d1031f537e830b76da53bae2400c5814c89165` |
| Windows 11 (PVLAB) | <build> |
| Sysmon | <version> + config <source, commit> |
| pySigma + backend | <versions> |
| Control engine | <version> |
| Defender | exclusion only for `<lab folder>`, signatures <version> |

## 8. Out of scope

- Evasions of specific commercial EDRs are not published.
- ATT&CK mapping errors in SigmaHQ are reported but **not fixed** before the run.

## 9. Known threats to validity

Single host, single build, single Sysmon config; catalog bias is inherited by the sample; pySigma semantics ≠ a production SIEM; the manual baseline is labelled by the author (mitigation: labelled before the run and published in full).
