# itgc-toolkit

An IT general controls review of a personal technology environment, and the tool
that performs it.

Thirteen controls across four ITGC domains — access to programs and data, program
changes, third-party access, and computer operations — each mapped to **CIS
Controls v8, Implementation Group 1**. Every test runs against the **full
population**, never a sample.

Python 3.9+. **No third-party dependencies.** An audit tool a reviewer cannot
install is an audit tool nobody runs.

---

## What it does

```
python -m itgc status                                   # what evidence exists
python -m itgc collect passwords --csv exported.csv     # credential reuse, hashes only
python -m itgc collect github --owner USER --token ...  # repo configuration
python -m itgc test                                     # run all 13 control tests
python -m itgc report                                   # render the audit report
```

It produces three things an auditor would recognise:

| Output | What it is |
|---|---|
| `controls/control-matrix.csv` | The control framework: objective, test procedure, population source, evidence required, CIS mapping |
| `findings/findings.csv` | The findings register: severity, population, exception rate, recommendation, owner, due date, status |
| `reports/itgc-report.md` | The report: scope, approach, summary of results, findings by severity, remediation tracking |

---

## The controls

Sixteen controls. Three candidates were considered and **dropped with reasons**
(see `docs/scope-and-exclusions.md`): credential rotation, Program Development,
and log review. A matrix where nothing was dropped is a checklist, not an audit.

| ID | Domain | CIS v8 | Objective |
|---|---|---|---|
| ITGC-AC-01 | Access | 5.1 | An inventory of all accounts is maintained |
| ITGC-AC-02 | Access | 5.3 | Dormant accounts are closed within 180 days |
| ITGC-AC-03 | Access | 5.4 | Administrative access is documented and intentional |
| ITGC-AC-04 | Access | 5.1 | Deprecated identifiers are not in use |
| ITGC-AC-05 | Access | 5.1 | Account recovery methods are current and owner-controlled |
| ITGC-AC-06 | Access | 6.2 | Active sessions and trusted devices are recognised |
| ITGC-AU-01 | Access | 6.3 | MFA is enabled on all externally exposed accounts |
| ITGC-AU-02 | Access | 5.2 | Credentials are unique per system |
| ITGC-TP-01 | Third party | 3.3 | OAuth grants with sensitive scopes are reviewed and justified |
| ITGC-CM-01 | Program changes | 4.1 | Default branches are protected |
| ITGC-CM-02 | Program changes | 4.1 | Changes require review before merge |
| ITGC-CM-03 | Program changes | 16.12 | Secret scanning is enabled |
| ITGC-OP-01 | Operations | 11.1 | A documented backup exists for every critical system |
| ITGC-OP-02 | Operations | 11.5 | Recovery from backup is tested annually and passes |
| ITGC-OP-03 | Operations | 3.6 | Disk encryption is enabled on all workstation volumes |
| ITGC-OP-04 | Operations | 10.1 | Endpoint protection is enabled with current signatures |

---

## Three design decisions worth defending

**Credentials are never stored.** The control objective is *"credentials are
unique per system"*, and that can be satisfied with SHA-256 hashes alone. The
reuse test groups identical hashes and reports the systems involved. No plaintext
password is written to disk at any point.

**Severity is derived, not asserted.** Control criticality sets the floor; an
exception rate at or above 50% raises it one level. An auditor should be able to
explain why a finding is High without saying it felt High.

**Full population, every time.** Sampling is a concession to manual effort. Once
the test is code, the concession is unnecessary — so the tool tests everything and
reports the exception rate alongside the count.

---

## Repository layout

```
controls/control-matrix.csv      the framework
inventory/                       what you are auditing (git-ignored: it is personal)
evidence/                        collected evidence (git-ignored)
findings/findings.csv            the findings register (git-ignored)
reports/itgc-report.md           the report (git-ignored)
itgc/collectors/                 evidence gathering
itgc/controls.py                 one function per control test
itgc/engine.py                   severity, findings register
itgc/report.py                   report rendering
```

Inventory, evidence, findings and reports are git-ignored by default, because
this repository audits a real environment. Publish the **tool and the framework**;
keep the workpapers local, or publish a redacted report only.

---

## Scope limitation

This is a review of a single-person environment, which means there is no
segregation of duties to test and the auditor is also the control owner. Both
facts are stated in the report rather than glossed over. The framework and the
test suite transfer unchanged to a multi-user environment; only the inventory
grows.
