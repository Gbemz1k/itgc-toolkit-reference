# Scope, limitations and exclusions

Paste section 1 of this into the report. The exclusions are the part that makes
it an audit rather than a checklist — a reviewer looks for them first.

---

## Scope

**In scope.** All accounts, systems, repositories and workstations under my
personal control or under Shego Holdings' control as at the review date.

**Out of scope.** University-managed systems and accounts, including any former university address. I do not own these systems and have no authority to test
them. Any system owned by a third party is likewise excluded.

---

## Scope limitation

This is a single-person environment. There is no segregation of duties to test,
and the auditor is also the control owner. Both facts limit the assurance this
review provides, and neither is hidden.

ITGC-AC-03 was **reworded** rather than dropped for the same reason. The standard
objective is *"administrative privilege is restricted"*, which is not meaningful
when one person owns everything. The objective tested here is *"administrative
access is documented and intentional"*, which is.

ITGC-CM-02 is expected to fail in single-maintainer repositories. Requiring
review of one's own pull request is not a control. Where the exception arises
from a solo repository, the recommendation is the compensating control —
protected branch plus required status checks — rather than a self-review.

---

## Controls considered and excluded

### Credential rotation (CIS 5.2)

**Excluded for lack of evidence.** The intended test was that credentials on
high-criticality systems are rotated at least annually. No reliable
last-changed date is exposed by the browser credential store, so the test could
only have been satisfied by asserting a date rather than evidencing one.

A control tested against a number the auditor made up is worse than no control.
Excluded, and recorded here so the exclusion is visible.

### Program Development (ITGC domain)

**Excluded as not applicable.** The domain covers controls over how new systems
are developed and promoted to production. There is no formal SDLC, no separate
environments, and no promotion process in this environment. One of the four ITGC
domains is therefore out of scope, deliberately.

### Log review (CIS 8.x)

**Excluded for lack of an evidenceable control.** Audit logs exist and are
readable for Google and GitHub, but the control objective is that logs are
*reviewed*, and there is currently no review process to evidence. Recorded as a
gap for the next review rather than tested and failed.

---

## Evidence limitations in the current run

These are stated in the report rather than quietly passed:

| Control | Limitation |
|---|---|
| ITGC-AU-02 | Not tested. Requires a browser credential export, which is a plaintext file and is the account holder's to produce and delete. |
| ITGC-CM-01/02/03 | Repository list collected unauthenticated, so branch protection and secret-scanning configuration could not be read. Repositories are excluded from the population rather than reported as failures. |
| ITGC-OP-03 | Encryption status requires an elevated shell. Reported as not tested. |
| ITGC-TP-01 | Two of four data-access grants remain unenumerated and are carried as findings in their own right. |

**Missing evidence is a scope limitation, not an exception.** The tool is written
to report it that way, which is why `ITGC-CM-01` shows a population of zero
rather than seven failures.
