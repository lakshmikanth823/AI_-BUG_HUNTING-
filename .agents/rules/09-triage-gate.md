---
trigger: always_on
description: Sequential falsifiable triage decision procedure to evaluate candidate bug findings, eliminate false positives, and verify real impact.
---

# Triage Gate Protocol

This rule enforces a strict, sequential, falsifiable decision procedure before any candidate security finding is accepted, confirmed, or drafted into a report.

---

## STAGE 0 — EVIDENCE SUFFICIENCY (Hard Stop)

Reject the candidate finding immediately if ANY of the following four elements is missing, and name the missing item explicitly:
- **(a) Exact Request**: The complete HTTP request method, full URL, all relevant headers, and request body.
- **(b) Exact Response**: The complete HTTP response status code, relevant headers, and relevant response body excerpt.
- **(c) Attacker-Controlled Proof**: Proof that the observed behavior is attacker-controlled rather than self-inflicted (e.g. tested via a distinct second account, a second independent session, or a verified external out-of-band interaction actually received).
- **(d) In-Scope Asset Mapping**: The exact authorized program name and the specific in-scope asset hostname/CIDR listed in program scope.

> **Rule**: An automated scanner alert without a captured, reproducible request/response pair is NOT a finding. It is merely an unverified **LEAD**.

---

## STAGE 1 — IMPACT EVALUATION (The Seven Questions)

Every gate evaluation must answer all seven questions with a single-line clause justification:

1. **Cross-User Data Read**: Can an attacker read data belonging to a DIFFERENT user or tenant? Name the exact object whose authorization check is missing.
2. **Cross-User Data Mutation**: Can an attacker write, modify, or delete another user's data? Name the mutating request and affected resource.
3. **Execution or Unauthorized Request**: Can an attacker execute code, or cause the server to make a request to a destination the attacker chose? (If SSRF: specify which internal/collaborator host, and what response returned).
4. **Authentication / Session Hijack**: Can an attacker authenticate as, or take over the active session of, another user?
5. **Financial / Resource Abuse**: Can an attacker move, hold, or burn real money, financial credits, digital tokens, or paid service quota?
6. **Privilege-Free Reachability**: Can an unprivileged attacker reach this without prior administrative access, and does the finding survive a logged-out, different-tenant, or clean-device test?
7. **End-to-End Proof**: Is the business impact demonstrated end-to-end, or does it depend on unverified assumptions?

> **VERDICT RULE**: If Questions 1 through 5 are ALL "no", the finding is **INFORMATIONAL**. Kill it immediately.
> 
> *The following are informational by default unless chained into proven impact*:
> - Missing security headers (`CSP`, `X-Frame-Options`, `HSTS`, `X-Content-Type-Options`).
> - Missing rate limits without demonstrated automated brute-force or financial loss.
> - Verbose stack traces or error pages with no sensitive credentials or PII.
> - Public source maps (`.js.map`) with no production credentials or secrets.
> - CORS origin reflection without `Access-Control-Allow-Credentials: true` or authenticated data exfiltration.
> - Self-XSS (actions affecting only the executing user).

---

## STAGE 2 — EXPLOITABILITY REALITY CHECK

Evaluate operational hurdles:
- **Clean Session**: Is the vulnerability reproducible from a clean browser session with no cached state?
- **Unrealistic User Action**: Does exploitation require the victim to perform bizarre or multi-step manual actions?
- **Observed Defenses**: Is exploitation blocked by observed browser or network controls (`CSP`, `SameSite` cookies, WAF)? Did you prove an actual bypass, or assume one?
- **Race Condition Fidelity**: How many concurrent requests were sent ($N$), how many trials were attempted, and what was the measured success rate over $N$ tries?

---

## STAGE 3 — SEVERITY (Evidence-Based CVSS 3.1)

1. Formulate the CVSS 3.1 Base Score with the exact vector string written out (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`).
2. Justify each metric selection in one clause based purely on observed evidence, never hypothetical worst-case scenarios.
3. Cross-check against the target program's own published reward matrix (if available in `data/programs-ranked.csv` or program rules).
4. If CVSS and the program matrix differ, document both and indicate which standard the triage team enforces.

---

## STAGE 4 — DUPLICATE & DISCLOSED PRIOR ART CHECK

Search the corpus (`writeups-bug-bounty` 220 links, `writeups-ctf` 717 links) for the same target asset and vulnerability class.
- If a publicly disclosed report describes the same underlying root cause, note the reference.
- Reframe the report as an unaddressed variant or chain, rather than falsely claiming novelty.

---

## STAGE 5 — REPORT DRAFT GATE

Only proceed to drafting if Stages 0 through 3 pass and the finding is `VALID-PAYABLE`:
- Title following standard naming conventions.
- Formulated CVSS 3.1 vector string.
- Numbered, minimal, copy-pasteable reproduction sequence (`curl` or raw HTTP).
- Observed impact in one succinct sentence.
- Remediation guidance.
- Explicit note on second test account verification.

If reproduction steps cannot be written without assumptions or gaps, return to **STAGE 0**.

---

## OUTPUT CONTRACT

Every triage gate invocation must emit exactly this block:

```text
VERDICT:        KILL | LEAD | VALID-INFORMATIONAL | VALID-PAYABLE
STAGE REACHED:  0 | 1 | 2 | 3 | 4 | 5
BLOCKING GAP:   <the single most important missing piece, or "none">
SEVEN ANSWERS:  Q1: <yes/no, clause>; Q2: <yes/no, clause>; Q3: <yes/no, clause>; Q4: <yes/no, clause>; Q5: <yes/no, clause>; Q6: <yes/no, clause>; Q7: <yes/no, clause>
CVSS:           <vector string or "n/a">
NEXT ACTION:    <one concrete step>
```
