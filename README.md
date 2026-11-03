# AI Bug Hunting & Security Research Framework (`AI_-BUG_HUNTING-`)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Safety Protocol: Strict](https://img.shields.io/badge/Safety_Gate-Enforced-red.svg)](#scope-authorisation-guard)
[![Benchmark: 18/18 Verified](https://img.shields.io/badge/Benchmark_Suite-18%2F18_Verified_(100%25_Pass)-brightgreen.svg)](#empirical-proofs--benchmark-evidence)

An autonomous, multi-tiered AI bug bounty hunting, reconnaissance, triage evaluation, and security research engine. Built with strict **Target Provenance**, **Permanent Deny Lists**, **Deterministic Triage Gates (Stages 0–5)**, and an ingested knowledge corpus of **9,879+ curated, de-duplicated, and verified security research URLs**.

---

## Table of Contents
1. [Architecture & System Design](#architecture--system-design)
2. [Directory Structure](#directory-structure)
3. [Safety & Scope Authorisation Guard](#safety--scope-authorisation-guard)
4. [Triage Gate Protocol (Stages 0–5)](#triage-gate-protocol-stages-05)
5. [Empirical Proofs & Benchmark Evidence](#empirical-proofs--benchmark-evidence)
6. [Live Target Testing & Proof-of-Concept](#live-target-testing--proof-of-concept)
7. [Knowledge Base & Full-Text Search](#knowledge-base--full-text-search)
8. [CLI Usage & Quickstart](#cli-usage--quickstart)
9. [Safety & Responsible Disclosure Policy](#safety--responsible-disclosure-policy)

---

## Architecture & System Design

```mermaid
flowchart TD
    subgraph Operator Console
        CLI["hunter.py (CLI Console)"]
    end

    subgraph Core Framework
        SG["ScopeGuard (core/scope_guard.py)<br/>Target Provenance & Deny-List Check"]
        KE["KnowledgeEngine (core/knowledge_engine.py)<br/>SQLite FTS5 Knowledge Retrieval"]
        RE["ReconEngine (core/recon.py)<br/>Asset Discovery & Subdomain Profiling"]
        RP["ReportGenerator (core/reporter.py)<br/>CVSS 3.1 & Disclosed Report Formatting"]
    end

    subgraph Triage Pipeline
        S0["Stage 0: Evidence Sufficiency<br/>Exact Req/Resp & Provenance"]
        S1["Stage 1: Seven Impact Questions<br/>Cross-Tenant, Mutating, RCE, Money"]
        S2["Stage 2: Reality Check<br/>WAF, CSP, SameSite, Clean Session"]
        S3["Stage 3: Evidence CVSS 3.1<br/>Vector Formulation & Program Matrix"]
        S4["Stage 4: Prior Art Check<br/>De-duplicate Disclosed Reports"]
        S5["Stage 5: Report Draft Gate<br/>Reproducible curl & Output Contract"]
    end

    subgraph Execution Targets
        LAB["Local Lab Carve-Out<br/>Juice Shop, DVWA, WebGoat, crAPI"]
        LIVE["In-Scope Live Program<br/>Low-rate PoC (≤1 RPS, Budget Clamp)"]
    end

    CLI --> SG
    SG -->|Authorized Lab| LAB
    SG -->|Authorized Bounty Program| LIVE
    SG -->|Deny-List / Out-of-Scope| STOP["Hard Stop (KILL)"]
    
    LAB --> S0
    LIVE --> S0
    S0 --> S1 --> S2 --> S3 --> S4 --> S5
    KE -.-> CLI
    RP <-- S5
```

---

## Directory Structure

| Directory / File | Description |
|---|---|
| `hunter.py` | Unified operator console CLI for scope validation, lab testing, methodology search, and triage evaluation. |
| `core/scope_guard.py` | Enforces target provenance, rate limits, request budgets, and blocks all cloud metadata and internal subnets. |
| `core/knowledge_engine.py` | High-speed interface to query 15 ingested vulnerability guides, payloads, and writeup archives. |
| `core/recon.py` | Reconnaissance engine supporting passive DNS, asset categorization, and port discovery. |
| `core/reporter.py` | Automated report generator that compiles triage verdicts and computes CVSS 3.1 vector strings. |
| `engine/triage_evaluator.py` | Falsifiable Stage 0–5 Triage Gate protocol evaluating candidate leads into KILL, LEAD, or VALID. |
| `engine/autonomous_hunter.py` | Autonomous hunting engine that loops through asset discovery, probing, and triage reporting. |
| `engine/authz_probe.py` | Targeted Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA) probe. |
| `engine/content_indexer.py` | Semantic chunker and SQLite FTS5 indexer for the markdown knowledge base. |
| `lab/` | Vulnerable application harnesses: `lab_controller.py`, `run_flipkart_probes.py`, and test suites. |
| `knowledge_base/` | 15 curated high-signal security repositories: OWASP WSTG, HackTricks, PayloadsAllTheThings, HackerOne reports, etc. |
| `data/` | Reference datasets: 460+ ranked programs (`programs-ranked.csv`), 9,879 URLs (`all-links.txt`), and `in_scope_assets.json`. |
| `.agents/rules/` | Antigravity model decision rules (`00-corpus-index.md`, `08-scope-authorisation.md`, `09-triage-gate.md`). |
| `by-category/` | 17 structured security reference listings with titles and live HTTP verification status. |
| `authored_18_results.json` | Complete benchmark dataset containing 18 empirical test cases with raw HTTP requests and responses. |

---

## Safety & Scope Authorisation Guard

The engine strictly operates under `.agents/rules/08-scope-authorisation.md` and `core/scope_guard.py`.

### 1. Target Provenance
- Active testing requires an explicitly listed asset in `data/programs-ranked.csv` or a verified admission document (`data/in_scope_assets.json`).
- Authorization is never assumed from public infrastructure or wildcard domains.

### 2. Permanent Deny List
Under no circumstances will the engine generate or execute requests targeting:
- `169.254.169.254` (AWS/GCP/Azure link-local metadata)
- `metadata.google.internal` (Google Cloud internal metadata)
- `100.100.100.200` (Alibaba Cloud metadata)
- `fd00:ec2::254` (IPv6 cloud metadata)
- `169.254.0.0/16` (Link-local network range)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private ranges)
- `*.internal`, `*.local` (Internal mDNS/DNS zones)
- `0.0.0.0` (Unspecified broadcast address)

### 3. Authorized Lab Carve-Out
As an explicit, bounded exception to private address bans, active testing is allowed strictly on loopback (`127.0.0.1` / `localhost`) and ONLY against these verified ports:
- `3000` — OWASP Juice Shop
- `8081` — OWASP WebGoat
- `8082` — Damn Vulnerable Web Application (DVWA)
- `9099` — OWASP WebWolf
- `8888` — OWASP crAPI

---

## Triage Gate Protocol (Stages 0–5)

To prevent scanner spam and invalid reports, every candidate finding is evaluated against a 6-stage falsifiable decision procedure:

```
[Candidate Lead]
       │
       ▼
[STAGE 0: Evidence Sufficiency] ──Missing exact Req/Resp or Scope?──► KILL (Stage 0)
       │
       ▼
[STAGE 1: Impact Evaluation]     ──Q1 through Q5 all 'No'?───────────► KILL / Informational (Stage 1)
       │ (Cross-User Read/Write, RCE, Auth Hijack, Financial Loss)
       ▼
[STAGE 2: Reality Check]         ──Blocked by WAF/CSP/SameSite?──────► KILL (Stage 2)
       │
       ▼
[STAGE 3: Severity Formulation]  ──Calculate CVSS 3.1 Vector & Reward Matrix
       │
       ▼
[STAGE 4: Prior Art Check]       ──Match Disclosed Reports & Variant Check
       │
       ▼
[STAGE 5: Report Draft Gate]     ──Output Minimal Reproducible curl Proof
```

### Output Contract
Every triage gate execution produces the standard machine-readable contract:

```text
VERDICT:        KILL | LEAD | VALID-INFORMATIONAL | VALID-PAYABLE
STAGE REACHED:  0 | 1 | 2 | 3 | 4 | 5
BLOCKING GAP:   <the single most important missing piece, or "none">
SEVEN ANSWERS:  Q1: <yes/no, clause>; Q2: <yes/no, clause>; Q3: <yes/no, clause>; Q4: <yes/no, clause>; Q5: <yes/no, clause>; Q6: <yes/no, clause>; Q7: <yes/no, clause>
CVSS:           <vector string or "n/a">
NEXT ACTION:    <one concrete step>
```

---

## Empirical Proofs & Benchmark Evidence

The framework's decision engine is continuously evaluated against an 18-exercise empirical benchmark suite (`authored_18_results.json` per `LAB-SETUP.md` Section 4). All 18 exercises execute against real running lab containers (Juice Shop 3000, DVWA 8082, WebGoat 8081, crAPI 8888, WebWolf 9099) and produce authentic, non-templated Seven Answer evaluation blocks.

### Benchmark Verification Results
- **Total Exercises**: 18
- **Attempted**: 18 / 18 (100%)
- **Matched Ground Truth**: 18 / 18 (100% Pass)
- **Mismatches**: 0
- **Templated Answers Detected**: 0 (all 18 Seven Answer blocks are empirically distinct)

| Suite Tier | Lab Service | Port | Vulnerability Tested | Ground Truth | Evaluator Verdict | Result |
|---|---|---|---|---|---|---|
| Tier 1 | None | — | Unattributed Scanner Alert without Req/Resp | KILL | KILL | MATCH |
| Tier 1 | Juice Shop | 3000 | Missing CSP Header on Static Asset | KILL | KILL | MATCH |
| Tier 1 | Juice Shop | 3000 | Verbose Stack Trace without PII | KILL | KILL | MATCH |
| Tier 1 | DVWA | 8082 | SQLi Impossible (Parameterized Defense) | KILL | KILL | MATCH |
| Tier 1 | Juice Shop | 3000 | Reflected Query Parameter (Self-XSS) | KILL | KILL | MATCH |
| Tier 2 | DVWA | 8082 | OS Command Injection (; whoami) | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 2 | DVWA | 8082 | SQL Injection at Low (UNION User Dump) | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 2 | Juice Shop | 3000 | SQLi Login Bypass (' OR 1=1--) | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 2 | crAPI | 8888 | Challenge 1 — BOLA on Vehicle Location | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 2 | crAPI | 8888 | Challenge 2 — BFLA Mechanic Reports | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 2 | crAPI | 8888 | Challenge — BFLA / Excessive Data Exposure | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 2 | WebGoat | 8081 | Path Traversal File Upload | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 3 | crAPI | 8888 | Challenge 3 — Password Reset ATO via OTP | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 3 | crAPI | 8888 | Challenge 15 — JWT HMAC Signature Forgery | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 3 | crAPI | 8888 | SSRF Targeting Cloud Metadata 169.254.169.254 | KILL | KILL | MATCH |
| Tier 3 | crAPI | 8888 | Challenge — BFLA Delete Vehicle Order | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 3 | WebGoat | 8081/9099 | SSRF / Auth Callback to WebWolf Landing | VALID-PAYABLE | VALID-PAYABLE | MATCH |
| Tier 3 | Juice Shop | 3000 | IDOR Single-Account Test (Missing Stage 0c) | LEAD | LEAD | MATCH |

Below are actual execution proofs demonstrating the triage gate:

### Proof 1: SQL Injection vs Parameterized Defensive Control (DVWA Port 8082)
* **Target:** `http://127.0.0.1:8082/vulnerabilities/sqli/`
* **Test Case:** SQL injection submitted at security level `impossible` using parameterized queries.
* **Raw Request:**
  ```http
  GET /vulnerabilities/sqli/?id=%27+OR+1%3D1--&Submit=Submit&user_token=07329cb9b485d675bd368a72e8a6bb80 HTTP/1.1
  Host: 127.0.0.1:8082
  Cookie: PHPSESSID=hkmvggro6tte9p9gig6pp7qiu4; security=impossible
  ```
* **Raw Response:**
  ```http
  HTTP/1.1 200 OK
  Content-Type: text/html;charset=UTF-8

  <form action="#" method="GET">...<input type='hidden' name='user_token' ... /></form>
  ```
* **Triage Verdict Contract:**
  ```text
  VERDICT:        KILL
  STAGE REACHED:  2
  BLOCKING GAP:   Exploitation failed on Stage 2 reality check: payload neutralized, zero records returned; parameterized query / server-side validation prevented execution.
  SEVEN ANSWERS:  Q1: no, parameterized query returned 0 rows; Q2: no, request is read-only select; Q3: no, database engine treated injection as literal string; Q4: no, zero credentials returned; Q5: no, financial attributes untouched; Q6: yes, unprivileged probe submitted; Q7: no, defensive control blocked execution
  CVSS:           n/a
  NEXT ACTION:    KILL finding; defense successfully mitigated vulnerability.
  ```

---

### Proof 2: Missing Security Header (Juice Shop Port 3000)
* **Target:** `http://127.0.0.1:3000/assets/public/favicon_js.ico`
* **Observation:** Missing `Content-Security-Policy` and `Strict-Transport-Security` on static assets.
* **Triage Verdict Contract:**
  ```text
  VERDICT:        KILL
  STAGE REACHED:  1
  BLOCKING GAP:   Content-Security-Policy header is absent on static resource, but Q1-Q5 are all negative with no demonstrated cross-tenant exploit chain.
  SEVEN ANSWERS:  Q1: no, does not read other user data; Q2: no, read-only GET request; Q3: no, no code execution; Q4: no, session credentials not extractable; Q5: no, no currency burned; Q6: yes, survives clean session; Q7: no, theoretical risk without impact
  CVSS:           n/a
  NEXT ACTION:    KILL from payable queue; record as defensive recommendation only.
  ```

---

### Proof 3: Link-Local Cloud Metadata Access Blocking
* **Target:** `http://169.254.169.254/latest/meta-data/`
* **Result:** **HARD STOP at Stage 0**. The Scope Guard immediately intercepts and terminates the action before any packet is transmitted.
* **Contract Output:**
  ```text
  VERDICT:        KILL
  STAGE REACHED:  0
  BLOCKING GAP:   PERMANENT_DENY_VIOLATION: Destination 169.254.169.254 is link-local cloud metadata.
  NEXT ACTION:    Hard Stop. Target blocked under Safety Gate.
  ```

---

## Live Target Testing & Proof-of-Concept

The framework includes live testing harnesses (`lab/run_flipkart_probes.py`) executed against authorized bounty targets under low-rate safe harbor conditions.

### Test Configuration:
- **Program:** Flipkart HackerOne Bug Bounty Program
- **Operator Handle:** `lakshmikanth02001`
- **Rate Limit:** 1 Request Per Second (RPS)
- **Request Budget:** Maximum 20 requests per asset
- **In-Scope Assets Tested:**
  1. `www.flipkart.com`
  2. `www.myntra.com`
  3. `api.myntra.com`
  4. `payments.myntra.com`
  5. `pay.payzippy.com`
  6. `uiscoop.payzippy.com`

### Probe Strategies Tested:
1. **SQLi Authentication Bypass Probe** — POST payload verification.
2. **BOLA/IDOR Object Enumeration Probe** — Multi-tenant object access check.
3. **Reflected Cross-Site Scripting (XSS) Fuzzing** — Parameter reflection and tag breakout.
4. **Stored XSS Feedback Probe** — Form payload injection.
5. **Open Redirect Validation** — Header reflection on `Location:` redirect paths.
6. **Cross-Origin Resource Sharing (CORS) Misconfiguration** — `Origin:` arbitrary reflection.
7. **Password-Reset Token Guessability Probe** — Token entropy analysis.
8. **Out-of-Band SSRF Probe** — Controlled callback destination testing.
9. **Path Traversal Directory Probe** — Dot-dot-slash sequence validation on static routes.

### Live Results Summary:
* Every host enforced rate-limiting, WAF filtering, or returned HTTP 404/410/503.
* In accordance with **Stage 0 of the Triage Gate**, any lead lacking a verified request/response pair demonstrating cross-user impact was marked **KILL**. Zero non-reproducible leads or spam submissions were generated.

---

## Knowledge Base & Full-Text Search

The framework embeds an ingested knowledge corpus of 15 top-tier security research repositories:
- **Methodologies:** OWASP WSTG, HackTricks, HackTricks Cloud, The Bug Hunter's Methodology (TBHM), HowToHunt, EdOverflow Bug Bounty Cheatsheet, API Security Checklist.
- **Payloads & Bypasses:** PayloadsAllTheThings, Can-I-Take-Over-XYZ (80+ cloud fingerprints).
- **Disclosed Writeups:** Awesome Bug Bounty Writeups, Bug Bounty Reference, HackerOne Disclosed Reports archive.
- **Templates:** ProjectDiscovery Nuclei community templates (9,000+ detection rules).

### Instant Search Example:
```bash
python engine/content_indexer.py --query "ssrf cloud metadata" --limit 3
```

---

## CLI Usage & Quickstart

### Prerequisites
- Python 3.10 or higher
- Git
*(No mandatory third-party pip dependencies required: the core CLI, ScopeGuard, KnowledgeEngine, ReconEngine, and TriageEvaluator run strictly on the Python Standard Library).*

### Installation
```bash
# Clone the repository
git clone https://github.com/lakshmikanth823/AI_-BUG_HUNTING-.git
cd AI_-BUG_HUNTING-
```

### Inspect Program Scope & Targets
```bash
# List top 20 paying bounty programs from corpus
python hunter.py targets --limit 20

# View program scope, rate limits, and safe-harbor terms (positional program name)
python hunter.py scope Flipkart
```

### Query Security Methodologies & Payloads
```bash
# Query 51,000+ chunks of methodologies, playbooks & writeups across 15 ingested repositories
python hunter.py search "graphql authorization bypass" --limit 3
```

### Run Lab Verification Benchmark
```bash
# Run automated verification benchmark against running lab containers
python hunter.py lab
```

### Evaluate a Candidate Finding
```bash
# Evaluate a finding against the Stage 0–5 Triage Gate with command-line flags
python hunter.py triage --url "http://127.0.0.1:3000/rest/basket/1" --status 200 --lab

# Or evaluate interactively via terminal prompts
python hunter.py triage --interactive
```

---

## Safety & Responsible Disclosure Policy

1. **Authorization is Mandatory:** This framework must only be executed against systems you own or against programs where you have explicit written authorization under a documented safe-harbor policy.
2. **Blast Radius Control:** All probes are rate-limited to ≤1 RPS by default with an automatic request budget clamp.
3. **No Malicious Exfiltration:** Data access must be minimized to the minimum proof required to confirm the vulnerability.
4. **Report, Do Not Exploit:** Findings must be submitted privately through official program disclosure channels (HackerOne, Bugcrowd, Intigriti, YesWeHack).

---

## License

This project is licensed under the [MIT License](LICENSE).
Ingested research materials and playbooks in `knowledge_base/` are subject to their respective upstream licenses (MIT, CC-BY-SA-4.0, and CC-BY-NC-SA-4.0).
