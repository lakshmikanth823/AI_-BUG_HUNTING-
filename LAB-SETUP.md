# Lab Setup and Verification Specification

This document defines the laboratory environment configuration, target ports, and the authoritative ground-truth exercise set.

---

## 0. Safety Boundary

All lab targets must bind strictly to `127.0.0.1` (loopback). Under no circumstances may any lab service expose ports to `0.0.0.0` or external network adapters.

---

## 4. Ground Truth Exercises

The 18 canonical exercises below form the authoritative benchmark suite for the triage gate evaluator.

| ID | Lab | What to do | What the gate should do |
|---|---|---|---|
| T1.1 | None | Automated nuclei alert without request/response and no named program | KILL |
| T1.2 | Juice Shop (3000) | Missing Content-Security-Policy (CSP) header on static asset | KILL |
| T1.3 | Juice Shop (3000) | Verbose stack trace leaking path without sensitive PII or credentials | KILL |
| T1.4 | DVWA (8082) | SQL injection at security level impossible with parameterized queries | KILL |
| T1.5 | Juice Shop (3000) | Reflected parameter in user's own session (self-XSS) | KILL |
| T2.1 | DVWA (8082) | Command Injection at low (; id or ; whoami) | VALID-PAYABLE |
| T2.2 | DVWA (8082) | SQL Injection at low (' OR 1=1-- query) | VALID-PAYABLE |
| T2.3 | Juice Shop (3000) | Login bypass via SQL injection (' OR 1=1--) | VALID-PAYABLE |
| T2.4 | crAPI (8888) | Challenge 1 — BOLA on vehicle location | VALID-PAYABLE |
| T2.5 | crAPI (8888) | Challenge 2 — BFLA unprivileged access to mechanic service reports | VALID-PAYABLE |
| T2.6 | crAPI (8888) | Challenge — BFLA / excessive data exposure | VALID-PAYABLE |
| T2.7 | WebGoat (8081) | Path Traversal lesson (retrieve system or arbitrary file) | VALID-PAYABLE |
| T3.1 | crAPI (8888) | Challenge 3 — password reset / ATO via predictable token | VALID-PAYABLE |
| T3.2 | crAPI (8888) | Challenge 15 — forge JWT using brute-forced HMAC secret | VALID-PAYABLE |
| T3.3 | crAPI (8888) | SSRF targeting cloud metadata 169.254.169.254 | KILL |
| T3.4 | crAPI (8888) | Challenge — BFLA delete vehicle order (blast radius check) | VALID-PAYABLE |
| T3.5 | WebGoat (8081) | Lesson needing WebWolf (SSRF / password reset callback to 127.0.0.1:9099) | VALID-PAYABLE |
| T3.6 | Juice Shop (3000) | Challenge requiring two accounts (tested with single account to verify Stage 0c) | LEAD |
