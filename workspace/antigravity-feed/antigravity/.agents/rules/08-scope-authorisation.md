---
trigger: always_on
description: Target Provenance, Permanent Deny List, Lab-First and Request Budget Guardrails.
---

# Scope & Authorisation Gate

This rule governs all testing activities. It enforces strict target provenance, permanent destination bans, safe lab isolation, and blast-radius constraints.

---

## 1. TARGET PROVENANCE

Before ANY active testing or probing step is proposed or executed:
- The target host MUST be verified as an explicitly listed, in-scope asset within `data/programs-ranked.csv` for a program the user has explicitly named.
- If the host is not in scope, or if the user has not explicitly named an authorized bug bounty program or provided written scope documentation, the agent MUST refuse to generate requests and ask for scope clarification.
- **NEVER** infer authorization from assumptions like "it is a subdomain of a well-known company" or "it runs on public infrastructure".

---

## 2. PERMANENT DENY LIST & LAB CARVE-OUT

Under no circumstances may the agent emit, suggest, encode, or obfuscate requests targeting reserved, private, internal, or link-local endpoints:
- `169.254.169.254` (AWS/GCP/Azure link-local metadata)
- `metadata.google.internal` (Google Cloud internal metadata)
- `100.100.100.200` (Alibaba Cloud metadata)
- `fd00:ec2::254` (IPv6 cloud metadata)
- `169.254.0.0/16` (Link-local network range)
- `127.0.0.0/8` (Loopback range — subject to strict lab carve-out below)
- `10.0.0.0/8` (RFC 1918 Private Class A)
- `172.16.0.0/12` (RFC 1918 Private Class B)
- `192.168.0.0/16` (RFC 1918 Private Class C)
- `*.internal` (Internal DNS zones)
- `*.local` (Local mDNS zones)
- `0.0.0.0` (Unspecified broadcast address)

> **SSRF Rule**: Any SSRF demonstration MUST point to a non-reserved external destination under researcher control (e.g. an out-of-band collaborator or `interactsh` host), **NEVER** against cloud metadata or internal private infrastructure.

### Authorized Lab Carve-Out
As an explicit, bounded exception to the `127.0.0.0/8` ban, active local testing is permitted strictly on loopback (`127.0.0.1` / `localhost`) and ONLY against these verified local lab ports:
- `3000` (OWASP Juice Shop)
- `8081` (OWASP WebGoat)
- `8082` (DVWA)
- `9099` (OWASP WebWolf)
- `8888` (OWASP crAPI)

Any request to any other port on loopback or private networks remains strictly blocked.

---

## 3. LAB FIRST FOR HIGH-RISK TECHNIQUES

For any potentially destructive technique, resource exhaustion, authentication bypass at scale, mass fuzzing, or multi-user account takeover:
- First provide the reproduction command for the equivalent local vulnerable application listed in `LABS.md`.
- Explicitly output: *"Confirm behavior in a local lab before touching a live program."*
- Because Docker and local containers do not execute directly inside the agent sandbox, emit the `docker-compose` command for the user to run on their host machine.

---

## 4. RATE LIMIT & BLAST RADIUS

Every proposed active probe must specify a strict request budget and clear termination conditions:
- **Default Budget**: Maximum of 10 requests for a minimal proof-of-concept.
- **Account Isolation**: Test with a single authorized account first; do not touch secondary account data without explicit operator confirmation.
- **Data Minimization**: Never exfiltrate data beyond what is strictly necessary to demonstrate access.
- **No Persistence / Mutation**: No persistent backdoors, no lateral movement, no modifying or deleting other users' production data.
- **Pause Gate**: If proving impact requires altering a second user's state, pause immediately and require explicit operator confirmation before proceeding.

---

## 5. NO UNSANCTIONED MASS SCANNING

Refuse to generate commands whose objective is unconstrained scanning, indiscriminate brute-forcing, or spray-and-pray fuzzing across wildcards not explicitly listed in program scope.

---

## 6. ESCALATION PHRASE

When any target fails provenance or scope verification, the agent MUST emit this exact phrase and stop immediately:

```text
OUT OF SCOPE — <host> is not a listed in-scope asset for <program>. Confirm authorisation or pick a target from data/programs-ranked.csv.
```

Do not offer workarounds or alternative exploitation paths for unverified targets.
