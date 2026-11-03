---
trigger: always_on
---

# Security Research Link Corpus (index)

This workspace ships a curated corpus of **9,879 security-research URLs** covering bug bounty hunting, CTFs, offensive tooling, vulnerable labs, standards databases and the canonical reading list. It exists so the agent can cite real, current sources instead of inventing URLs.

## How to use it

1. Each category below is a separate `model_decision` rule under `.agents/rules/`. The agent loads only the category that matches the current task — do not read them all.
2. For bulk or programmatic use, the same corpus is in machine-readable form:
   - `data/all-links.txt` — every URL, one per line
   - `data/all-links-core.txt` — security-relevant subset (drops generic OSINT noise)
   - `data/verified-live-only.txt` — only URLs that returned HTTP 200
   - `data/links.csv` / `data/links.json` — with title, category, verification status, source
   - `data/programs-ranked.csv` — real bounty programs with payouts, scope size and responsiveness
3. Grep before you guess: `grep -i ssrf data/all-links.txt` beats recalling a URL from memory.

## Category map

| Rule file | Category | Links |
|---|---|---|
| `10-platforms-bounty-programs*.md` | HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi program URLs and directories. Use when the task is finding or triaging a bug bounty program, checking scope, or picking a target. | 1,041 |
| `11-enterprise-programs-top500*.md` | Direct vulnerability reward / PSIRT / responsible-disclosure pages for big-tech, finance, healthcare, automotive and ICS vendors. Use when researching a specific large company's program or security posture. | 381 |
| `12-writeups-bug-bounty*.md` | Disclosed bug bounty reports, hacktivity archives, researcher blogs and writeup collections. Use when looking for prior art on a vulnerability class or learning report quality. | 220 |
| `13-methodology-cheatsheets*.md` | OWASP WSTG/ASVS/Top-10/CheatSheetSeries, PortSwigger Academy, HackTricks, GTFOBins, LOLBAS and hunting methodologies. Use when planning a test, building a checklist, or verifying coverage. | 108 |
| `14-vuln-classes-reference*.md` | Per-vulnerability technique docs and payload collections: SQLi, XSS, SSRF, IDOR, SSTI, deserialization, request smuggling, race conditions, auth bypass. Use when constructing or explaining a specific vulnerability class. | 1,521 |
| `15-tools-recon*.md` | Subdomain enumeration, crawling, parameter mining, secret scanning, wordlists, OSINT and internet-wide search engines. Use when building a recon pipeline or discovering attack surface. | 1,295 |
| `16-tools-exploitation*.md` | Proxies, scanners, fuzzers, deserialization gadget generators, SAST/code analysis, mobile and binary tooling. Use when selecting a tool to confirm or exploit a finding. | 1,474 |
| `17-labs-vulnerable-apps*.md` | Juice Shop, DVWA, WebGoat, vulhub, crAPI, CloudGoat, Kubernetes Goat, mobile vulnerable apps. Use when setting up a safe local lab to reproduce a vulnerability class. | 116 |
| `18-ctf-platforms-labs*.md` | HackTheBox, TryHackMe, PortSwigger Labs, picoCTF, pwn.college, Root-Me, OverTheWire and similar. Use when recommending practice environments or skills drills. | 113 |
| `19-writeups-ctf*.md` | CTF writeup archives by event/year/challenge plus CTFtime. Use when looking for worked solutions to pwn/web/crypto/rev challenges. | 717 |
| `20-standards-databases*.md` | NVD, CVE, CWE, CVSS, EPSS, CISA KEV, Exploit-DB, OSV, vendor advisory feeds, Shodan/Censys/crt.sh. Use when looking up CVE data, severity scoring, exploitability or certificate transparency. | 106 |
| `21-books-courses*.md` | Canonical reading list and training: No Starch, Wiley, Packt, O'Reilly, OSCP/PNPT/BSCP and free academies. Use when recommending learning material. | 179 |
| `22-mobile-api-cloud-iot*.md` | Android/iOS, REST/GraphQL API, AWS/Azure/GCP/Kubernetes, IoT firmware and ICS/OT specific resources. Use for domain-specific testing guidance. | 136 |
| `23-ai-llm-security*.md` | Prompt injection, jailbreaks, LLM red teaming, OWASP LLM/GenAI Top 10, MITRE ATLAS, AI bug bounties. Use when testing or reasoning about AI-enabled systems. | 118 |
| `24-github-security-repos*.md` | GitHub security orgs, awesome-lists and repositories worth cloning. Use when sourcing or recommending a codebase. | 1,972 |
| `25-youtube-media*.md` | DEF CON, Black Hat, Recon and other conference media, YouTube channels, podcasts, newsletters. Use when recommending a talk or written deep-dive. | 360 |
| `26-communities-forums*.md` | Subreddits, Discords, Stack Exchange sites and forums where researchers share findings. Use when recommending where to ask or share. | 22 |

## Hard safety rules (always apply)

- **Authorization is a precondition.** Never generate, execute, or help refine an attack against a host, application, or account the user does not own or is not explicitly authorized to test. Ask for the scope document, program URL, or written permission first.
- **Stay in scope.** Respect each program's out-of-scope list, rate limits, and safe-harbor terms.
- **No SSRF against cloud metadata.** Endpoints such as `169.254.169.254`, `metadata.google.internal`, `100.100.100.200` and `fd00:ec2::254` were deliberately removed from this corpus. Do not re-add or fetch them — they can expose cloud credentials.
- **No live exploitation of third parties.** Demonstrate impact in a local lab (`by-category/08-labs-vulnerable-apps.md`) or against your own infrastructure.
- **Report, don't leak.** Do not help publish unreported vulnerabilities, PII, or customer data.
- **Verify before citing.** Links marked `~` returned an anti-bot response; confirm they resolve before quoting them as fact.
