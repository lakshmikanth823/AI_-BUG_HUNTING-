# Bug Bounty & Security Research — Strategy, Methodology and Target Selection

**Companion to:** a corpus of **9,879 verified security-research URLs** (`data/`, `by-category/`, `antigravity/`)
**Generated:** 2026-10-29 · **Program data:** 946 live programs scraped from HackerOne, Bugcrowd, Intigriti and YesWeHack

---

## 0. How to read this

This document is the *reasoning layer*. The link corpus is the *reference layer*. Use them together:
every claim below about where to look, what to use, and what to read has a corresponding category
in `by-category/` that you can grep.

```
grep -ri "request smuggling" data/all-links.txt      # find prior art
grep -i  "ssrf"  by-category/05-vuln-classes-reference.md
```

---

## 1. The economics: where the money actually is

Bug bounty income is not a wage. It is a **portfolio of low-probability, high-variance bets**.
Rough it out as expected value per hour:

```
EV/hr  =  P(find something reportable) × P(it is in scope & valid & not duplicate)
         × payout(severity) ÷ hours_spent
```

Every strategy decision below is an attempt to move one of those four terms. Most beginners
optimise the wrong one — they chase `payout` and ignore `P(valid)` and `hours_spent`.

### 1.1 Published ceilings (2025–2026)

The highest published single-finding rewards in the industry:

| Program | Top award | Notes |
|---|---|---|
| **Apple Security Bounty** | **$2,000,000** | Zero-interaction network attack → kernel code execution. Doubled in Oct 2025; bonuses for Lockdown Mode bypass and beta-software findings can push a single chain past $5M in aggregate |
| **Apple — iCloud server data** | $1,000,000 | Unauthorised access to iCloud account data on Apple servers |
| **Apple — browser → kernel** | $1,000,000 | Safari navigation to kernel control |
| **Apple — wireless proximity → app processor** | $1,000,000 | Attack on Apple-designed radio components |
| **OpenSea** (Bugcrowd) | $3,000,000 | Highest published ceiling in the scraped dataset — web3 |
| **Swiss Post E-Voting** (YesWeHack) | ~$230,000 | Highest in the dataset outside web3 |
| **T-Mobile** (Bugcrowd) | $133,700 | Largest published ceiling among non-crypto telcos |
| **SpaceX / Starlink** | $100,000 | |
| **Tesla** | $100,000 | |

Source: Apple's own published reward tables [5](https://security.apple.com/bounty/categories/) and
the Oct-2025 programme overhaul [2](https://security.apple.com/blog/apple-security-bounty-evolved/)
[8](https://www.tomshardware.com/tech-industry/cyber-security/apple-doubles-security-bounty-to-usd2-million-with-bonuses-potentially-increasing-rewards-to-usd5-million);
the remainder from `data/programs-ranked.csv` (scraped live program metadata).

### 1.2 Aggregate volume — the more useful signal

Per-programme ceilings are marketing. **Aggregate spend** tells you where sustained effort pays:

- **Google** paid **$17.1M** across its VRPs in 2025, to 747 researchers — its highest ever
  [5](https://www.securityweek.com/microsoft-bug-bounty-program-20-million-paid-to-500-researchers/)
- **Microsoft** paid **$20M** to ~500 researchers in the same period
  [5](https://www.securityweek.com/microsoft-bug-bounty-program-20-million-paid-to-500-researchers/)
- **Apple** has paid **$35M cumulative**, with the top award now $2M
  [5](https://www.securityweek.com/microsoft-bug-bounty-program-20-million-paid-to-500-researchers/)
- **HackerOne's 10th Security Research Report (2026)** is built on **92,194 valid reports** and
  **$89.1M in payouts**, plus surveys of 111 security leaders and 408 active researchers
  [1](https://www.hackerone.com/report/hacker-powered-security)

**Implication:** well over $130M/yr flows through just four vendors — Meta alone publishes reward tiers up to **$300K** for impactful findings [3](https://bugbounty.meta.com/scope/). The bottleneck is not money —
it is the number of researchers who can reliably produce *valid, novel, well-scoped* reports.
That is a skill problem, and skill problems are solvable with labs and reps (see §6).

### 1.3 Apple's services reward table is the best public proxy for "what big tech pays for"

Apple publishes an explicit price list for server-side findings. Treat it as a **severity → payout
map that generalises** across large enterprises (numbers are maxima, not typicals):

| Finding | Max reward |
|---|---|
| Unauthorised access to iCloud account data on Apple servers | $1,000,000 |
| **RCE** — command injection, deserialization, XXE leading to RCE | $100,000 |
| **Unrestricted filesystem / DB access** — unsandboxed XXE, SQL injection | $50,000 |
| **Logic flaws bypassing significant security controls** — IDOR, remote user impersonation, account takeover, privilege escalation, SSRF, directory traversal, HTTP request smuggling, proxy misconfiguration | $50,000 |
| **Client/server code execution** — XSS, CSRF, HTML injection, prohibited write-access | $40,000 |
| **Confidential / sensitive data** — access-control issues exposing PII | $30,000 |
| **Domain & subdomain takeover** | $5,000 |

Source: [5](https://security.apple.com/bounty/categories/)

Read the ordering carefully — it is the single most useful table in this document.

---

## 2. Top-priority bug classes at large enterprises

Ranked by **(payout ceiling × likelihood a Fortune-500 actually has it × how rarely it is fully
automated away)**. This is the priority order to hunt in.

### Tier S — chase these

| Class | Why it wins at scale | Where to study |
|---|---|---|
| **Broken access control / IDOR** | Enterprise SSO, multi-tenant SaaS, partner portals, admin consoles. Scanners cannot find it; it is pure logic. Highest yield per hour for a skilled hunter. | `by-category/05-vuln-classes-reference.md` → access control; PortSwigger Academy labs |
| **Authentication & session flaws → ATO** | Every MNC has legacy auth, SSO federation (SAML/OIDC), password reset, MFA bypass, session fixation. Chains into Tier-S payouts. | `05-vuln-classes-reference`, `04-methodology-cheatsheets` |
| **SSRF → cloud metadata / internal services** | The classic enterprise killer. Cloud-first infra means SSRF frequently becomes credential theft. Highest *escalation* potential of any web bug. | `05-vuln-classes-reference` → SSRF; **see §9 safety note** |
| **RCE (deserialization, template injection, file upload, command injection)** | Ceiling-payout class. In large estates it hides in internal tooling, legacy JSP/.NET/PHP, CI runners, and integration middleware. | `07-tools-exploitation` (ysoserial, PHPGGC, tplmap), `05-vuln-classes-reference` |
| **Privilege escalation (vertical, tenant→tenant, user→admin)** | Multi-tenant SaaS: one tenant reading another's data is a critical, not a medium. | `05-vuln-classes-reference` |
| **Request smuggling / cache poisoning / cache deception** | Enterprises sit behind CDNs, WAFs, and layered proxies — exactly the topology where desync bugs live. Under-hunted, high payout. | `05-vuln-classes-reference`, PortSwigger research |

### Tier A — reliable income

| Class | Notes |
|---|---|
| **SQL injection** | Still $50k ceiling at Apple. Rare on the main site, common in forgotten sub-apps, reporting endpoints, legacy SOAP/REST, mobile backends. |
| **XSS (stored, DOM, mXSS)** | Lower ceiling ($40k at Apple) but by far the highest *hit rate*. Self-XSS is usually out of scope — know the difference. |
| **XXE** | Unsandboxed XXE = $50k at Apple. Hunt file parsers: DOCX/XLSX/PPTX/SVG/PDF upload, SAML assertions, XML APIs. |
| **Business-logic abuse** | Coupon/refund/withdrawal races, negative quantities, state-machine skipping, IDOR in workflows. Zero scanner coverage, high payout, requires understanding the product. |
| **Race conditions** | Single-packet attack made these reliable. Payouts are high because they are under-hunted. |
| **Subdomain / dangling-resource takeover** | Low ceiling ($5k at Apple) but near-zero effort and very high success rate on large estates. Good for building reputation and stats early. |

### Tier B — situational

Information disclosure (`.git`, `.env`, source maps, verbose errors, Swagger/OpenAPI exposure),
CORS misconfiguration, open redirect chained into OAuth token theft, CSRF on state-changing
endpoints, exposed internal services (Jenkins, Elasticsearch, Kibana, Grafana, phpMyAdmin),
insecure deserialization in non-Java stacks, JWT algorithm confusion / `none` / key leakage.

### Tier C — usually out of scope or unpaid at large enterprises

Missing security headers in isolation, SSL/TLS configuration nits, clickjacking on
non-sensitive pages, self-XSS, CSRF on logout, banner grabbing, rate-limiting absence without
a demonstrated abuse, "user enumeration" without impact, speculative CVSS inflation.

**The trap:** beginners farm Tier C on VDPs, accumulate reports, earn nothing, and never build
the Tier S skills. If your goal is income, spend 70% of your time in Tiers S/A.

### 2.1 The 2026 addition: AI / LLM attack surface

HackerOne's 2026 report leads with the observation that **AI expanded the attack surface faster
than most organisations could secure it** [8](https://www.linkedin.com/posts/philvenables_hacker-powered-security-report-9th-edition-activity-7379162818119630848-zjfV)
[1](https://www.hackerone.com/report/hacker-powered-security). Concretely, at large enterprises
the highest-value AI findings right now are:

1. **Prompt injection → data exfiltration** (indirect, via documents/web pages the model reads)
2. **Prompt injection → tool/function abuse** — the model is made to call an internal API with
   attacker-chosen parameters. This is the Tier-S equivalent: it becomes RCE or IDOR.
3. **RAG poisoning / knowledge-base injection**
4. **Model or system-prompt leakage** revealing internal logic, keys, or vendor config
5. **Insecure plugin / MCP-server implementations** — SSRF and path traversal through agent tooling
6. **Training-data / PII leakage** through model outputs

See `by-category/14-ai-llm-security.md` (118 links): OWASP LLM Top 10, MITRE ATLAS, garak,
promptfoo, NeMo Guardrails, Lakera Gandalf, and Simon Willison's prompt-injection series.

---

## 3. Target selection: three data-driven archetypes

From the 946 programs in `data/programs-ranked.csv`, three archetypes dominate. **Pick one and
specialise** — the switching cost between them is high.

### Archetype 1 — Enormous surface, disclosure-only (VDP)

The largest in-scope asset counts in the entire dataset:

| Program | In-scope assets | Paid |
|---|---|---|
| Fiserv | **10,923** | no |
| CBRE | **8,691** | no |
| Clarivate | **5,026** | no |
| John Deere | **2,050** | no |
| ION Group | **1,444** | no |
| DIB-VDP | 1,094 | no |
| ABB Information Systems | 1,063 | no |
| AWS VDP | 554 | no |
| MTN Group | 495 | no |
| Essity | 480 | no |
| Estée Lauder | 471 | no |
| Ferrero | 416 | no |
| Mondelēz International | 372 | no |
| PepsiCo VDP | 227 | no |
| HPE VDP | 207 | no |

**Play:** thousands of forgotten subdomains, acquisitions never integrated, staging hosts,
partner portals. Excellent for *learning* and for building a reputation, terrible for income.
Use these for your first 50 reports, then leave.

### Archetype 2 — High ceiling, narrow scope, managed/invitational

OpenSea ($3M), Fireblocks ($150k), T-Mobile ($133.7k), SpaceX/Starlink ($100k), Tesla ($100k),
Sophos ($80k), Okta ($75k), Auth0 ($50k), Zendesk ($50k), Doctolib ($50k), Kiteworks ($50k),
AXIS OS ($40k), Pinterest ($25k), SAP Invitational ($20k), Arm ($20k), Cash App ($18k),
Square ($18k), Canva ($15k), BMW Group Automotive (€15k).

**Play:** these are *hard*. Narrow scope + mature internal teams + heavy prior hunting. Requires
Tier-S skill (logic bugs, race conditions, novel chains). Do not start here.

### Archetype 3 — Mid-size, paid, and **responsive** ← the sweet spot

The dataset includes HackerOne's `response_efficiency_percentage` — a direct measure of how
reliably a program triages and pays. The top paid programs by responsiveness with meaningful
bounty-eligible asset counts:

| Program | Response efficiency | Bounty-eligible assets |
|---|---|---|
| inDrive | 100% | 174 |
| Airbnb | 100% | 27 |
| HackerOne (dogfooding) | 100% | 25 |
| Crypto.com | 100% | 24 |
| CrowdStrike | 100% | 20 |
| 8x8 | 100% | 20 |
| Krisp | 100% | 12 |
| Hostinger | 100% | 12 |
| Trendyol | 100% | 11 |
| Semrush | 100% | 10 |
| Brave Software | 100% | 5 |
| **Remitly** | 99% | **72** |
| **Goldman Sachs** | 99% | **38** |
| MoonPay | 99% | 21 |

**Play:** this is where sustained income lives. Good triage means fewer N/A'd reports, faster
bounty awards, and a program that *keeps* your duplicates down because the scope is fresh.
Sort `data/programs-ranked.csv` by `resp_eff` descending with `offers=True` to regenerate this
list — it changes monthly.

### 3.1 The targeting heuristics that actually matter

1. **Freshness beats size.** A program that launched last month has 10× the findable bugs of one
   that has been public for five years. Watch platform "new programs" feeds daily.
2. **M&A creates orphaned assets.** Every acquisition leaves a domain, an SSO integration, and a
   staging environment nobody owns. Check the target's press releases for acquisitions, then
   enumerate *their* domains, not just the parent's.
3. **Mobile and API backends are under-hunted.** The marketing site has been scanned to death;
   the app's GraphQL endpoint has not. Extract APIs from the mobile binary (jadx, MobSF).
4. **Internal/admin surfaces leak outward.** Jenkins, Grafana, Kibana, Swagger UI, Actuator
   endpoints, `staging.`, `dev.`, `internal.`, `admin.`, `test.` — `nuclei` templates cover most.
5. **Second-order scope.** Third-party SaaS the target uses (SSO providers, support widgets,
   chat, analytics, feature-flag systems) is often in scope and rarely hunted.
6. **Avoid the top 1% of programs** until you have Tier-S skills. Everyone hunts Google, Meta,
   Shopify, Uber. Duplicate rates there are brutal.

---

## 4. The seven-phase methodology

### Phase 0 — Authorization (non-negotiable)

Before touching a target:
- Read the program's **scope, out-of-scope list, and safe-harbor terms** in full.
- Confirm **rate limits** and whether automated scanning is permitted (many programs forbid it).
- Note the **disclosure policy** — most forbid public writeups without written approval.
- Record the date and program version. Scope changes; a legal find yesterday can be illegal today.
- Use a **dedicated account and IP** so you are attributable and your activity is distinguishable.

### Phase 1 — Passive recon (no packets to the target)

Certificate transparency (`crt.sh`), search engines (Shodan, Censys, FOFA, ZoomEye), historical
URLs (`gau`, `waybackurls`, Common Crawl), DNS permutation (`dnsgen`, `altdns`, `puredns`),
GitHub/GitLab secret and code search (`gitleaks`, `trufflehog`, `noseyparker`, GitHub code
search for the target's domains), employee and tech-stack OSINT, favicon hashing (`fav-up`),
and acquisition research.

→ `by-category/06-tools-recon.md` (1,295 links)

### Phase 2 — Active mapping

Subdomain resolution (`httpx`), port scan within permitted limits (`naabu`, `nmap`), technology
fingerprinting (`whatweb`, `webanalyze`, `retire.js`), crawling (`katana`, `hakrawler`,
Burp Spider), **parameter discovery** (`Arjun`, Param Miner), API surface enumeration
(`kiterunner`, extracted OpenAPI/Swagger specs), JS analysis (`LinkFinder`, `JSFinder`,
SecretFinder), and content discovery with the right wordlist (`ffuf`/`feroxbuster` +
SecLists / Assetnote wordlists).

Build a **content inventory**: every endpoint, every parameter, every response-code pattern.
Most hunters stop at subdomains; the money is in the endpoint × parameter matrix.

### Phase 3 — Class-directed hunting

Do not "look for bugs". Work a **queue by vulnerability class**, in the Tier S → A order from §2.
For each class, run the full PortSwigger/HackTricks technique list against the inventory from
Phase 2. This is what `by-category/05-vuln-classes-reference.md` (1,521 links) and
`by-category/04-methodology-cheatsheets.md` are for.

Automate breadth (`nuclei` with tuned templates), then spend your attention on **depth**:
authentication flows, authorisation boundaries, multi-tenant object references, state machines,
file parsing, and every place user input crosses a trust boundary.

### Phase 4 — Impact escalation (the highest-leverage phase)

A medium finding escalated to critical is worth 10–50× more than a second medium finding.
Escalation patterns:

- **SSRF** → internal service → cloud metadata → credentials → account takeover of infrastructure
- **XSS** → session/token theft → **account takeover** → admin account → full compromise
- **IDOR** on a low-value object → IDOR on **PII at scale** or **cross-tenant** data
- **Subdomain takeover** → host on a trusted domain → **cookie tossing / OAuth redirect** → ATO
- **Open redirect** → OAuth `redirect_uri` manipulation → **token theft**
- **Race condition** → withdraw/transfer duplication → **direct financial loss**
- **Information disclosure** (`.git`, source map) → recovered secrets → **RCE or DB access**
- **Low-privilege write** → stored payload executed in an **admin's** context → privilege escalation

Write the chain before you write the report. Triagers pay for demonstrated impact, not for a
vulnerability class name.

### Phase 5 — Validation and PoC

- Reproduce **deterministically**. If you cannot reproduce it three times, you do not have a bug.
- **Minimise harm**: stop at proof, never exfiltrate more data than needed, never modify or
  destroy data, never pivot into other users' records beyond a single demonstration.
- Build a **clean, minimal PoC**: exact HTTP requests, an unambiguous screenshot or video, and a
  reproduction script. Assume the triager has five minutes.
- Test in a **local lab first** whenever possible (see §6) — it is faster, safer, and it teaches
  you the underlying mechanism.

### Phase 6 — Reporting

Structure: **Title** (class + component + impact) → **Summary** (3 sentences) → **Severity**
(CVSS 4.0 vector shown, justified) → **Steps to reproduce** (numbered, copy-pasteable) →
**Impact** (what a real attacker achieves, in business terms) → **Remediation** (specific, not
"validate input").

The single biggest cause of downgrades is a vague impact statement. The single biggest cause of
N/A is a duplicate. Search public reports first — `by-category/03-writeups-bug-bounty.md`
(220 links) and HackerOne hacktivity.

### Phase 7 — After the report

Track triage timelines (`average_time_to_report_resolved` and `average_time_to_bounty_awarded`
are both in `data/programs-ranked.csv` — use them to choose programs). Escalate politely and on
the documented timeline. Never disclose without written approval.

---

## 5. Toolchain

### Minimum viable (day one)

Burp Suite Community · `ffuf` · `nmap` · `subfinder` + `httpx` · `gau` · `nuclei` ·
SecLists · `gitleaks` · a browser with a JS-aware devtools workflow

### Full pipeline

**Recon:** `amass`, `subfinder`, `puredns`, `massdns`, `dnsx`, `naabu`, `httpx`, `katana`,
`gau`, `waybackurls`, `hakrawler`, `Arjun`, `kiterunner`, `LinkFinder`, `JSFinder`,
`SecretFinder`, `trufflehog`, `noseyparker`, `fav-up`, `cariddi`, `csprecon`, `reconftw`, `osmedeus`

**Exploitation:** Burp Pro + Autorize + Turbo Intruder + Hackvertor + Param Miner · Caido · ZAP ·
`sqlmap` · `commix` · `dalfox` · `XSStrike` · `tplmap` · `NoSQLMap` · `dotdotpwn` · `SSRFmap` ·
`Gopherus` · `ysoserial` · `PHPGGC` · `marshalsec` · `interactsh`

**Code / SAST:** `semgrep` + rules · CodeQL · Joern · `bandit` · `brakeman` · `gosec` · Trivy

**Mobile:** MobSF · Frida · objection · jadx · apktool

**Binary / fuzzing:** Ghidra · radare2/Cutter · pwndbg · GEF · AFL++ · libFuzzer · honggfuzz ·
syzkaller · OSS-Fuzz

**Wordlists / payloads:** SecLists · Assetnote wordlists · fuzzdb · PayloadsAllTheThings ·
fuzz.txt · payloadbox collections · OneListForAll

→ `by-category/06-tools-recon.md` (1,295) and `07-tools-exploitation.md` (1,474)

---

## 6. Labs — how to actually build the skill

See `LABS.md` for the full three-tier build plan. Summary:

**Tier 1 — Guided (weeks 1–8).** PortSwigger Web Security Academy (free, ~150 labs, the single
best resource in existence for web security) → TryHackMe → HackTheBox Academy → Hacker101 →
picoCTF. Do *every* PortSwigger lab; do not skip to the ones you think you know.

**Tier 2 — Local vulnerable apps (weeks 4–20, in parallel).** OWASP Juice Shop · DVWA · WebGoat ·
**vulhub** (Docker-compose environments for real CVEs — the highest-value item in the corpus) ·
crAPI (API security) · VAmPI · Metasploitable3 · CloudGoat + IAM Vulnerable + Kubernetes Goat +
Terragoat (cloud) · DIVA + AndroGoat + InsecureShop (Android) · iGoat + DVIA-v2 (iOS).
Goal: reproduce every Tier-S class *locally* until you can explain the mechanism from memory.

**Tier 3 — Unguided (week 12+).** HackTheBox machines without walkthroughs · Root-Me ·
OverTheWire (Natas, Behinder) · pwn.college · CryptoHack · ROP Emporium · live CTFs via CTFtime.
Then read writeups only *after* you have tried.

→ `by-category/08-labs-vulnerable-apps.md` (116) · `09-ctf-platforms-labs.md` (113) ·
`10-writeups-ctf.md` (717)

---

## 7. Reading list (ordered)

Full annotated list in `BOOKS.md` (179 links in `by-category/12-books-courses.md`).

1. **The Web Application Hacker's Handbook, 2e** — Stuttard & Pinto. Still the foundation;
   superseded in tooling by PortSwigger Academy, not in thinking.
2. **Bug Bounty Bootcamp** — Vickie Li. Best structured beginner-to-first-payout path.
3. **Real-World Bug Hunting** — Peter Yaworski. Teaches you to read other people's reports.
4. **Web Hacking 101** — Peter Yaworski. Free, case-study driven.
5. **Hacking APIs** — Corey Ball. The most under-read high-value book; enterprise attack surface
   is overwhelmingly API.
6. **The Bug Hunter's Diary** — Tobias Klein. Deep, low-level, changes how you read software.
7. **The Hacker Playbook 3** — Peter Kim. Practical campaign methodology.
8. **Black Hat Python 2e** / **Black Hat Go** — automation, which is how you scale.
9. **Practical Binary Analysis** / **Practical Reverse Engineering** — for Tier-S binary work.
10. **Threat Modeling: Designing for Security** — Shostack. Makes you better at *finding* logic bugs.

Consensus picks across independent 2026 reading lists
[5](https://www.cybershelf.org/en/guides/best-books-for-bug-bounty-hunters-2026)
[1](https://danaepp.com/5-books-every-api-hacker-should-read)
[4](https://infosecwriteups.com/bugbounty-mastering-the-basics-along-with-resources-part-4-f424a26c6ef6).

---

## 8. Feeding this corpus into Antigravity

Antigravity discovers rules from the filesystem and injects them into agent context. Two
mechanisms matter here (both documented at [3](https://antigravity.google/docs/rules/)):

- **`AGENTS.md`** — no frontmatter, always active for its scope.
- **`.agents/rules/*.md`** — require YAML frontmatter with a `trigger`:
  `always_on` | `model_decision` | `glob` | `manual`.
- **Hard limits:** **24,000 bytes per file**, and a **20,000-token aggregate budget** shared by
  all active `always_on` rules. `model_decision` rules only inject their *path and description*
  upfront; the agent reads the body on demand (progressive disclosure).

That is exactly why this corpus is packaged as it is:

```
antigravity/
├── AGENTS.md                      # small, describes the workspace
└── .agents/
    └── rules/
        ├── 00-corpus-index.md     # always_on  — category map + safety rules (small)
        ├── 10-platforms-bounty-programs-part1..5.md   # model_decision
        ├── 11-enterprise-programs-top500-part1..2.md
        ├── ...                    # 64 files total, 9,879 links, max 19.7 KB each
        └── 26-communities-forums.md
```

**Install:** copy `antigravity/AGENTS.md` to your project root (or `~/.gemini/AGENTS.md` for
global scope) and copy `antigravity/.agents/` into your project. Every rule file is under the
24 KB limit and only `00-corpus-index.md` is `always_on`, so you consume a few hundred tokens
permanently and pull in full categories only when a task matches.

The flat machine-readable corpus (`data/all-links.txt`, `links.csv`, `links.json`) sits outside
the rules budget entirely — the agent greps it instead of loading it.

---

## 9. Safety note — why some URLs were deliberately removed

The corpus was harvested partly from HackTricks, which documents SSRF against cloud metadata
services. **33 URLs pointing at link-local and internal metadata endpoints were stripped** and
are listed in `data/dropped-unsafe-ssrf-targets.txt` for transparency:

`169.254.169.254` · `metadata.google.internal` · `100.100.100.200` · `fd00:ec2::254` ·
`*.internal` · `localhost` · RFC-1918 ranges

If an agent auto-fetches every URL in a corpus, these would hit **its own** cloud metadata
service and could return live credentials. They are attack *targets*, not resources, and have no
place in a reading corpus. The `00-corpus-index.md` rule also encodes a standing prohibition on
re-adding or fetching them.

The same rule file encodes the general guardrail: **authorization is a precondition** for any
offensive work, scope and safe-harbor terms must be respected, and impact is demonstrated in a
local lab — never against a third party.

---

## 10. What the corpus contains

| Category | Links | File |
|---|---|---|
| Bug bounty platforms & program directories | 1,041 | `by-category/01-*` |
| Enterprise / Fortune-500 program pages | 381 | `by-category/02-*` |
| Bug bounty writeups & disclosed reports | 220 | `by-category/03-*` |
| Methodology, checklists & cheat sheets | 108 | `by-category/04-*` |
| Vulnerability class reference & payloads | 1,521 | `by-category/05-*` |
| Recon & asset discovery tools | 1,295 | `by-category/06-*` |
| Exploitation, scanning & fuzzing tools | 1,474 | `by-category/07-*` |
| Vulnerable apps & practice labs | 116 | `by-category/08-*` |
| CTF platforms & training ranges | 113 | `by-category/09-*` |
| CTF writeups & archives | 717 | `by-category/10-*` |
| Vulnerability databases, standards & threat intel | 106 | `by-category/11-*` |
| Books, courses & certifications | 179 | `by-category/12-*` |
| Mobile, API, cloud, IoT & OT security | 136 | `by-category/13-*` |
| AI / LLM & agentic security | 118 | `by-category/14-*` |
| GitHub security repos & awesome lists | 1,972 | `by-category/15-*` |
| Talks, conferences, video & podcasts | 360 | `by-category/16-*` |
| Communities, forums & Discords | 22 | `by-category/17-*` |
| **Total** | **9,879** | |

**Verification:** every URL was checked live. 7,428 returned HTTP 200. 2,451 returned an
anti-bot 403/429 or a 5xx — these are overwhelmingly Cloudflare-protected sites
(`book.hacktricks.wiki` 1,159, `hackerone.com` 566, `dl.acm.org` 47, `usenix.org` 26) and are
retained but flagged `~`. 804 confirmed-dead links were dropped and are listed in
`data/dropped-dead-links.csv` so you can see exactly what was excluded and why.

**Pipeline:** 22,500 raw links harvested → 11,094 unique after normalisation and de-duplication →
9,879 after live validation and safety filtering. Fully reproducible from `work/`.
