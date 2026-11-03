# Index — Security Research Link Corpus

**9,879 verified URLs** across 17 categories · 7,428 confirmed HTTP 200 · 2,451 behind anti-bot protection but valid · 9,012 security-core (the rest is adjacent OSINT/IR material).

Collected 2026-10-29 from 70+ curated sources (awesome-lists, GitHub trees, the arkadiyt bounty-program dataset, and hand-curation), de-duplicated from 22,500 raw links, and individually HTTP-validated.

## Documents

| File | What it is |
|---|---|
| `README.md` | How to install this into Antigravity and what each file is for |
| `STRATEGY.md` | Methodology, what pays, how to pick targets, the 7-phase hunt |
| `TOP_PROGRAMS.md` | Data-driven guide to real bounty programs with payouts, scope size and responsiveness |
| `BOOKS.md` | Annotated reading list and learning path |
| `LABS.md` | Three-tier home-lab build plan |

## Categories

| # | Category | Links | Full listing |
|---|---|---|---|
| 01 | **Bug Bounty Platforms & Program Directories**<br><sub>Where to find programs and check scope.</sub> | 1,041 | `by-category/01-platforms-bounty-programs.md` |
| 02 | **Enterprise / Big-Tech & Fortune-500 Program Pages**<br><sub>Direct VRP and PSIRT pages for large organisations.</sub> | 381 | `by-category/02-enterprise-programs-top500.md` |
| 03 | **Bug Bounty Writeups & Disclosed Reports**<br><sub>Learn from real, paid, disclosed reports.</sub> | 220 | `by-category/03-writeups-bug-bounty.md` |
| 04 | **Methodology, Checklists & Cheat Sheets**<br><sub>How to actually run a hunt, end to end.</sub> | 108 | `by-category/04-methodology-cheatsheets.md` |
| 05 | **Vulnerability Class Reference & Payloads**<br><sub>Per-class technique docs and payload collections.</sub> | 1,521 | `by-category/05-vuln-classes-reference.md` |
| 06 | **Recon & Asset Discovery Tools**<br><sub>Finding the attack surface.</sub> | 1,295 | `by-category/06-tools-recon.md` |
| 07 | **Exploitation, Scanning & Fuzzing Tools**<br><sub>Confirming and demonstrating impact.</sub> | 1,474 | `by-category/07-tools-exploitation.md` |
| 08 | **Vulnerable Apps & Practice Labs**<br><sub>Safe local reproduction of every class.</sub> | 116 | `by-category/08-labs-vulnerable-apps.md` |
| 09 | **CTF Platforms & Training Ranges**<br><sub>Where to build reps.</sub> | 113 | `by-category/09-ctf-platforms-labs.md` |
| 10 | **CTF Writeups & Archives**<br><sub>Worked solutions by event, year and challenge.</sub> | 717 | `by-category/10-writeups-ctf.md` |
| 11 | **Vulnerability Databases, Standards & Threat Intel**<br><sub>CVE/CWE/CVSS/EPSS/KEV, advisories, internet-wide scanning.</sub> | 106 | `by-category/11-standards-databases.md` |
| 12 | **Books, Courses & Certifications**<br><sub>The canonical reading list and training paths.</sub> | 179 | `by-category/12-books-courses.md` |
| 13 | **Mobile, API, Cloud, IoT & OT Security**<br><sub>Domain-specific testing.</sub> | 136 | `by-category/13-mobile-api-cloud-iot.md` |
| 14 | **AI / LLM & Agentic Security**<br><sub>Prompt injection, LLM red teaming, agentic tooling abuse.</sub> | 118 | `by-category/14-ai-llm-security.md` |
| 15 | **GitHub Security Repositories & Awesome Lists**<br><sub>Curated lists and repositories worth cloning.</sub> | 1,972 | `by-category/15-github-security-repos.md` |
| 16 | **Talks, Conferences, Video & Podcasts**<br><sub>DEF CON / Black Hat / Recon media and channels.</sub> | 360 | `by-category/16-youtube-media.md` |
| 17 | **Communities, Forums & Discords**<br><sub>Where researchers share and ask.</sub> | 22 | `by-category/17-communities-forums.md` |
| | **Total** | **9,879** | |

## Start here — hand-picked highest-value links

Everything else in the corpus is breadth; these are the load-bearing resources.

### Bug Bounty Platforms & Program Directories

- ~ [HackerOne - public program directory](https://hackerone.com/directory/programs)
- ✓ [Bugcrowd - bug bounty program list](https://bugcrowd.com/bug-bounty-list)
- ✓ [Immunefi - Web3/crypto bug bounties (highest payouts)](https://immunefi.com/explore)
- ✓ [Intigriti - programs](https://intigriti.com/programs)
- ✓ [YesWeHack - bug bounty programs](https://yeswehack.com/programs)
- ✓ [HackerOne Hacker101 - free course](https://hacker101.com)
- ✓ [disclose.io - safe-harbour & program standards](https://disclose.io)

### Enterprise / Big-Tech & Fortune-500 Program Pages

- ✓ [Pentester Land - list of bug bounty writeups](https://pentester.land/list-of-bug-bounty-writeups.html)
- ✓ [GitHub Enterprise SQL Injection](https://blog.orange.tw/posts/2017-01-bug-bounty-github-enterprise-sql-injection)
- ✓ [Google VRP / bughunters.google.com](https://bughunters.google.com)
- ✓ [Apple Security Bounty](https://security.apple.com/bounty)
- ✓ [Meta Bug Bounty - program overview](https://bugbounty.meta.com)
- ✓ [GitHub Security Lab](https://securitylab.github.com)
- ~ [CISA ICS-CERT advisories](https://cisa.gov/ics-advisories)
- ~ [r/bugbounty](https://reddit.com/r/bugbounty)

### Bug Bounty Writeups & Disclosed Reports

- ✓ [HackerOne disclosed reports (reddelexc index)](https://github.com/reddelexc/hackerone-reports)
- ✓ [devanshbatham/Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups)
- ~ [HackerOne - hacktivity (public disclosed reports)](https://hackerone.com/hacktivity)
- ~ [InfoSec Writeups (Medium)](https://infosecwriteups.com)
- ✓ [0xdf writes hack things](https://0xdf.gitlab.io)

### Methodology, Checklists & Cheat Sheets

- ✓ [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/stable)
- ✓ [OWASP Cheat Sheet Series (site)](https://cheatsheetseries.owasp.org)
- ✓ [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten)
- ✓ [HowToHunt - bug bounty methodology & checklists](https://github.com/KathanP19/HowToHunt)
- ✓ [OWASP ASVS - Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard)
- ✓ [OWASP API Security Project](https://owasp.org/API-Security)
- ~ [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10)

### Vulnerability Class Reference & Payloads

- ✓ [PortSwigger Web Security Academy labs](https://portswigger.net/web-security/all-labs)
- ✓ [PortSwigger Web Security Academy (free)](https://portswigger.net/web-security)
- ~ [pull_request_template](https://book.hacktricks.wiki/en/.github/pull_request_template)
- ✓ [GTFOBins (unix binary exploitation)](https://gtfobins.github.io)
- ✓ [LOLBAS (Living Off The Land Binaries and Scripts)](https://lolbas-project.github.io)
- ✓ [PortSwigger Research (exploit techniques)](https://portswigger.net/research)
- ✓ [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings)
- ✓ [Reference](http://html5sec.org)
- ✓ [XSS cheat sheet (PortSwigger)](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- ✓ [Burp Suite Certified Practitioner](https://portswigger.net/web-security/certification)
- ✓ [Burp Suite Community/Pro](https://portswigger.net/burp/communitydownload)
- ✓ [CTF Wiki (comprehensive)](https://ctf-wiki.org/en)

### Recon & Asset Discovery Tools

- ✓ [Assetnote wordlists](https://wordlists.assetnote.io)

### Exploitation, Scanning & Fuzzing Tools

- ✓ [PayloadsAllTheThings (GitHub)](https://github.com/swisskyrepo/PayloadsAllTheThings)
- ✓ [Nuclei templates (ProjectDiscovery)](https://github.com/projectdiscovery/nuclei-templates)
- ✓ [Frida](http://frida.re)
- ✓ [https://goreportcard.com/badge/github.com/gitleaks/gitleaks/v8](https://goreportcard.com/badge/github.com/gitleaks/gitleaks/v8)

### Vulnerable Apps & Practice Labs

- ✓ [OWASP MASTG - Mobile App Security Testing Guide](https://mas.owasp.org/MASTG)
- ✓ [OWASP Juice Shop (GitHub)](https://github.com/juice-shop/juice-shop)
- ✓ [crAPI - completely ridiculous API](https://github.com/OWASP/crAPI)
- ✓ [DVWA - Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- ✓ [browse the full content online](https://pwning.owasp-juice.shop)
- ✓ [OWASP WebGoat (GitHub)](https://github.com/WebGoat/WebGoat)
- ✓ [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- ✓ [IAM Vulnerable - AWS privilege escalation lab](https://github.com/BishopFox/iam-vulnerable)
- ✓ [OWASP iGoat - vulnerable iOS app](https://github.com/OWASP/iGoat-Swift)
- ✓ [Metasploitable3](https://github.com/rapid7/metasploitable3)

### CTF Platforms & Training Ranges

- ✓ [pwn.college writeups](https://pwn.college)
- ✓ [HackTheBox - machines](https://app.hackthebox.com/home)
- ✓ [TryHackMe](https://tryhackme.com)
- ✓ [CTFtime - event calendar & writeups](https://ctftime.org)
- ✓ [picoCTF](https://picoctf.org)
- ✓ [Over The Wire](http://overthewire.org/wargames)
- ✓ [CryptoHack](https://cryptohack.org)
- ✓ [ROP Emporium](https://ropemporium.com)
- ✓ [Exploit.Education](http://exploit.education)
- ✓ [VulnHub - downloadable vulnerable VMs](https://vulnhub.com)
- ✓ [Root-me.org](https://root-me.org)

### CTF Writeups & Archives

- ✓ [CloudGoat - AWS CTF by Rhino Security](https://github.com/RhinoSecurityLabs/cloudgoat)
- ✓ [Write-Ups for CTF challenges](https://ctftime.org/writeups)
- ✓ [sajjadium/ctf-writeups - massive writeup archive](https://github.com/sajjadium/ctf-writeups)
- ✓ [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- ✓ [Awesome CTF (apsdehal)](https://github.com/apsdehal/awesome-ctf)

### Vulnerability Databases, Standards & Threat Intel

- ✓ [MITRE ATT&CK - technique index](https://attack.mitre.org/techniques/enterprise)
- ✓ [Microsoft MSRC Researcher Portal](https://msrc.microsoft.com)
- ✓ [NVD - National Vulnerability Database](https://nvd.nist.gov/vuln/search)
- ✓ [CWE - Common Weakness Enumeration](https://cwe.mitre.org/data/definitions/699.html)
- ✓ [EPSS - Exploit Prediction Scoring System](https://first.org/epss)
- ~ [CISA Known Exploited Vulnerabilities Catalog](https://cisa.gov/known-exploited-vulnerabilities-catalog)
- ✓ [crt.sh - certificate transparency search](https://crt.sh)
- ✓ [OSV.dev - open source vulnerability database](https://osv.dev)
- ✓ [Zero Day Initiative](http://zerodayinitiative.com/advisories/published)
- ✓ [Exploit Database](https://exploit-db.com)
- ✓ [CVSS v4.0 calculator](https://first.org/cvss/calculator/4.0)
- ✓ [MITRE ATLAS - adversarial threat landscape for AI](https://atlas.mitre.org)

### Books, Courses & Certifications

- ✓ [Bug Bounty Bootcamp (Vickie Li) - No Starch](https://nostarch.com/bug-bounty-bootcamp)
- ✓ [Real-World Bug Hunting (Peter Yaworski) - No Starch](https://nostarch.com/bughunting)
- ✓ [Hacking APIs (Corey Ball) - No Starch](https://nostarch.com/hacking-apis)
- ✓ [Web Hacking 101](https://leanpub.com/web-hacking-101)
- ✓ [A Bug Hunter's Diary (Tobias Klein) - No Starch](https://nostarch.com/bughunter)
- ✓ [No Starch Press - security catalog](https://nostarch.com/catalog/security)
- ✓ [Black Hat GraphQL - No Starch](https://nostarch.com/black-hat-graphql)
- ✓ [Practical Binary Analysis (Dennis Andriesse) - No Starch](https://nostarch.com/binaryanalysis)
- ✓ [TCM Security PNPT](https://certifications.tcm-sec.com/pnpt)

### AI / LLM & Agentic Security

- ✓ [garak - LLM vulnerability scanner](https://github.com/NVIDIA/garak)
- ✓ [promptfoo - LLM red teaming](https://promptfoo.dev/docs/red-team)
- ✓ [Simon Willison - prompt injection series](https://simonwillison.net/tags/prompt-injection)

### GitHub Security Repositories & Awesome Lists

- ✓ [Awesome bug bounty resources by EdOverflow](https://github.com/EdOverflow/bugbounty-cheatsheet)
- ✓ [vulhub/vulhub - Dockerized CVE environments (1000+)](https://github.com/vulhub/vulhub)
- ✓ [arkadiyt/bounty-targets-data - scraped program dataset](https://github.com/arkadiyt/bounty-targets-data)
- ✓ [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei)
- ✓ [ProjectDiscovery subfinder](https://github.com/projectdiscovery/subfinder)
- ✓ [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx)
- ✓ [ProjectDiscovery katana (crawler)](https://github.com/projectdiscovery/katana)
- ✓ [ProjectDiscovery interactsh (OOB)](https://github.com/projectdiscovery/interactsh)
- ✓ [SecLists - wordlists](https://github.com/danielmiessler/SecLists)
- ✓ [gau - wayback/commoncrawl URLs](https://github.com/lc/gau)
- ✓ [ffuf - web fuzzer](https://github.com/ffuf/ffuf)
- ✓ [kiterunner (API discovery)](https://github.com/assetnote/kiterunner)
- ✓ [SQLMap Tamper Scripts](https://github.com/sqlmapproject/sqlmap)
- ✓ [ysoserial - Java deserialization](https://github.com/frohoff/ysoserial)
- ✓ [PHPGGC - PHP generic gadget chains](https://github.com/ambionics/phpggc)
- ✓ [MobSF - mobile security framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- ✓ [Semgrep](https://github.com/semgrep/semgrep)
- ✓ [trufflehog](https://github.com/trufflesecurity/trufflehog)
- ✓ [Dalfox - XSS](https://github.com/hahwul/dalfox)
- ✓ [commix - command injection](https://github.com/commixproject/commix)
- ✓ [tplmap - SSTI](https://github.com/epinna/tplmap)
- ✓ [android-security-awesome](https://github.com/ashishb/android-security-awesome)
- ✓ [awesome-mobile-security](https://github.com/vaib25vicky/awesome-mobile-security)
- ✓ [Mobile App Pentest Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
- ✓ [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
- ✓ [awesome-web-security](https://github.com/qazbnm456/awesome-web-security)
- ✓ [HackTricks (GitHub)](https://github.com/HackTricks-wiki/hacktricks)
- ✓ [Awesome Hacking](https://github.com/carpedm20/awesome-hacking)
- ✓ [awesome-security](https://github.com/sbilly/awesome-security)

### Talks, Conferences, Video & Podcasts

- ✓ [Google Project Zero blog](https://googleprojectzero.blogspot.com)
- ~ [DEF CON Media Server (free talks)](https://media.defcon.org)
- ~ [Black Hat](http://blackhat.com)
- ✓ [Recon](https://recon.cx)

### Communities, Forums & Discords

- ~ [r/netsec](https://reddit.com/r/netsec)
- ~ [Information Security Stack Exchange](https://security.stackexchange.com)

<sub>129 hand-picked links; the remaining 9,750 are in `by-category/`.</sub>


## Data files

| File | Format | Contents |
|---|---|---|
| `data/all-links.txt` | text | All 9,879 URLs, one per line |
| `data/all-links-core.txt` | text | 9,012 security-core URLs (generic OSINT noise removed) |
| `data/verified-live-only.txt` | text | 7,428 URLs that returned HTTP 200 |
| `data/links.csv` | CSV | url, title, category, relevance, verified, status, source |
| `data/links.json` | JSON | Same, nested, with counts |
| `data/programs-ranked.csv` | CSV | 948 bounty programs: payout, scope size, responsiveness |
| `data/dropped-dead-links.csv` | CSV | 804 dead links that were excluded, with reason |
| `data/dropped-unsafe-ssrf-targets.txt` | text | 33 SSRF metadata endpoints deliberately stripped |
| `data/stats.json` | JSON | Pipeline statistics |

## Antigravity package

```
antigravity/
├── AGENTS.md                    # workspace description, always active
└── .agents/rules/
    ├── 00-corpus-index.md      # always_on: category map + hard safety rules
    └── 10..26-<category>[-partN].md   # model_decision: the links themselves
```

64 rule files, every one under Antigravity's 24,000-byte per-file limit, largest 19,682 bytes. Only the index is `always_on`; categories load on demand.
