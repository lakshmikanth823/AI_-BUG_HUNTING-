# Lab Setup — Three Tiers

Building a lab is the single highest-ROI action available to you. It converts "I read about SSRF"
into "I can explain why this SSRF became RCE", and it is the only safe place to practise the
impact-escalation chains described in `STRATEGY.md` §4.

**116 vulnerable-app links** live in `by-category/08-labs-vulnerable-apps.md`, and **113 platform
links** in `by-category/09-ctf-platforms-labs.md`.

---

## Tier 0 — Hardware and hypervisor

### Minimum viable (free, laptop-only)

- **16 GB RAM** — runs Kali + one target VM comfortably
- **VirtualBox** (free) or **VMware Workstation Player** (free for personal use)
- **Kali Linux** VM: 4 vCPU, 8 GB RAM, 80 GB disk
- 250 GB free disk

This is enough for every Tier-1 and Tier-2 app below. Most published guides stop here, and most
people only need this
[2](https://www.cybrary.it/blog/building-cybersecurity-lab-environment-home)
[1](https://unihackers.com/blog/cybersecurity-home-lab-setup).

### Recommended (serious work)

- **32–64 GB RAM**, 8+ cores, **1–2 TB NVMe**
- **Proxmox VE** (free, hypervisor-grade) instead of VirtualBox — snapshots, cloning, and many
  simultaneous VMs matter more than any single tool choice
- A **dedicated VLAN / isolated virtual network** for targets. Never bridge vulnerable machines
  onto your LAN. This is not optional: DVWA-class apps are trivially exploitable and Metasploitable
  is designed to be compromised.
- Optional: a small cloud account (spot instances) for testing cloud-specific classes — CloudGoat,
  IAM Vulnerable, Kubernetes Goat. Budget-cap it hard; accidental spend is the most common lab mistake.

### Network topology

```
[ Your workstation ]
        |
   [ Proxmox / VirtualBox ]
        |
        +-- VMNET-isolated (host-only, NO uplink)
        |       ├── Kali (attacker)        10.10.10.10
        |       ├── Target VM / container  10.10.10.20
        |       └── AD lab (Tier 3)        10.10.10.30-40
        |
        +-- VMNET-bridge (internet) → Kali only, for tooling updates
```

Two NICs on Kali: one host-only (to targets), one bridged/NAT (to the internet). Targets get
**only** the host-only NIC. Snapshot before every destructive test.

### Core tooling baseline

Kali ships with most of it. Add: Burp Suite Community (or Pro), `nuclei` + templates,
ProjectDiscovery suite (`subfinder`, `httpx`, `naabu`, `katana`, `dnsx`, `interactsh`),
`ffuf`, `gau`, `sqlmap`, `gitleaks`, `trufflehog`, `semgrep`, Docker, `jq`, `tmux`, `nmap`.
Full list in `by-category/06-tools-recon.md` and `07-tools-exploitation.md`.

**Burp is the lab.** Configure FoxyProxy, install the CA cert, turn on the extensions
Autorize, Turbo Intruder, Hackvertor and Param Miner from day one.

---

## Tier 1 — Guided platforms (do not skip)

Structured, curated, graded. This is where you build the mental models.

| Platform | Cost | Use it for |
|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs) | **Free** | The core. ~150 labs covering every major web class. Do all of them, including Expert. |
| [TryHackMe](https://tryhackme.com/) | Freemium | Gentle on-ramp; guided paths for Linux, web fundamentals, tooling. |
| [HackTheBox Academy](https://academy.hackthebox.com/) | Freemium | Deeper, more realistic modules than THM. |
| [HackTheBox Machines](https://app.hackthebox.com/home) | Freemium | Unguided practice — the bridge to real hunting. |
| [Hacker101](https://www.hacker101.com/) + [CTF](https://ctf.hacker101.com) | **Free** | HackerOne's own material; CTF progress unlocks private program invites. |
| [picoCTF](https://picoctf.org/) | **Free** | Beginner CTF, all categories. |
| [pwn.college](https://dojo.pwn.college/) | **Free** | The best free systems/exploitation curriculum anywhere. |
| [Root-Me](https://www.root-me.org/?lang=en) | **Free** | 500+ challenges, very broad. |
| [OverTheWire](https://overthewire.org/wargames/) | **Free** | Linux/Bandit fundamentals, Natas for web. |
| [PentesterLab](https://pentesterlab.com/exercises) | Paid | Excellent, focused web exercises. |
| [CryptoHack](https://cryptohack.org/) | **Free** | Cryptography, properly taught. |
| [ROP Emporium](https://ropemporium.com/) | **Free** | Exploit development fundamentals, no rabbit hole. |
| [CyberDefenders](https://cyberdefenders.org/) / [LetsDefend](https://letsdefend.io/) | Freemium | Blue-team and DFIR — knowing detection makes you better at evasion and at judging real impact. |

**Sequencing:** PortSwigger Apprentice → TryHackMe web path → PortSwigger Practitioner →
HTB Academy → PortSwigger Expert → HTB machines without walkthroughs.

---

## Tier 2 — Local vulnerable applications (the real skill builder)

Running these locally means unlimited attempts, no rate limits, no scope risk, and — most
importantly — **you can read the source**. Reading the vulnerable code is what turns pattern
matching into understanding.

### Web

| App | What it teaches | Link |
|---|---|---|
| **OWASP Juice Shop** | The best-maintained vulnerable app in existence. Modern Angular/Node/Express. 100+ challenges covering the OWASP Top 10, business logic, and JWT. | [owasp.org](https://owasp.org/www-project-juice-shop/) ✓ · [GitHub](https://github.com/juice-shop/juice-shop) ✓ · [companion guide](https://pwning.owasp-juice.shop/) ✓ |
| **DVWA** | Classic PHP. Difficulty slider is genuinely useful for learning how a fix changes the attack. | [GitHub](https://github.com/digininja/DVWA) ✓ |
| **OWASP WebGoat** | Java/Spring. Deliberately bad practices with lessons attached. | [owasp.org](https://owasp.org/www-project-webgoat/) ✓ · [GitHub](https://github.com/WebGoat/WebGoat) ✓ |
| **bWAPP** | 100+ vulnerabilities, deliberately sprawling. | [itsecgames.com](http://www.itsecgames.com/) — check availability; often unmaintained |
| **OWASP Node.js Goat / RailsGoat / PyGoat** | Framework-specific anti-patterns. | [owasp.org projects](https://owasp.org/projects/) ✓ |
| **OWASP Security Shepherd** | CTF-style, multi-user — good if you are training a team. | [owasp.org](https://owasp.org/www-project-security-shepherd/) ✓ |
| **OWASP WrongSecrets** | Secrets management failures — the #1 real-world cloud mistake. | [owasp.org](https://owasp.org/www-project-wrongsecrets/) ✓ |

### Real CVE reproduction — **vulhub** (highest-value single item in the corpus)

[vulhub.org](https://vulhub.org/) ✓ · [github.com/vulhub/vulhub](https://github.com/vulhub/vulhub) ✓

Docker-compose environments for **hundreds of real, specific CVEs** — Log4Shell, Spring4Shell,
Struts2 chains, Confluence OGNL, Jenkins, Elasticsearch, Weblogic, Drupal, ThinkPHP, Shiro,
Fastjson. Instead of a generic "SQLi" lesson you get *the actual vulnerability that paid out on a
real program*.

```bash
git clone https://github.com/vulhub/vulhub.git
cd vulhub/log4j/CVE-2021-44228 && docker-compose up -d
# reproduce, read the source, write the exploit, tear down
docker-compose down -v
```

This is how you build the CVE-to-exploit intuition that makes Tier-S findings fast. Pair it with
`by-category/11-standards-databases.md` (NVD, CISA KEV, EPSS) to pick which CVEs are worth
learning — sort by EPSS and KEV presence, not by CVSS.

### API

| App | Focus | Link |
|---|---|---|
| **crAPI** (OWASP) | "Completely Ridiculous API". Built specifically around the OWASP API Security Top 10: BOLA, BFLA, mass assignment, JWT abuse. **Do this one.** | [github.com/OWASP/crAPI](https://github.com/OWASP/crAPI) ✓ |
| **VAmPI** | Vulnerable Flask API, OWASP Top 10 mapped. | [github.com/erev0s/VAmPI](https://github.com/erev0s/VAmPI) ✓ |
| **DVWS / dvws-node** | Websocket-specific. | [github.com/interference-security/DVWS](https://github.com/interference-security/DVWS) ✓ |
| **DVNA / DVJA** | Node and Java respectively. | [dvna](https://github.com/appsecco/dvna) ✓ · [dvja](https://github.com/appsecco/dvja) ✓ |

### Cloud / container / IaC

| App | Focus | Link |
|---|---|---|
| **CloudGoat** (Rhino Security) | AWS attack scenarios, `vulnerable-iam` → privilege escalation chains. | [GitHub](https://github.com/RhinoSecurityLabs/cloudgoat) ✓ |
| **IAM Vulnerable** (BishopFox) | AWS privilege escalation by assumption, specifically. | [GitHub](https://github.com/BishopFox/iam-vulnerable) ✓ |
| **SadCloud** (NCC Group) | Deliberately insecure AWS via Terraform — audits your *scanning* skills. | [GitHub](https://github.com/nccgroup/sadcloud) ✓ |
| **Kubernetes Goat** | K8s attack paths, end to end. | [GitHub](https://github.com/madhuakula/kubernetes-goat) ✓ · [docs](https://madhuakula.com/kubernetes-goat/) ✓ |
| **TerraGoat** | Insecure IaC for detection practice. | [GitHub](https://github.com/bridgecrewio/terragoat) ✓ |
| **DVSA** | Vulnerable serverless. | [GitHub](https://github.com/OWASP/DVSA) ✓ |

### Mobile

| App | Platform | Link |
|---|---|---|
| **DIVA** | Android — the standard starter | [github.com/payatu/diva-android](https://github.com/payatu/diva-android) ✓ |
| **AndroGoat** | Android — OWASP MSTG aligned | [github.com/satishpatnayak/AndroGoat](https://github.com/satishpatnayak/AndroGoat) ✓ |
| **InsecureShop** | Android — modern Kotlin | [github.com/optiv/InsecureShop](https://github.com/optiv/InsecureShop) ✓ |
| **OWASP iGoat** | iOS (Swift) | [github.com/OWASP/iGoat-Swift](https://github.com/OWASP/iGoat-Swift) ✓ |
| **DVIA-v2** | iOS | [github.com/prateek147/DVIA-v2](https://github.com/prateek147/DVIA-v2) ✓ |

Tooling: **MobSF** ([GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF) ✓) for
static/dynamic analysis, **Frida** ([frida.re](https://frida.re/) ✓) for runtime instrumentation,
**objection** ([GitHub](https://github.com/sensepost/objection) ✓) for Frida-scripted bypasses,
**jadx** for decompilation. Methodology: the free [OWASP MASTG](https://mas.owasp.org/MASTG/) ✓.

### Full system compromise

| App | Link |
|---|---|
| **Metasploitable3** | [github.com/rapid7/metasploitable3](https://github.com/rapid7/metasploitable3) ✓ |
| **Metasploitable2** | [sourceforge](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/) ✓ |
| **VulnHub** (hundreds of downloadable VMs) | [vulnhub.com](https://www.vulnhub.com/) ✓ |

> ⚠ **Metasploitable2 is intentionally trivially exploitable and must never touch a network with
> an internet uplink.** Host-only NIC only.

---

## Tier 3 — Active Directory and enterprise simulation

This tier is what actually prepares you for Fortune-500 estates, because large enterprises *are*
AD environments with SSO, federation and thousands of hosts.

```bash
# GOAD — Game of Active Directory: the standard free AD attack lab
git clone https://github.com/Orange-Cyberdefense/GOAD.git
# Provision with Vagrant + VirtualBox/VMware/Proxmox or LXC
# Includes: multiple forests, Kerberoasting, AS-REP roasting, ACL abuse,
#           delegation attacks, MSSQL linked servers, ADCS misconfig
```

Add:
- **DetectionLab** — AD lab with full Windows logging/SIEM, so you learn what your attacks look
  like to a defender ([github.com/clong/DetectionLab](https://github.com/clong/DetectionLab))
- **PentestIT / CyberDefenders** AD scenarios
- A **Vulnerable-by-design SSO** setup: Keycloak with deliberately weak realm settings, to
  practise SAML/OIDC attacks safely

Then work the technique references: [HackTricks](https://book.hacktricks.wiki/en/) ~ ,
[GTFOBins](https://gtfobins.github.io/) ✓, [LOLBAS](https://lolbas-project.github.io/) ✓,
[MITRE ATT&CK](https://attack.mitre.org/) ✓.

For AI/LLM work (increasingly in scope on enterprise programs), add a local model stack and
red-team it: **garak** ([github.com/NVIDIA/garak](https://github.com/NVIDIA/garak) ✓),
**promptfoo** ([promptfoo.dev/docs/red-team](https://www.promptfoo.dev/docs/red-team/) ✓),
**Lakera Gandalf** ([gandalf.lakera.ai](https://gandalf.lakera.ai/) ✓). Full list in
`by-category/14-ai-llm-security.md`.

---

## Lab discipline — the habits that make it work

1. **Snapshot before every test.** Proxmox/VirtualBox snapshots cost nothing and save hours.
2. **Isolate the network.** Host-only NICs for targets. No exceptions.
3. **Read the source.** For every Tier-2 app, find the vulnerable line and the fix. This is the
   whole point of running it locally instead of on a hosted platform.
4. **Write it up as if you were submitting.** A lab finding you did not write up is a lab finding
   you did not learn. Practise the `STRATEGY.md` §4 Phase 6 report format every time.
5. **Keep a notes system.** One file per vulnerability class, accumulating payloads, edge cases,
   and *failed* approaches. Your failed-approach log is worth more than your payload list.
6. **Tear down.** `docker-compose down -v`, delete VMs you are not using. Disk fills silently.
7. **Never point lab tooling at production.** A stray `nuclei -l targets.txt` with the wrong file
   is an incident. Keep lab target lists in a separate directory with an obvious name.

### Further reading on lab construction

- [Building a Cybersecurity Lab Environment at Home — Cybrary](https://www.cybrary.it/blog/building-cybersecurity-lab-environment-home) ✓
- [How to Build a Cybersecurity Practice Lab in 2026](https://blog.cyberdesserts.com/cybersecurity-practice-lab-setup/) ✓ — covers local VirtualBox, cloud labs, containers and AI-assisted workflows
- [Cybersecurity Home Lab Setup Guide — UniHackers](https://unihackers.com/blog/cybersecurity-home-lab-setup) ✓ — free-to-advanced progression
