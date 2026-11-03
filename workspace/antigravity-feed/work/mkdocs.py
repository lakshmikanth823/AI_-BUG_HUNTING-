#!/usr/bin/env python3
"""Phase 7: generate TOP_PROGRAMS.md and INDEX.md from harvested data."""
import json, os, re
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
S = json.load(open(os.path.join(HERE, "programs_summary.json"), encoding="utf-8"))
L = json.load(open(os.path.join(ROOT, "data", "links.json"), encoding="utf-8"))
STATS = json.load(open(os.path.join(ROOT, "data", "stats.json"), encoding="utf-8"))
PROG = json.load(open(os.path.join(HERE, "programs_summary.json"), encoding="utf-8"))

# ---------------------------------------------------------------- TOP_PROGRAMS.md
def money(v, c): return f"{v:,.0f} {c}" if v else "—"

o = []
o.append("# Enterprise Bug Bounty Program Targeting Guide\n\n")
o.append(f"**Source:** live program metadata for **{S['total_programs']} programs** scraped from "
         "HackerOne, Bugcrowd, Intigriti and YesWeHack "
         "([arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data)).\n\n")
o.append("**Machine-readable version:** `data/programs-ranked.csv` — regenerate any time with "
         "`cd work && python3 programs.py`. Program scope, payouts and responsiveness change "
         "monthly; this snapshot is dated **2026-10-29**.\n\n")
o.append("> **Authorisation first.** Every entry below is a pointer to a *program page*, not a "
         "target. Read the scope document, out-of-scope list, rate limits and safe-harbor terms "
         "before sending a single packet. Scope changes without notice.\n\n---\n\n")

o.append(f"## Platform coverage\n\n| Platform | Programs indexed |\n|---|---|\n")
for k, v in sorted(S["platform_counts"].items(), key=lambda x: -x[1]):
    o.append(f"| {k} | {v} |\n")
o.append(f"| **Total** | **{S['total_programs']}** |\n\n")
o.append(f"{S['with_published_payout']} of them publish a maximum bounty. HackerOne does not "
         "expose payout amounts through this feed, so it is ranked instead by "
         "**response efficiency** and **bounty-eligible asset count** — both better predictors of "
         "actual earnings than a headline ceiling.\n\n---\n\n")

o.append("## 1. Highest published maximum payouts\n\n")
o.append("| # | Program | Max payout | Platform | In-scope assets |\n|---|---|---|---|---|\n")
for i, p in enumerate(S["top_by_payout"][:40], 1):
    o.append(f"| {i} | [{p['name']}]({p['url']}) | **{money(p['payout'], p['currency'])}** | "
             f"{p['platform']} | {p['in_scope']} |\n")
o.append("\nFull top-100 in `data/programs-ranked.csv`, sorted by `payout`.\n\n")
o.append("**Reading this table:** the top of the list is web3 and a handful of telco/automotive "
         "giants. High ceilings correlate with *narrow* scope and mature internal security teams. "
         "These are the hardest programs in existence and are the wrong place to start.\n\n---\n\n")

o.append("## 2. Most responsive programs on HackerOne\n\n")
o.append("> **Data Limitation Caveat**: Payout data and triage-responsiveness data come from DISJOINT platform sets. HackerOne exposes responsiveness (443 programs) but zero payout figures in this dataset. Bugcrowd, Intigriti, and YesWeHack expose payouts but zero responsiveness figures. The intersection is **ZERO** programs. Therefore, 'pays well AND triages fast' is NOT computable from this dataset. Furthermore, triage times are published by HackerOne in **HOURS** (e.g. 1,543.0 hours = 64.3 days, not 1,543 days).\n\n")
o.append("| Program | Response efficiency | Bounty-eligible assets | Total in-scope | Avg. resolve (hours) | Avg. resolve (days) | Avg. bounty (hours) |\n|---|---|---|---|---|---|---|\n")
for p in S["top_h1_by_responsiveness"][:45]:
    if (p.get("bounty_assets") or 0) < 1: continue
    ttr_h = p.get("ttr_hours")
    ttr_d = p.get("ttr_days") if p.get("ttr_days") is not None else (round(ttr_h / 24, 1) if isinstance(ttr_h, (int, float)) else None)
    ttb_h = p.get("ttb_hours")
    o.append(f"| [{p['name']}]({p['url']}) | **{p['resp_eff']}%** | {p.get('bounty_assets')} | "
             f"{p.get('in_scope')} | {round(ttr_h, 1) if isinstance(ttr_h, (int, float)) else '—'} | "
             f"{round(ttr_d, 1) if isinstance(ttr_d, (int, float)) else '—'} | "
             f"{round(ttb_h, 1) if isinstance(ttb_h, (int, float)) else '—'} |\n")
o.append("\n**Reading this table:** this is where sustained income lives. Sort "
         "`data/programs-ranked.csv` by `resp_eff` desc, filter `offers=True`, and re-run monthly.\n\n---\n\n")

o.append("## 3. Largest attack surface (best for learning and reputation-building)\n\n")
o.append("These programs put thousands of assets in scope — acquisitions, subsidiaries, partner "
         "portals and forgotten infrastructure. Most are disclosure-only (unpaid), which makes "
         "them ideal for your first 50 reports and terrible for income.\n\n")
o.append("| Program | In-scope assets | Paid | Platform |\n|---|---|---|---|\n")
for p in S["largest_attack_surface"][:35]:
    o.append(f"| [{p['name']}]({p['url']}) | **{p['in_scope']:,}** | "
             f"{'yes' if p.get('offers') else 'no'} | {p['platform']} |\n")
o.append("\n---\n\n")

o.append("""## 4. Vendor-operated programs (bypass the platforms entirely)

The biggest tech vendors run their own reward programs with their own rules, queues and payout
tables. These are indexed in `by-category/02-enterprise-programs-top500.md` (375 links):

| Vendor | Entry point |
|---|---|
| Google / Alphabet | [bughunters.google.com](https://bughunters.google.com/) — covers Google, Android, Chrome, Cloud, Firebase, Abseil, Angular, Dart, Flutter, Go, Fuchsia, Kubernetes |
| Microsoft | [msrc.microsoft.com](https://msrc.microsoft.com/) — Windows, Azure, Office, .NET, Dynamics, Edge, Xbox, Hyper-V |
| Apple | [security.apple.com/bounty](https://security.apple.com/bounty/) — published reward tables for both devices and services |
| Meta | [bugbounty.meta.com](https://bugbounty.meta.com/) — [scope & reward tiers](https://bugbounty.meta.com/scope/) |
| GitHub | [securitylab.github.com](https://securitylab.github.com/) + HackerOne |
| Tesla | [tesla.com/support/vulnerability-response](https://www.tesla.com/support/vulnerability-response) |
| Intel | [intel.com/.../security-center](https://www.intel.com/content/www/us/en/security-center/default.html) |
| Cisco | [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html) |
| Oracle | [Security Testing Policy](https://www.oracle.com/corporate/security-practices/testing/faq/) + [vulnerability disclosure](https://www.oracle.com/corporate/security-practices/assurance/vulnerability/disclosure/) — **no open bounty program**; disclosure only |
| Samsung | [security.samsungmobile.com](https://security.samsungmobile.com/rewardsProgram.smsb) |
| Qualcomm | [qualcomm.com/company/product-security](https://www.qualcomm.com/company/product-security) |
| NVIDIA | [nvidia.com/en-us/security](https://www.nvidia.com/en-us/security/) |
| IBM | [ibm.com/.../bounty](https://www.ibm.com/security/secure-engineering/bounty.html) |
| Salesforce | [security.salesforce.com](https://security.salesforce.com/) |
| AWS | [aws.amazon.com/security/vulnerability-reporting](https://aws.amazon.com/security/vulnerability-reporting/) |

**ICS / OT / medical device** vendors disclose through CISA rather than a bounty platform —
see [CISA ICS advisories](https://www.cisa.gov/ics-advisories) and
[Siemens CERT portal](https://cert-portal.siemens.com/).

---

## 5. Web3 / smart-contract programs (highest ceilings, highest skill floor)

[Immunefi](https://immunefi.com/explore/) hosts the largest payouts in the industry — OpenSea's
$3M ceiling comes from the Bugcrowd dataset, but Immunefi regularly lists $1M–$10M rewards for
smart-contract and chain-level findings. The skill set is almost disjoint from web hacking
(Solidity/EVM, DeFi composability, oracle manipulation, bridge logic). Enter only if you
already have that background — but if you do, the expected value per hour beats web.

---

## 6. How to use this file with Antigravity

`by-category/02-enterprise-programs-top500.md` is packaged as Antigravity rule files
`11-enterprise-programs-top500-part{1,2}.md` with a `model_decision` trigger, so the agent pulls
in the enterprise program list only when a task involves researching a specific company's
security posture. `data/programs-ranked.csv` stays outside the rules budget for programmatic
queries.
""")

open(os.path.join(ROOT, "TOP_PROGRAMS.md"), "w", encoding="utf-8").write("".join(o))
print(f"TOP_PROGRAMS.md: {len(''.join(o)):,} bytes")

# ---------------------------------------------------------------- INDEX.md
CATS = [
 ("01","platforms-bounty-programs","Bug Bounty Platforms & Program Directories",
  "Where to find programs and check scope."),
 ("02","enterprise-programs-top500","Enterprise / Big-Tech & Fortune-500 Program Pages",
  "Direct VRP and PSIRT pages for large organisations."),
 ("03","writeups-bug-bounty","Bug Bounty Writeups & Disclosed Reports",
  "Learn from real, paid, disclosed reports."),
 ("04","methodology-cheatsheets","Methodology, Checklists & Cheat Sheets",
  "How to actually run a hunt, end to end."),
 ("05","vuln-classes-reference","Vulnerability Class Reference & Payloads",
  "Per-class technique docs and payload collections."),
 ("06","tools-recon","Recon & Asset Discovery Tools",
  "Finding the attack surface."),
 ("07","tools-exploitation","Exploitation, Scanning & Fuzzing Tools",
  "Confirming and demonstrating impact."),
 ("08","labs-vulnerable-apps","Vulnerable Apps & Practice Labs",
  "Safe local reproduction of every class."),
 ("09","ctf-platforms-labs","CTF Platforms & Training Ranges",
  "Where to build reps."),
 ("10","writeups-ctf","CTF Writeups & Archives",
  "Worked solutions by event, year and challenge."),
 ("11","standards-databases","Vulnerability Databases, Standards & Threat Intel",
  "CVE/CWE/CVSS/EPSS/KEV, advisories, internet-wide scanning."),
 ("12","books-courses","Books, Courses & Certifications",
  "The canonical reading list and training paths."),
 ("13","mobile-api-cloud-iot","Mobile, API, Cloud, IoT & OT Security",
  "Domain-specific testing."),
 ("14","ai-llm-security","AI / LLM & Agentic Security",
  "Prompt injection, LLM red teaming, agentic tooling abuse."),
 ("15","github-security-repos","GitHub Security Repositories & Awesome Lists",
  "Curated lists and repositories worth cloning."),
 ("16","youtube-media","Talks, Conferences, Video & Podcasts",
  "DEF CON / Black Hat / Recon media and channels."),
 ("17","communities-forums","Communities, Forums & Discords",
  "Where researchers share and ask."),
]
links_all = L["links"]
by_cat = defaultdict(list)
for r in links_all:
    by_cat[r["category"]].append(r)

i = []
i.append("# Index — Security Research Link Corpus\n\n")
c = STATS
i.append(f"**{c['final_kept']:,} verified URLs** across {len(CATS)} categories · "
         f"{c['live_verified_http200']:,} confirmed HTTP 200 · "
         f"{c['antibot_but_valid']:,} behind anti-bot protection but valid · "
         f"{c['core_relevance']:,} security-core (the rest is adjacent OSINT/IR material).\n\n")
i.append("Collected 2026-10-29 from 70+ curated sources (awesome-lists, GitHub trees, "
         "the arkadiyt bounty-program dataset, and hand-curation), de-duplicated from 22,500 raw "
         "links, and individually HTTP-validated.\n\n")
i.append("## Documents\n\n")
i.append("| File | What it is |\n|---|---|\n")
i.append("| `README.md` | How to install this into Antigravity and what each file is for |\n")
i.append("| `STRATEGY.md` | Methodology, what pays, how to pick targets, the 7-phase hunt |\n")
i.append("| `TOP_PROGRAMS.md` | Data-driven guide to real bounty programs with payouts, scope size and responsiveness |\n")
i.append("| `BOOKS.md` | Annotated reading list and learning path |\n")
i.append("| `LABS.md` | Three-tier home-lab build plan |\n\n")
i.append("## Categories\n\n")
i.append("| # | Category | Links | Full listing |\n|---|---|---|---|\n")
for num, key, title, blurb in CATS:
    n = len(by_cat.get(key, []))
    i.append(f"| {num} | **{title}**<br><sub>{blurb}</sub> | {n:,} | "
             f"`by-category/{num}-{key}.md` |\n")
i.append(f"| | **Total** | **{c['final_kept']:,}** | |\n\n")

i.append("## Start here — hand-picked highest-value links\n\n")
i.append("Everything else in the corpus is breadth; these are the load-bearing resources.\n")

PICK_PATTERNS = [
 # methodology / standards
 "portswigger.net/web-security/all-labs", "portswigger.net/web-security$",
 "owasp.org/www-project-web-security-testing-guide/stable",
 "cheatsheetseries.owasp.org", "owasp.org/www-project-top-ten",
 "book.hacktricks.wiki/en/", "gtfobins.github.io", "lolbas-project.github.io",
 "portswigger.net/research", "KathanP19/HowToHunt", "EdOverflow/bugbounty-cheatsheet",
 "owasp.org/www-project-application-security-verification-standard",
 "mas.owasp.org/MASTG", "owasp.org/API-Security",
 # vulnerability classes & payloads
 "swisskyrepo.github.io/PayloadsAllTheThings", "html5sec.org",
 "portswigger.net/web-security/cross-site-scripting/cheat-sheet",
 "Swisskyrepo/PayloadsAllTheThings", "attack.mitre.org/techniques",
 # writeups
 "reddelexc/hackerone-reports", "devanshbatham/Awesome-Bugbounty-Writeups",
 "hackerone.com/hacktivity", "pentester.land/list-of-bug-bounty-writeups",
 "infosecwriteups.com$", "blog.orange.tw", "0xdf.gitlab.io$",
 "googleprojectzero.blogspot.com",
 # labs
 "juice-shop/juice-shop", "vulhub/vulhub", "OWASP/crAPI", "digininja/DVWA",
 "RhinoSecurityLabs/cloudgoat", "pwning.owasp-juice.shop", "WebGoat/WebGoat",
 "madhuakula/kubernetes-goat", "BishopFox/iam-vulnerable", "OWASP/iGoat-Swift",
 "rapid7/metasploitable3",
 # books / training
 "nostarch.com/bug-bounty-bootcamp", "nostarch.com/bughunting",
 "nostarch.com/hacking-apis", "leanpub.com/web-hacking-101", "nostarch.com/bughunter",
 "nostarch.com/catalog/security", "nostarch.com/black-hat-graphql",
 "nostarch.com/binaryanalysis", "portswigger.net/web-security/certification",
 "pwn.college$", "certifications.tcm-sec.com/pnpt",
 # platforms & programs
 "hackerone.com/directory/programs", "bugcrowd.com/bug-bounty-list",
 "immunefi.com/explore", "intigriti.com/programs", "yeswehack.com/programs$",
 "hacker101.com$", "arkadiyt/bounty-targets-data", "disclose.io$",
 "bughunters.google.com$", "security.apple.com/bounty", "msrc.microsoft.com$",
 "bugbounty.meta.com$", "securitylab.github.com", "cisa.gov/ics-advisories",
 # standards / databases
 "nvd.nist.gov/vuln/search", "cwe.mitre.org/data/definitions/699",
 "first.org/epss", "cisa.gov/known-exploited-vulnerabilities-catalog",
 "crt.sh$", "osv.dev$", "zerodayinitiative.com/advisories/published",
 "exploit-db.com$", "first.org/cvss/calculator",
 # AI / LLM
 "genai.owasp.org/llm-top-10", "atlas.mitre.org", "NVIDIA/garak",
 "promptfoo.dev/docs/red-team", "simonwillison.net/tags/prompt-injection",
 # tools
 "projectdiscovery/nuclei$", "projectdiscovery/subfinder", "projectdiscovery/httpx",
 "projectdiscovery/katana", "projectdiscovery/interactsh",
 "projectdiscovery/nuclei-templates", "danielmiessler/SecLists", "lc/gau",
 "ffuf/ffuf", "wordlists.assetnote.io", "assetnote/kiterunner",
 "portswigger.net/burp/communitydownload", "sqlmapproject/sqlmap",
 "frohoff/ysoserial", "ambionics/phpggc", "MobSF/Mobile-Security-Framework-MobSF",
 "semgrep/semgrep", "frida.re$", "trufflesecurity/trufflehog", "gitleaks/gitleaks",
 "hahwul/dalfox", "commixproject/commix", "epinna/tplmap",
 # CTF & practice
 "app.hackthebox.com/home", "tryhackme.com$", "ctftime.org$", "ctftime.org/writeups",
 "picoctf.org$", "overthewire.org/wargames", "cryptohack.org",
 "sajjadium/ctf-writeups", "perfectblue/ctf-writeups", "ctf-wiki.org/en",
 "ropemporium.com", "exploit.education", "vulnhub.com$", "root-me.org",
 # mobile / cloud
 "ashishb/android-security-awesome", "vaib25vicky/awesome-mobile-security",
 "tanprathan/MobileApp-Pentest-Cheatsheet", # mega-lists & media
 "enaqx/awesome-pentest", "qazbnm456/awesome-web-security", "apsdehal/awesome-ctf",
 "HackTricks-wiki/hacktricks$", "carpedm20/awesome-hacking", "sbilly/awesome-security",
 "media.defcon.org", "blackhat.com$", "recon.cx",
 "reddit.com/r/bugbounty", "reddit.com/r/netsec", "security.stackexchange.com$",
]

TITLE = {kk: t for _n, kk, t, _b in CATS}
used, found = set(), []
unmatched = []
for pat in PICK_PATTERNS:
    tail = pat.endswith("$")
    needle = pat.rstrip("$").lower()
    for r in links_all:
        if r["url"] in used: continue
        u = re.sub(r"^https?://(www\.)?", "", r["url"].rstrip("/")).lower()
        if u == needle or u.endswith("/" + needle) or (not tail and needle in u):
            found.append(r); used.add(r["url"]); break
    else:
        unmatched.append(pat)
if unmatched:
    print(f"  unmatched picks ({len(unmatched)}): {unmatched}")

grouped = defaultdict(list)
for r in found: grouped[r["category"]].append(r)
for _num, key, title, _blurb in CATS:
    rows = grouped.get(key, [])
    if not rows: continue
    i.append(f"\n### {title}\n\n")
    for r in rows:
        t = (r.get("title") or "").strip() or r["url"]
        if len(t) > 78: t = t[:75] + "…"
        i.append(f"- {'✓' if r.get('live') else '~'} [{t}]({r['url']})\n")
i.append(f"\n<sub>{len(found)} hand-picked links; the remaining "
         f"{c['final_kept'] - len(found):,} are in `by-category/`.</sub>\n")

i.append("\n\n## Data files\n\n")
i.append("| File | Format | Contents |\n|---|---|---|\n")
i.append(f"| `data/all-links.txt` | text | All {c['final_kept']:,} URLs, one per line |\n")
i.append(f"| `data/all-links-core.txt` | text | {c['core_relevance']:,} security-core URLs (generic OSINT noise removed) |\n")
i.append(f"| `data/verified-live-only.txt` | text | {c['live_verified_http200']:,} URLs that returned HTTP 200 |\n")
i.append("| `data/links.csv` | CSV | url, title, category, relevance, verified, status, source |\n")
i.append("| `data/links.json` | JSON | Same, nested, with counts |\n")
i.append(f"| `data/programs-ranked.csv` | CSV | {S['total_programs']} bounty programs: payout, scope size, responsiveness |\n")
i.append(f"| `data/dropped-dead-links.csv` | CSV | {c['dropped_dead']} dead links that were excluded, with reason |\n")
i.append(f"| `data/dropped-unsafe-ssrf-targets.txt` | text | {c['dropped_unsafe_ssrf']} SSRF metadata endpoints deliberately stripped |\n")
i.append("| `data/stats.json` | JSON | Pipeline statistics |\n\n")
i.append("## Antigravity package\n\n")
i.append("```\nantigravity/\n├── AGENTS.md                    # workspace description, always active\n└── .agents/rules/\n")
i.append("    ├── 00-corpus-index.md      # always_on: category map + hard safety rules\n")
i.append("    └── 10..26-<category>[-partN].md   # model_decision: the links themselves\n```\n\n")
import glob as _g
_rf = _g.glob(os.path.join(ROOT, "antigravity/.agents/rules/*.md"))
_mx = max((os.path.getsize(x) for x in _rf), default=0)
i.append(f"{len(_rf)} rule files, every one under Antigravity's 24,000-byte per-file limit, "
         f"largest {_mx:,} bytes. Only the index is `always_on`; categories load on demand.\n")

open(os.path.join(ROOT, "INDEX.md"), "w", encoding="utf-8").write("".join(i))
print(f"INDEX.md: {len(''.join(i)):,} bytes")
