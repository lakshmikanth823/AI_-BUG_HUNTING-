#!/usr/bin/env python3
"""Phase 6: build the Antigravity drop-in package (.agents/rules/*.md, chunked <22KB)."""
import json, os, re, textwrap
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
AG   = os.path.join(ROOT, "antigravity")
RULES = os.path.join(AG, ".agents", "rules")
os.makedirs(RULES, exist_ok=True)

L = json.load(open(os.path.join(ROOT, "data", "links.json"), encoding="utf-8"))
stats = json.load(open(os.path.join(ROOT, "data", "stats.json"), encoding="utf-8"))
PROG = json.load(open(os.path.join(HERE, "programs_summary.json"), encoding="utf-8"))
NPROG = PROG.get("total_programs", "?")
cands = L["links"]   # already normalised, filtered, classified and validated by emit.py

KEEP = {"ok", "skipped", "bot-blocked", "server-error"}
UNSAFE = re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|"
                    r"0\.0\.0\.0|\.internal$|\.local$|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.)", re.I)
import urllib.parse, ipaddress
def safe(u):
    h = urllib.parse.urlparse(u).netloc.lower()
    if UNSAFE.search(h): return False
    try:
        ipaddress.ip_address(h); return False
    except ValueError:
        return True

links = [r for r in cands if r.get("status") in KEEP and safe(r["url"])]
for r in links:
    r["live"] = r["status"] in ("ok", "skipped")

CATS = [
 ("10","platforms-bounty-programs","bug bounty program platforms and directories",
  "HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi program URLs and directories. Use when the task is finding or triaging a bug bounty program, checking scope, or picking a target."),
 ("11","enterprise-programs-top500","enterprise VRP and PSIRT pages for large companies",
  "Direct vulnerability reward / PSIRT / responsible-disclosure pages for big-tech, finance, healthcare, automotive and ICS vendors. Use when researching a specific large company's program or security posture."),
 ("12","writeups-bug-bounty","public bug bounty reports and writeups",
  "Disclosed bug bounty reports, hacktivity archives, researcher blogs and writeup collections. Use when looking for prior art on a vulnerability class or learning report quality."),
 ("13","methodology-cheatsheets","web security testing methodology and checklists",
  "OWASP WSTG/ASVS/Top-10/CheatSheetSeries, PortSwigger Academy, HackTricks, GTFOBins, LOLBAS and hunting methodologies. Use when planning a test, building a checklist, or verifying coverage."),
 ("14","vuln-classes-reference","vulnerability technique and payload reference",
  "Per-vulnerability technique docs and payload collections: SQLi, XSS, SSRF, IDOR, SSTI, deserialization, request smuggling, race conditions, auth bypass. Use when constructing or explaining a specific vulnerability class."),
 ("15","tools-recon","reconnaissance and asset discovery tooling",
  "Subdomain enumeration, crawling, parameter mining, secret scanning, wordlists, OSINT and internet-wide search engines. Use when building a recon pipeline or discovering attack surface."),
 ("16","tools-exploitation","exploitation, scanning, fuzzing and analysis tooling",
  "Proxies, scanners, fuzzers, deserialization gadget generators, SAST/code analysis, mobile and binary tooling. Use when selecting a tool to confirm or exploit a finding."),
 ("17","labs-vulnerable-apps","deliberately vulnerable apps for local practice",
  "Juice Shop, DVWA, WebGoat, vulhub, crAPI, CloudGoat, Kubernetes Goat, mobile vulnerable apps. Use when setting up a safe local lab to reproduce a vulnerability class."),
 ("18","ctf-platforms-labs","CTF platforms and training ranges",
  "HackTheBox, TryHackMe, PortSwigger Labs, picoCTF, pwn.college, Root-Me, OverTheWire and similar. Use when recommending practice environments or skills drills."),
 ("19","writeups-ctf","CTF writeup archives",
  "CTF writeup archives by event/year/challenge plus CTFtime. Use when looking for worked solutions to pwn/web/crypto/rev challenges."),
 ("20","standards-databases","vulnerability databases, standards and threat intel",
  "NVD, CVE, CWE, CVSS, EPSS, CISA KEV, Exploit-DB, OSV, vendor advisory feeds, Shodan/Censys/crt.sh. Use when looking up CVE data, severity scoring, exploitability or certificate transparency."),
 ("21","books-courses","security books, courses and certifications",
  "Canonical reading list and training: No Starch, Wiley, Packt, O'Reilly, OSCP/PNPT/BSCP and free academies. Use when recommending learning material."),
 ("22","mobile-api-cloud-iot","mobile, API, cloud, IoT and OT security",
  "Android/iOS, REST/GraphQL API, AWS/Azure/GCP/Kubernetes, IoT firmware and ICS/OT specific resources. Use for domain-specific testing guidance."),
 ("23","ai-llm-security","AI, LLM and agentic system security",
  "Prompt injection, jailbreaks, LLM red teaming, OWASP LLM/GenAI Top 10, MITRE ATLAS, AI bug bounties. Use when testing or reasoning about AI-enabled systems."),
 ("24","github-security-repos","security repositories and curated awesome lists",
  "GitHub security orgs, awesome-lists and repositories worth cloning. Use when sourcing or recommending a codebase."),
 ("25","youtube-media","conference talks, videos, podcasts and newsletters",
  "DEF CON, Black Hat, Recon and other conference media, YouTube channels, podcasts, newsletters. Use when recommending a talk or written deep-dive."),
 ("26","communities-forums","security research communities and forums",
  "Subreddits, Discords, Stack Exchange sites and forums where researchers share findings. Use when recommending where to ask or share."),
]

TITLE = {
 "platforms-bounty-programs":"Bug Bounty Platforms & Program Directories",
 "enterprise-programs-top500":"Enterprise / Fortune-500 Program Pages",
 "writeups-bug-bounty":"Bug Bounty Writeups & Disclosed Reports",
 "methodology-cheatsheets":"Methodology, Checklists & Cheat Sheets",
 "vuln-classes-reference":"Vulnerability Class Reference & Payloads",
 "tools-recon":"Recon & Asset Discovery Tools",
 "tools-exploitation":"Exploitation, Scanning & Fuzzing Tools",
 "labs-vulnerable-apps":"Vulnerable Apps & Practice Labs",
 "ctf-platforms-labs":"CTF Platforms & Training Ranges",
 "writeups-ctf":"CTF Writeups & Archives",
 "standards-databases":"Vulnerability Databases, Standards & Threat Intel",
 "books-courses":"Books, Courses & Certifications",
 "mobile-api-cloud-iot":"Mobile, API, Cloud, IoT & OT Security",
 "ai-llm-security":"AI / LLM & Agentic Security",
 "github-security-repos":"GitHub Security Repos & Awesome Lists",
 "youtube-media":"Talks, Conferences, Video & Podcasts",
 "communities-forums":"Communities, Forums & Discords",
}

by_cat = defaultdict(list)
for r in links:
    by_cat[r["category"]].append(r)
for k in by_cat:
    by_cat[k].sort(key=lambda r: (0 if r["source"] == "CURATED" else 1,
                                  0 if r["live"] else 1, r["url"].lower()))

MAX = 22500   # stay under Antigravity's 24,000-byte per-file limit

def emit_chunk(num, key, desc, rows, part, nparts, subtitle):
    body = []
    body.append("---\n")
    body.append("trigger: model_decision\n")
    d = subtitle if nparts == 1 else f"{subtitle} (part {part}/{nparts})"
    body.append(f'description: "{d}"\n')
    body.append("---\n\n")
    body.append(f"# Security Research Link Corpus — {TITLE.get(key, key)}\n\n")
    body.append(f"Part {part} of {nparts}. {len(rows)} links. "
                "`✓` = HTTP 200 verified at collection time; `~` = returned an anti-bot "
                "403/429 or 5xx but is normally valid (Cloudflare-protected).\n\n")
    for r in rows:
        t = (r.get("title") or "").strip().replace("\n", " ")
        t = (t[:70] + "…") if len(t) > 70 else t
        mark = "✓" if r["live"] else "~"
        body.append(f"- {mark} <{r['url']}>" + (f" — {t}" if t and t != "—" else "") + "\n")
    txt = "".join(body)
    if len(txt.encode()) > 24000:
        raise SystemExit(f"FATAL: {num}-{key} part{part} is {len(txt.encode())} bytes (>24000 limit)")
    name = f"{num}-{key}.md" if nparts == 1 else f"{num}-{key}-part{part}.md"
    open(os.path.join(RULES, name), "w", encoding="utf-8").write(txt)
    return name, len(rows), len(txt.encode())

written = []
for num, key, desc, subtitle in CATS:
    rows = by_cat.get(key, [])
    if not rows: continue
    # chunk
    chunks, cur, size = [], [], 400
    for r in rows:
        est = 42 + len(r["url"]) + min(len(r.get("title") or ""), 70)
        if size + est > MAX and cur:
            chunks.append(cur); cur, size = [], 400
        cur.append(r); size += est
    if cur: chunks.append(cur)
    for i, ch in enumerate(chunks, 1):
        written.append(emit_chunk(num, key, desc, ch, i, len(chunks), subtitle))

# ------------------------------------------------------------------ index rule
idx = ["---\n", "trigger: always_on\n", "---\n\n",
       "# Security Research Link Corpus (index)\n\n",
       f"This workspace ships a curated corpus of **{len(links):,} security-research URLs** "
       "covering bug bounty hunting, CTFs, offensive tooling, vulnerable labs, standards "
       "databases and the canonical reading list. It exists so the agent can cite real, "
       "current sources instead of inventing URLs.\n\n",
       "## How to use it\n\n",
       "1. Each category below is a separate `model_decision` rule under `.agents/rules/`. "
       "The agent loads only the category that matches the current task — do not read them all.\n",
       "2. For bulk or programmatic use, the same corpus is in machine-readable form:\n",
       "   - `data/all-links.txt` — every URL, one per line\n",
       "   - `data/all-links-core.txt` — security-relevant subset (drops generic OSINT noise)\n",
       "   - `data/verified-live-only.txt` — only URLs that returned HTTP 200\n",
       "   - `data/links.csv` / `data/links.json` — with title, category, verification status, source\n",
       "   - `data/programs-ranked.csv` — real bounty programs with payouts, scope size and responsiveness\n",
       "3. Grep before you guess: `grep -i ssrf data/all-links.txt` beats recalling a URL from memory.\n\n",
       "## Category map\n\n",
       "| Rule file | Category | Links |\n|---|---|---|\n"]
for num, key, desc, subtitle in CATS:
    n = len(by_cat.get(key, []))
    if n: idx.append(f"| `{num}-{key}*.md` | {subtitle} | {n:,} |\n")
idx += ["\n## Hard safety rules (always apply)\n\n",
 "- **Authorization is a precondition.** Never generate, execute, or help refine an attack "
 "against a host, application, or account the user does not own or is not explicitly authorized "
 "to test. Ask for the scope document, program URL, or written permission first.\n",
 "- **Stay in scope.** Respect each program's out-of-scope list, rate limits, and safe-harbor terms.\n",
 "- **No SSRF against cloud metadata.** Endpoints such as `169.254.169.254`, "
 "`metadata.google.internal`, `100.100.100.200` and `fd00:ec2::254` were deliberately removed "
 "from this corpus. Do not re-add or fetch them — they can expose cloud credentials.\n",
 "- **No live exploitation of third parties.** Demonstrate impact in a local lab "
 "(`by-category/17-labs-vulnerable-apps.md`) or against your own infrastructure.\n",
 "- **Report, don't leak.** Do not help publish unreported vulnerabilities, PII, or customer data.\n",
 "- **Verify before citing.** Links marked `~` returned an anti-bot response; confirm they "
 "resolve before quoting them as fact.\n"]
open(os.path.join(RULES, "00-corpus-index.md"), "w", encoding="utf-8").write("".join(idx))

# ------------------------------------------------------------------ AGENTS.md
agents = f"""# Workspace: Security Research Link Corpus

This workspace is a **reference corpus**, not an application. It contains
**{len(links):,} curated, de-duplicated, HTTP-verified security-research URLs** intended to be
fed to an agent as grounding material for bug bounty and CTF work.

## What is here

| Path | Contents |
|---|---|
| `STRATEGY.md` | The methodology: how to hunt, what pays, how to pick targets |
| `TOP_PROGRAMS.md` | Data-driven enterprise program targeting guide |
| `BOOKS.md` | Curated reading list and learning path |
| `LABS.md` | Three-tier home-lab build plan |
| `INDEX.md` | Human-readable index of all 17 categories |
| `data/` | Machine-readable corpus: `.txt`, `.csv`, `.json` |
| `by-category/` | Full categorized listings with titles and verification status |
| `.agents/rules/` | This corpus, chunked into Antigravity `model_decision` rules |
| `work/` | The harvesting / validation pipeline (reproducible) |

## Agent behaviour in this workspace

- Load `.agents/rules/00-corpus-index.md` first; it is `always_on` and maps every category.
- Pull in only the category rule that matches the task. Do not read all of them.
- Prefer `grep`/`rg` over `data/` files for lookup; the corpus is too large to load wholesale.
- Treat every URL as a *lead to verify*, not a fact. Verification status is recorded per link.
- Follow the hard safety rules in the index rule file without exception.

## Regenerating / refreshing

```
cd work
python3 harvest.py && python3 harvest2.py && python3 curated.py   # collect
python3 build.py                                                  # dedupe + classify
python3 validate.py                                               # HTTP verify (~2 min)
python3 programs.py                                               # bounty program ranking
python3 emit.py && python3 mkantigravity.py                       # emit deliverables
```
"""
open(os.path.join(AG, "AGENTS.md"), "w", encoding="utf-8").write(agents)

print(f"links placed: {len(links)}")
print(f"rule files written: {len(written) + 1}")
over = [(n, b) for n, c, b in written if b > 24000]
print(f"files over 24KB limit: {len(over)}")
print(f"largest file: {max(b for _,_,b in written):,} bytes")
print(f"smallest file: {min(b for _,_,b in written):,} bytes")
for n, c, b in written:
    print(f"  {b:7,}B  {c:5d} links  {n}")
