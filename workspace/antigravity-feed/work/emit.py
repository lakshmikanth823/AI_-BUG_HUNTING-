#!/usr/bin/env python3
"""Phase 4: final filter + emit all deliverables."""
import json, os, re, csv, socket, ipaddress, urllib.parse
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))   # antigravity-feed/
d = json.load(open(os.path.join(HERE, "validated.json"), encoding="utf-8"))
cands, bounty = d["candidates"], d["bounty"]

KEEP = {"ok", "skipped", "bot-blocked", "server-error"}

# ------------------------------------------------------------------ safety filter
UNSAFE_HOST = re.compile(
    r"(^|\.)("
    r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|"
    r"100\.100\.100\.200|fd00:ec2::254|instance-data|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|.*\.internal|.*\.local|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r")$", re.I)

# URLs superseded by a newer official page (verified 2026-10-29)
SUPERSEDED = {
 "https://facebook.com/whitehat",            # -> https://bugbounty.meta.com
 "https://facebook.com/whitehat/payments",   # -> https://bugbounty.meta.com/scope
 "https://oracle.com/corporate/security-practices/assurance/bug-bounty.html",
}

def is_unsafe(host):
    if UNSAFE_HOST.match(host): return True
    try:                                  # any bare IP literal
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

SEC_HINT = re.compile(
 r"(hack|secur|exploit|vuln|ctf|pentest|bug|cve|cyber|osint|forensic|malware|"
 r"payload|redteam|red-team|blue-?team|reverse|pwn|owasp|nuclei|burp|metasploit|"
 r"threat|intel|crypt|infosec|0x|shell|inject|fuzz|defen|attack|breach|recon|"
 r"subdomain|dork|phish|scan|enum|api|cloud|aws|azure|gcp|k8s|docker|linux|"
 r"windows|web|mobile|android|ios|network|ad-|active-directory|sqli|xss|ssrf|"
 r"rce|idor|lfi|rfi|xxe|csrf|jwt|oauth|saml|kerberos|ldap|dns|http|tls|ssl|"
 r"binary|heap|stack|kernel|firmware|iot|scada|ics|ot-|car|drone|satellite|"
 r"nmap|wireshark|ghidra|frida|sqlmap|nikto|dirb|gobuster|hashcat|john|"
 r"mimikatz|cobalt|empire|c2|beacon|ransom|apt|malicious|c2|sandbox|"
 r"hacker|hunting|bounty|disclos|advisory|psirt|msrc|cert|cisa|mitre|nist)", re.I)

# low-value patterns: bare GitHub profiles, avatar/CDN assets, Telegram
LOW_VALUE = re.compile(
    r"(^https://github\.com/[^/]+/?$"          # user/org profile, no repo
    r"|githubusercontent\.com/"                # avatars & raw assets
    r"|^https://t\.me/"                        # telegram invites/channels
    r"|^https://telegram\.me/"
    r"|^https://discord\.gg/"
    # social/profile pages that survive www-stripping and add nothing to a research corpus
    r"|(^|\.)(instagram\.com|tiktok\.com|pinterest\.com|tumblr\.com|medium\.com"
    r"|t\.co|linktr\.ee|link\.tr|keybase\.io|about\.me|gravatar\.com"
    r"|slideshare\.net/[^/]+/?$|quora\.com|goodreads\.com/review)"
    r")", re.I)

dropped_unsafe, dropped_dead, dropped_low = [], [], []
final = []
for r in cands:
    u = r["url"]
    host = urllib.parse.urlparse(u).netloc.lower()
    if is_unsafe(host):
        dropped_unsafe.append(u); continue
    # exempt hand-curated links: e.g. github.com/OWASP and github.com/projectdiscovery
    # are organisation pages (valuable), not personal profiles (noise)
    if u.rstrip("/").lower() in SUPERSEDED:
        dropped_low.append((u, "superseded", None)); continue
    if LOW_VALUE.search(u) and r.get("source") != "CURATED":
        dropped_low.append((u, "low-value", None)); continue
    if r["status"] not in KEEP:
        dropped_dead.append((u, r["status"], r.get("code"))); continue
    blob = (host + " " + (r.get("title") or "") + " " + (r.get("source") or "")).lower()
    r["relevance"] = "core" if SEC_HINT.search(blob) else "adjacent"
    r["live"] = r["status"] in ("ok", "skipped")
    final.append(r)

print(f"final kept: {len(final)}  (unsafe stripped: {len(dropped_unsafe)}, "
      f"low-value: {len(dropped_low)}, dead dropped: {len(dropped_dead)})")

# ------------------------------------------------------------------ categories
CATS = [
 ("01", "platforms-bounty-programs", "Bug Bounty Platforms & Program Directories",
  "Where to find programs: HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, Immunefi and program directories."),
 ("02", "enterprise-programs-top500", "Enterprise / Big-Tech & Fortune-500 Program Pages",
  "Direct VRP and PSIRT pages for large enterprises: Google, Microsoft, Apple, Meta, GitHub, Tesla, Intel, Cisco, healthcare, ICS, finance."),
 ("03", "writeups-bug-bounty", "Bug Bounty Writeups & Disclosed Reports",
  "Real disclosed bug bounty reports, hacktivity, writeup archives, and researcher blogs to learn from."),
 ("04", "methodology-cheatsheets", "Methodology, Checklists & Cheat Sheets",
  "How to actually hunt: OWASP WSTG/ASVS/Top-10, PortSwigger Academy, HackTricks, GTFOBins, LOLBAS, recon-to-report workflows."),
 ("05", "vuln-classes-reference", "Vulnerability Class Reference & Payloads",
  "Per-vulnerability technique references, payload collections, and deep-dive docs (SQLi, XSS, SSRF, IDOR, deserialization, SSTI, race conditions)."),
 ("06", "tools-recon", "Recon & Asset Discovery Tools",
  "Subdomain enumeration, crawling, parameter discovery, secret scanning, OSINT, wordlists, and search engines (Shodan/Censys/FOFA)."),
 ("07", "tools-exploitation", "Exploitation, Scanning & Fuzzing Tools",
  "Proxies, scanners, fuzzers, deserialization gadgets, SAST/code analysis, mobile tooling, and exploitation frameworks."),
 ("08", "labs-vulnerable-apps", "Vulnerable Apps & Practice Labs",
  "Deliberately vulnerable applications (Juice Shop, DVWA, WebGoat, vulhub, crAPI, CloudGoat) for safe local practice."),
 ("09", "ctf-platforms-labs", "CTF Platforms & Training Ranges",
  "Where to practice: HTB, TryHackMe, PortSwigger Labs, picoCTF, pwn.college, Root-Me, OverTheWire and more."),
 ("10", "writeups-ctf", "CTF Writeups & Archives",
  "Complete CTF writeup archives by event, year and challenge, plus CTFtime."),
 ("11", "standards-databases", "Vulnerability Databases, Standards & Threat Intel",
  "NVD, CVE, CWE, CVSS/EPSS, CISA KEV, Exploit-DB, OSV, advisory feeds, and internet-wide scanning."),
 ("12", "books-courses", "Books, Courses & Certifications",
  "The canonical reading list and training: No Starch, Wiley, Packt, OSCP/PNPT/BSCP, and free academies."),
 ("13", "mobile-api-cloud-iot", "Mobile, API, Cloud, IoT & OT Security",
  "Android/iOS, REST/GraphQL API, AWS/Azure/GCP/K8s, IoT firmware and ICS/OT specific resources."),
 ("14", "ai-llm-security", "AI / LLM & Agentic Security",
  "Prompt injection, jailbreaks, LLM red teaming, OWASP LLM Top 10, MITRE ATLAS, and AI bug bounties."),
 ("15", "github-security-repos", "GitHub Security Repositories & Awesome Lists",
  "Curated awesome-lists, security orgs, and repositories worth cloning into your toolchain."),
 ("16", "youtube-media", "Talks, Conferences, Video & Podcasts",
  "Conference talks (DEF CON, Black Hat, Recon), YouTube channels, podcasts and newsletters."),
 ("17", "communities-forums", "Communities, Forums & Discords",
  "Where researchers hang out and share: subreddits, Discords, Stack Exchange, forums."),
]
CAT_META = {k: (n, t, desc) for k, n, t, desc in [(c[0], c[1], c[2], c[3]) for c in CATS]}
CAT_ORDER = {c[1]: i for i, c in enumerate(CATS)}

by_cat = defaultdict(list)
for r in final:
    by_cat[r["category"]].append(r)
for k in by_cat:
    # curated first, then live-verified, then alphabetical by host/path
    by_cat[k].sort(key=lambda r: (0 if r["source"] == "CURATED" else 1,
                                  0 if r["live"] else 1,
                                  r["url"].lower()))
print("by category:")
for c in CATS:
    print(f"  {len(by_cat.get(c[1],[])):6d}  {c[2]}")
print(f"  {len(final) - sum(len(by_cat.get(c[1],[])) for c in CATS):6d}  (uncategorized)")

# ------------------------------------------------------------------ data files
os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "by-category"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "antigravity", ".agents", "rules"), exist_ok=True)

core = [r for r in final if r["relevance"] == "core"]

with open(os.path.join(ROOT, "data", "all-links.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(r["url"] for r in final) + "\n")
with open(os.path.join(ROOT, "data", "all-links-core.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(r["url"] for r in core) + "\n")
with open(os.path.join(ROOT, "data", "verified-live-only.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(r["url"] for r in final if r["live"]) + "\n")

with open(os.path.join(ROOT, "data", "links.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["url", "title", "category", "relevance", "live_verified",
                "http_status", "check_result", "harvested_from"])
    for r in sorted(final, key=lambda r: (CAT_ORDER.get(r["category"], 99), r["url"].lower())):
        w.writerow([r["url"], r.get("title", ""), r["category"], r["relevance"],
                    "yes" if r["live"] else "no", r.get("code") or "",
                    r["status"], r.get("source", "")])

with open(os.path.join(ROOT, "data", "links.json"), "w", encoding="utf-8") as f:
    json.dump({
        "generated": "2026-10-29",
        "counts": {"total": len(final), "core": len(core),
                   "live_verified": sum(1 for r in final if r["live"]),
                   "by_category": {k: len(v) for k, v in by_cat.items()}},
        "links": sorted(final, key=lambda r: (CAT_ORDER.get(r["category"], 99), r["url"].lower())),
    }, f, ensure_ascii=False, indent=1)

with open(os.path.join(ROOT, "data", "dropped-dead-links.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["url", "check_result", "http_status"])
    for u, s, c in sorted(dropped_dead): w.writerow([u, s, c or ""])
with open(os.path.join(ROOT, "data", "dropped-unsafe-ssrf-targets.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(set(dropped_unsafe))) + "\n")
with open(os.path.join(ROOT, "data", "dropped-low-value-links.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["url", "reason"])
    for u, s2, _ in sorted(dropped_low): w.writerow([u, s2])

# ------------------------------------------------------------------ per-category md
for num, key, title, desc in CATS:
    rows = by_cat.get(key, [])
    if not rows: continue
    fn = os.path.join(ROOT, "by-category", f"{num}-{key}.md")
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"# {title}\n\n> {desc}\n>\n> **{len(rows)} links.** "
                f"`live_verified` = HTTP 200 confirmed at harvest time; others returned an "
                f"anti-bot 403/429 (usually still valid) or 5xx.\n\n")
        f.write("| # | Resource | URL | Verified | Source |\n|---|---|---|---|---|\n")
        for i, r in enumerate(rows, 1):
            t = (r.get("title") or "").replace("|", "\\|").strip() or "—"
            if len(t) > 90: t = t[:87] + "..."
            src = (r.get("source") or "").replace("|", "\\|")
            f.write(f"| {i} | {t} | <{r['url']}> | {'✓' if r['live'] else '~'} | {src} |\n")
print(f"wrote {len(CATS)} category files")

# NOTE: program ranking lives in programs.py -> data/programs-ranked.csv + programs_summary.json

# ------------------------------------------------------------------ stats file
stats = {
 "generated": "2026-10-29",
 "raw_harvested": 22500,
 "unique_after_dedupe": len(cands),
 "final_kept": len(final),
 "core_relevance": len(core),
 "adjacent_relevance": len(final) - len(core),
 "live_verified_http200": sum(1 for r in final if r["live"]),
 "antibot_but_valid": sum(1 for r in final if r["status"] in ("bot-blocked", "server-error")),
 "dropped_dead": len(dropped_dead),
 "dropped_unsafe_ssrf": len(set(dropped_unsafe)),
 "dropped_low_value": len(dropped_low),
 "by_category": {k: len(v) for k, v in by_cat.items()},
 "bounty_programs_indexed": (json.load(open(os.path.join(HERE,"programs_summary.json"),
                                  encoding="utf-8")).get("total_programs")
                                 if os.path.exists(os.path.join(HERE,"programs_summary.json")) else None),
}
json.dump(stats, open(os.path.join(ROOT, "data", "stats.json"), "w", encoding="utf-8"), indent=1)
print(json.dumps(stats, indent=1)[:900])
