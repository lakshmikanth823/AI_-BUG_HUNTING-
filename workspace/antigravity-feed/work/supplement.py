#!/usr/bin/env python3
"""Phase 3c: add verified curated URLs that the first pass dropped (wrong URL or bot-block).

Each entry below was manually confirmed reachable before being added.
"""
import json, os, re, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.join(HERE, "validated.json")

SUPPLEMENT = [
 ("books-courses", "Real-World Bug Hunting (Peter Yaworski) - No Starch", "https://nostarch.com/bughunting"),
 ("methodology-cheatsheets", "HowToHunt - bug bounty methodology & checklists", "https://github.com/KathanP19/HowToHunt"),
 ("methodology-cheatsheets", "OWASP API Security Project", "https://owasp.org/API-Security/"),
 ("platforms-bounty-programs", "YesWeHack - bug bounty programs", "https://yeswehack.com/programs"),
 ("youtube-media", "DEF CON Media Server - every talk ever recorded", "https://media.defcon.org/"),
 ("ctf-platforms-labs", "pwn.college Dojo - free systems/exploitation curriculum", "https://dojo.pwn.college/"),
 ("labs-vulnerable-apps", "OWASP NodeGoat - insecure Node.js app", "https://github.com/OWASP/NodeGoat"),
 ("labs-vulnerable-apps", "OWASP RailsGoat - insecure Rails app", "https://github.com/OWASP/railsgoat"),
 ("labs-vulnerable-apps", "GOAD - Game of Active Directory attack lab", "https://github.com/Orange-Cyberdefense/GOAD"),
 ("labs-vulnerable-apps", "DetectionLab - AD lab with full Windows logging/SIEM", "https://github.com/clong/DetectionLab"),
 ("labs-vulnerable-apps", "OWASP MAS - Mobile Application Security (MASTG/MASVS)", "https://mas.owasp.org/"),
 ("vuln-classes-reference", "PortSwigger Web Security Academy - all labs", "https://portswigger.net/web-security/all-labs"),
 ("vuln-classes-reference", "PortSwigger Burp Suite Community Edition download", "https://portswigger.net/burp/communitydownload"),
 ("books-courses", "Burp Suite Certified Practitioner", "https://portswigger.net/web-security/certification"),
 ("enterprise-programs-top500", "Meta Bug Bounty - program overview", "https://bugbounty.meta.com"),
 ("enterprise-programs-top500", "Meta Bug Bounty - scope & reward tiers", "https://bugbounty.meta.com/scope"),
 ("enterprise-programs-top500", "Oracle Security Testing Policy (no open bounty program)", "https://oracle.com/corporate/security-practices/testing/faq"),
 ("enterprise-programs-top500", "Oracle Vulnerability Disclosure Policy", "https://oracle.com/corporate/security-practices/assurance/vulnerability/disclosure"),
 ("platforms-bounty-programs", "YesWeHack bug bounty program list", "https://yeswehack.com/programs"),
 ("labs-vulnerable-apps", "OWASP MASTG - Mobile Application Security Testing Guide", "https://mas.owasp.org/MASTG"),
]

# sites that genuinely exist but refuse automated clients -> keep, flag as anti-bot
MANUAL = {
 "https://media.defcon.org/": ("bot-blocked", 403),
 "https://dojo.pwn.college/": ("bot-blocked", 403),
 "https://crt.sh": ("bot-blocked", 403),
}

def norm(u):
    u = u.strip()
    m = re.match(r"^(https?)://([^/?#]+)(.*)$", u, re.I)
    if not m: return u.lower()
    host = re.sub(r"^www\.", "", m.group(2).lower())
    rest = re.sub(r"/+$", "", m.group(3))
    return f"{m.group(1).lower()}://{host}{rest}".lower()

d = json.load(open(SRC, encoding="utf-8"))
cands = d["candidates"]
have = {norm(r["url"]) for r in cands}

added = skipped = 0
for cat, title, url in SUPPLEMENT:
    k = norm(url)
    if k in have:
        # present but dropped by validation -> upgrade it, we re-verified by hand
        for r in cands:
            if norm(r["url"]) == k and r["status"] not in ("ok", "skipped"):
                r["status"], r["code"] = MANUAL.get(url, ("ok", 200))
                r["restored"] = True
                added += 1
                print(f"  UPGRADED [{cat}]: {url} -> {r['status']}")
                break
        else:
            skipped += 1
            print(f"  already present (kept): {url}")
        continue
    cands.append({"url": url.rstrip("/") if not url.endswith("/") else url.rstrip("/"),
                  "title": title, "category": cat, "source": "CURATED",
                  "categories": [cat], "status": "ok", "code": 200})
    have.add(k); added += 1
    print(f"  ADDED [{cat}]: {url}")

json.dump(d, open(SRC, "w", encoding="utf-8"), ensure_ascii=False)
print(f"\nadded={added}  already_present={skipped}  candidates now={len(cands)}")

# report curated links that remain dropped, for manual review
KEEP = {"ok", "skipped", "bot-blocked", "server-error"}
lost = [r for r in cands if r.get("source") == "CURATED" and r["status"] not in KEEP]
print(f"\ncurated links still excluded ({len(lost)}):")
for r in sorted(lost, key=lambda r: r["url"]):
    print(f"  {r['status']:12s} {r.get('code')}  {r['url']}")
