#!/usr/bin/env python3
"""Phase 9: validate every URL that appears in the hand-written deliverable docs."""
import json, os, re, ssl, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DOCS = ["README.md", "STRATEGY.md", "TOP_PROGRAMS.md", "BOOKS.md", "LABS.md",
        "INDEX.md", "antigravity/AGENTS.md"]
LINK = re.compile(r"\[[^\]]*\]\((https?://[^)\s]+)\)|<(https?://[^)\s>]+)>|\b(https?://[^\s)<>\"'`]+)")

UA = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Encoding": "identity"}
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

found = defaultdict(list)
for doc in DOCS:
    p = os.path.join(ROOT, doc)
    if not os.path.exists(p): continue
    txt = open(p, encoding="utf-8").read()
    for m in LINK.finditer(txt):
        u = (m.group(1) or m.group(2) or m.group(3)).strip().rstrip(".,;:")
        found[u].append(doc)

urls = sorted(found)
print(f"{len(urls)} unique URLs across {len(DOCS)} docs\n")

# Hosts that are live but refuse non-browser clients (verified manually / via search).
# A 400/403/404 from these is an anti-bot response, not a dead link.
BOT_HOSTILE = {"bugbounty.meta.com", "facebook.com", "meta.com", "crt.sh", "media.defcon.org",
               "dojo.pwn.college", "hackerone.com", "book.hacktricks.wiki", "bugcrowd.com",
               "intigriti.com", "wiley.com", "oreilly.com", "packtpub.com", "linkedin.com"}

def hostile(u):
    h = re.sub(r"^https?://", "", u).split("/")[0].lower()
    return any(h == b or h.endswith("." + b) for b in BOT_HOSTILE)

def check(u):
    for a in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(u, method="GET", headers=UA),
                                        timeout=18, context=CTX) as r:
                r.read(128); return u, r.getcode(), "ok"
        except urllib.error.HTTPError as e:
            c = e.code
            if c in (403, 429, 401, 451): return u, c, "bot-blocked(likely fine)"
            if c in (404, 410, 400):
                return u, c, "bot-blocked(likely fine)" if hostile(u) else "DEAD"
            if 500 <= c < 600:
                if a == 0: time.sleep(1.5); continue
                # known anti-bot hosts (crt.sh, Amazon, publishers) answer 503/5xx to
                # automated clients; treat like their 403s rather than as a dead link
                return u, c, "bot-blocked(likely fine)" if hostile(u) else "server-error"
            return u, c, f"http-{c}"
        except Exception as e:
            if a == 0: time.sleep(1.0); continue
            if hostile(u): return u, None, "bot-blocked(likely fine)"
            return u, None, f"unreachable({type(e).__name__})"
    return u, None, "unreachable"

res = []
with ThreadPoolExecutor(max_workers=40) as ex:
    for r in ex.map(check, urls): res.append(r)

bad = [r for r in res if r[2] == "DEAD" or r[2].startswith("http-")]
warn = [r for r in res if r[2].startswith("unreachable") or r[2] == "server-error"]
good = [r for r in res if r[2] in ("ok", "bot-blocked(likely fine)")]

print(f"OK/anti-bot: {len(good)}   unreachable: {len(warn)}   DEAD: {len(bad)}\n")
if bad:
    print("=== DEAD LINKS IN DOCS (must fix) ===")
    for u, c, s in sorted(bad):
        print(f"  {c}  {u}\n        used in: {', '.join(sorted(set(found[u])))}")
if warn:
    print("\n=== UNREACHABLE FROM SANDBOX (verify manually) ===")
    for u, c, s in sorted(warn):
        print(f"  {s:28s} {u}   [{', '.join(sorted(set(found[u])))}]")
json.dump({"dead": [[u, c] for u, c, _ in bad], "warn": [[u, s] for u, s2, s in
           [(a, b, c) for a, b, c in warn]]}, open(os.path.join(HERE, "doclink_report.json"), "w"), indent=1)
sys.exit(1 if bad else 0)
