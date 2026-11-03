#!/usr/bin/env python3
"""Phase 3b: re-validate links the first pass marked dead/unreachable.

The first pass sent `Range: bytes=0-0`, which several CDNs (notably PortSwigger)
answer with 404. This pass uses a plain browser-like GET with no Range header and
restores anything that actually resolves.
"""
import json, gzip, os, ssl, sys, time, socket, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.join(HERE, "validated.json")
BAD  = {"dead", "unreachable", "dns-fail", "http-error", "server-error"}
UA = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                "image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "identity",
      "Upgrade-Insecure-Requests": "1",
      "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
      "Connection": "close"}
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

d = json.load(open(SRC, encoding="utf-8"))
cands = d["candidates"]
todo = [r for r in cands if r["status"] in BAD]
print(f"re-validating {len(todo)} previously-failed links (plain GET, no Range)")

def check(rec):
    u = rec["url"]
    for attempt in range(2):
        try:
            req = urllib.request.Request(u, method="GET", headers=UA)
            with urllib.request.urlopen(req, timeout=18, context=CTX) as r:
                code = r.getcode()
                r.read(256)
                if code and code < 400:
                    rec["status"], rec["code"] = "ok", code
                    rec["restored"] = True
                    return rec
        except urllib.error.HTTPError as e:
            c = e.code
            if c in (401, 403, 429, 451):
                rec["status"], rec["code"] = "bot-blocked", c; rec["restored"] = True; return rec
            if c in (404, 410):
                rec["status"], rec["code"] = "dead", c; return rec
            if 500 <= c < 600:
                if attempt == 0: time.sleep(1.5); continue
                rec["status"], rec["code"] = "server-error", c; return rec
            rec["status"], rec["code"] = "http-error", c; return rec
        except Exception:
            if attempt == 0: time.sleep(1.0); continue
    return rec

t0 = time.time(); n = 0
with ThreadPoolExecutor(max_workers=60) as ex:
    for r in ex.map(check, todo):
        n += 1
        if n % 200 == 0: print(f"  {n}/{len(todo)}  {time.time()-t0:.0f}s", flush=True)

restored = [r for r in todo if r.get("restored")]
json.dump(d, open(SRC, "w", encoding="utf-8"), ensure_ascii=False)

from collections import Counter
print(f"\nrestored {len(restored)} of {len(todo)} in {time.time()-t0:.0f}s")
print("  restored by status:", dict(Counter(r["status"] for r in restored)))
hosts = Counter(r["url"].split("/")[2] for r in restored)
print("  top restored hosts:")
for h, k in hosts.most_common(15): print(f"    {k:4d}  {h}")
print("\n  still dead:", sum(1 for r in cands if r["status"] == "dead"))
print("  still unreachable:", sum(1 for r in cands if r["status"] == "unreachable"))
print("  dns-fail:", sum(1 for r in cands if r["status"] == "dns-fail"))
