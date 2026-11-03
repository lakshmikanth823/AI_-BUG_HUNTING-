#!/usr/bin/env python3
"""Phase 3: concurrent link validation. Usage: validate.py [LIMIT]"""
import json, os, re, sys, ssl, time, socket, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.join(HERE, "candidates.json")
OUT  = os.path.join(HERE, "validated.json")
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 0

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# tree-derived GitHub blob/tree URLs are known-good by construction
SKIP_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/(blob|tree)/")

data = json.load(open(SRC, encoding="utf-8"))
cands = data["candidates"]
if LIMIT: cands = cands[:LIMIT]

def check(rec):
    u = rec["url"]
    if SKIP_RE.match(u):
        rec["status"] = "skipped"; rec["code"] = None; return rec
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(u, method=method, headers=dict(UA))
            if method == "GET": req.add_header("Range", "bytes=0-0")
            with urllib.request.urlopen(req, timeout=9, context=CTX) as r:
                code = r.getcode()
                if code == 206 and method == "GET": code = 200
                rec["status"], rec["code"] = "ok", code
                return rec
        except urllib.error.HTTPError as e:
            c = e.code
            if c in (403, 405, 400, 406, 422, 501, 429, 401) and method == "HEAD":
                continue                     # retry with GET
            if c in (401, 403, 429, 451):
                rec["status"], rec["code"] = "bot-blocked", c; return rec
            if c in (404, 410, 400):
                rec["status"], rec["code"] = "dead", c; return rec
            if 500 <= c < 600:
                rec["status"], rec["code"] = "server-error", c; return rec
            rec["status"], rec["code"] = "http-error", c; return rec
        except (urllib.error.URLError, socket.timeout, socket.gaierror, OSError,
                ssl.SSLError, ValueError) as e:
            msg = str(getattr(e, "reason", e)).lower()
            if method == "HEAD" and ("timed out" in msg or "reset" in msg or "ssl" in msg):
                continue
            if "name or service not known" in msg or "nodename nor servname" in msg \
               or "getaddrinfo" in msg or "name resolution" in msg:
                rec["status"], rec["code"] = "dns-fail", None; return rec
            rec["status"], rec["code"] = "unreachable", None; return rec
        except Exception:
            rec["status"], rec["code"] = "unreachable", None; return rec
    rec["status"], rec["code"] = "unreachable", None
    return rec

t0 = time.time()
done = 0
with ThreadPoolExecutor(max_workers=140) as ex:
    for r in ex.map(check, cands):
        done += 1
        if done % 500 == 0:
            print(f"  {done}/{len(cands)}  {time.time()-t0:.0f}s", flush=True)

json.dump({"candidates": cands, "bounty": data["bounty"]},
          open(OUT, "w", encoding="utf-8"), ensure_ascii=False)

from collections import Counter
c = Counter(r["status"] for r in cands)
print(f"\nchecked {len(cands)} in {time.time()-t0:.0f}s")
for k, v in c.most_common(): print(f"  {v:6d}  {k}")
