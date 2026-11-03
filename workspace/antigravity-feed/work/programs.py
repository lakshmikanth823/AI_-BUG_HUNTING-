#!/usr/bin/env python3
"""Phase 5: data-driven bounty program ranking from arkadiyt/bounty-targets-data."""
import json, urllib.request, urllib.parse, ssl, csv, os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DATA = os.path.join(ROOT, "data")
B = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def get(fn):
    cache_path = os.path.join(HERE, f"cache_{fn}")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    r = urllib.request.Request(B + fn, headers={"User-Agent": "Mozilla/5.0"})
    data = json.loads(urllib.request.urlopen(r, timeout=60, context=ctx).read().decode())
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass
    return data

rows = []
for p in get("bugcrowd_data.json"):
    tg = (p.get("targets") or {}).get("in_scope") or []
    rows.append(dict(platform="Bugcrowd", name=p["name"].strip(), url=p["url"],
        payout=p.get("max_payout"), currency="USD", in_scope=len(tg),
        managed=p.get("managed_by_bugcrowd"), offers=None,
        resp_eff=None, harbor=p.get("safe_harbor"), disclosure=p.get("allows_disclosure"),
        bounty_assets=None, ttr_hours=None, ttb_hours=None, ttr_days=None, ttb_days=None))

for p in get("intigriti_data.json"):
    tg = (p.get("targets") or {}).get("in_scope") or []
    mb = p.get("max_bounty") or {}
    v = mb.get("value") or None
    cur = (mb.get("currency") or "EUR")
    rows.append(dict(platform="Intigriti", name=p["name"].strip(), url=p["url"],
        payout=v, currency=cur, in_scope=len(tg), managed=None,
        offers=(p.get("status") == "open"), resp_eff=None, harbor=None,
        disclosure=None, bounty_assets=None, ttr_hours=None, ttb_hours=None, ttr_days=None, ttb_days=None))

for p in get("yeswehack_data.json"):
    tg = (p.get("targets") or {}).get("in_scope") or []
    rows.append(dict(platform="YesWeHack", name=(p.get("name") or "").strip(),
        url=("https://yeswehack.com/programs?search="
             + urllib.parse.quote((p.get("name") or "").strip())),
        payout=p.get("max_bounty"), currency="USD", in_scope=len(tg),
        managed=p.get("managed"), offers=(not p.get("disabled")), resp_eff=None,
        harbor=None, disclosure=None, bounty_assets=None, ttr_hours=None, ttb_hours=None, ttr_days=None, ttb_days=None))

for p in get("hackerone_data.json"):
    tg = (p.get("targets") or {}).get("in_scope") or []
    elig = [t for t in tg if t.get("eligible_for_bounty")]
    ttr = p.get("average_time_to_report_resolved")
    ttb = p.get("average_time_to_bounty_awarded")
    ttr_h = float(ttr) if ttr is not None else None
    ttb_h = float(ttb) if ttb is not None else None
    ttr_d = round(ttr_h / 24.0, 2) if ttr_h is not None else None
    ttb_d = round(ttb_h / 24.0, 2) if ttb_h is not None else None
    rows.append(dict(platform="HackerOne", name=p["name"].strip(), url=p["url"],
        payout=None, currency="USD", in_scope=len(tg), managed=p.get("managed_program"),
        offers=p.get("offers_bounties"), resp_eff=p.get("response_efficiency_percentage"),
        harbor=None, disclosure=None, bounty_assets=len(elig),
        ttr_hours=ttr_h, ttb_hours=ttb_h, ttr_days=ttr_d, ttb_days=ttb_d))

paid = sorted([r for r in rows if r["payout"]], key=lambda r: -r["payout"])
h1   = sorted([r for r in rows if r["platform"] == "HackerOne" and r["offers"]
               and (r.get("resp_eff") or 0) > 0],
              key=lambda r: (-(r["resp_eff"] or 0), -(r.get("bounty_assets") or 0)))
surf = sorted(rows, key=lambda r: -r["in_scope"])

# Compute paid and responsive intersection
paid_and_responsive = [r for r in rows if r.get("payout") and r.get("resp_eff")]

cols = ["platform", "name", "url", "payout", "currency", "in_scope", "managed",
        "offers", "resp_eff", "harbor", "disclosure", "bounty_assets",
        "ttr_hours", "ttb_hours", "ttr_days", "ttb_days"]

out_csv = os.path.join(DATA, "programs-ranked.csv")
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for r in sorted(rows, key=lambda r: (-(r["payout"] or 0), r["platform"], r["name"])):
        w.writerow({k: r.get(k) for k in cols})

# Copy to root data/
root_csv = os.path.join(ROOT, "..", "data", "programs-ranked.csv")
if os.path.exists(os.path.dirname(root_csv)):
    with open(root_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in sorted(rows, key=lambda r: (-(r["payout"] or 0), r["platform"], r["name"])):
            w.writerow({k: r.get(k) for k in cols})

summary = {
    "total_programs": len(rows),
    "with_published_payout": len(paid),
    "platform_counts": dict(Counter(r["platform"] for r in rows)),
    "paid_and_responsive": len(paid_and_responsive),
    "top_by_payout": [{k: r[k] for k in ("name","url","payout","currency","platform","in_scope")} for r in paid[:100]],
    "top_h1_by_responsiveness": [{k: r.get(k) for k in ("name","url","resp_eff","bounty_assets","in_scope","ttr_hours","ttb_hours","ttr_days","ttb_days")} for r in h1[:100]],
    "largest_attack_surface": [{k: r[k] for k in ("name","url","in_scope","platform","offers")} for r in surf[:100]],
}
json.dump(summary, open(os.path.join(HERE, "programs_summary.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)

print(f"programs={len(rows)}  paid={len(paid)}  platforms={summary['platform_counts']}  paid_and_responsive={len(paid_and_responsive)}")
