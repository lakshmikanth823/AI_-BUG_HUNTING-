#!/usr/bin/env python3
"""Regenerate work/final_numbers.json from the authoritative artefacts.

Two distinct scopes are kept separate on purpose:
  * v*  = the validation pass over ALL unique URLs (validated.json)
  * bare keys = the FINAL KEPT corpus (data/links.json, data/stats.json)
Mixing them is what made the README verification table fail to sum.
"""
import json, os, glob, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))

V   = json.load(open(os.path.join(HERE, "validated.json"), encoding="utf-8"))["candidates"]
S   = json.load(open(os.path.join(ROOT, "data", "stats.json"), encoding="utf-8"))
L   = json.load(open(os.path.join(ROOT, "data", "links.json"), encoding="utf-8"))["links"]
P   = json.load(open(os.path.join(HERE, "programs_summary.json"), encoding="utf-8"))
rules = glob.glob(os.path.join(ROOT, "antigravity/.agents/rules/*.md"))

st = collections.Counter(r.get("status", "?") for r in V)
KEEP = ("ok", "skipped", "bot-blocked", "server-error")

N = {
    # ---- final kept corpus
    "total":  S["final_kept"],
    "core":   S["core_relevance"],
    "adj":    S["adjacent_relevance"],
    "live":   S["live_verified_http200"],
    "antibot":S["antibot_but_valid"],
    "dead":   S["dropped_dead"],
    "unsafe": S["dropped_unsafe_ssrf"],
    "low":    S["dropped_low_value"],
    "raw":    S["raw_harvested"],
    "uniq":   S["unique_after_dedupe"],
    "rules":  len(rules),
    "maxb":   max(os.path.getsize(f) for f in rules),
    "programs": S["bounty_programs_indexed"],
    "paid":   P["with_published_payout"],
    "platforms": P["platform_counts"],
    "cats":   dict(collections.Counter(r["category"] for r in L)),
    # ---- validation pass over ALL uniques (what the README table describes)
    "vok":      st["ok"],
    "vskip":    st["skipped"],
    "vblock":   st["bot-blocked"],
    "vserr":    st["server-error"],
    "vdead":    st["dead"],
    "vdns":     st["dns-fail"],
    "vunreach": st["unreachable"],
    "vhttp":    st["http-error"],
}
N["vkept"] = N["vok"] + N["vskip"] + N["vblock"] + N["vserr"]
N["vfail"] = N["vdead"] + N["vdns"] + N["vunreach"] + N["vhttp"]

# ---- self-consistency assertions: fail loudly rather than emit a wrong doc
assert N["vkept"] + N["vfail"] == N["uniq"], "validation buckets must sum to uniques"
assert N["total"] + N["dead"] + N["unsafe"] + N["low"] == N["uniq"], "drop buckets must sum to uniques"
assert N["core"] + N["adj"] == N["total"], "relevance tags must sum to total"
assert sum(N["cats"].values()) == N["total"], "category counts must sum to total"
assert N["vfail"] - N["dead"] >= 0, "dead-dropped cannot exceed validation failures"
assert N["paid"] > 0 and N["programs"] == P["total_programs"], "program summary mismatch"
assert sum(P["platform_counts"].values()) <= N["programs"], "platform counts exceed program total"
N["overlap"] = N["vfail"] - N["dead"]   # failures already caught by unsafe/low-value

json.dump(N, open(os.path.join(HERE, "final_numbers.json"), "w", encoding="utf-8"),
          indent=2, ensure_ascii=False)
print(f"final_numbers.json regenerated  ({len(N)} keys)")
for k in ("uniq","vok","vskip","vblock","vserr","vkept","vfail","dead","unsafe","low","overlap","total","core","adj","live","antibot","rules","maxb","programs","paid"):
    print(f"  {k:9s} {N[k]:>7,}")
