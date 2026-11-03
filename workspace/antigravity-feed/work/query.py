#!/usr/bin/env python3
"""Grounded Retrieval Query Tool for Bounty Programs.
Enforces the three grounding rules:
1. NO DATA is a complete answer (HackerOne publishes zero payout figures).
2. NO MATCH means the program is not in the dataset.
3. Every figure reported by the agent must come from a query run in the same turn.
"""

import os
import sys
import csv
import argparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
CSV_PATH = os.path.join(ROOT, "data", "programs-ranked.csv")


def load_programs():
    if not os.path.exists(CSV_PATH):
        print(f"[!] Error: {CSV_PATH} not found.")
        sys.exit(1)
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cmd_find(args):
    progs = load_programs()
    q = args.name.lower().strip()
    matches = [p for p in progs if q in p["name"].lower()]

    if not matches:
        print(f"NO MATCH: Program '{args.name}' was not found in programs-ranked.csv (946 total programs).")
        return

    for p in matches[:5]:
        print("=" * 60)
        print(f"PROGRAM: {p['name']} [{p['platform']}]")
        print("=" * 60)
        print(f"URL:                  {p['url']}")
        payout = p.get('payout')
        payout_str = f"{float(payout):,.0f} {p.get('currency', 'USD')}" if payout else "NO DATA (Platform does not publish payout)"
        print(f"Max Published Bounty: {payout_str}")
        print(f"In-Scope Assets:      {p.get('in_scope') or 'N/A'}")
        print(f"Offers Bounties:      {p.get('offers') or 'N/A'}")
        print(f"Response Efficiency:  {p.get('resp_eff') + '%' if p.get('resp_eff') else 'NO DATA'}")
        print(f"Bounty-Eligible Assets: {p.get('bounty_assets') or 'NO DATA'}")
        
        ttr_h = p.get('ttr_hours')
        ttr_d = p.get('ttr_days')
        if ttr_h and float(ttr_h) > 0:
            print(f"Time to Resolve (TTR): {ttr_h} hours ({ttr_d} days)")
        else:
            print(f"Time to Resolve (TTR): NO DATA")

        ttb_h = p.get('ttb_hours')
        ttb_d = p.get('ttb_days')
        if ttb_h and float(ttb_h) > 0:
            print(f"Time to Bounty (TTB):  {ttb_h} hours ({ttb_d} days)")
        else:
            print(f"Time to Bounty (TTB):  NO DATA")
        print("=" * 60)


def cmd_top(args):
    progs = load_programs()
    by = args.by.lower()

    if by == "payout":
        valid = [p for p in progs if p.get("payout")]
        valid.sort(key=lambda x: float(x["payout"]), reverse=True)
        print("=" * 70)
        print(f"TOP PROGRAMS BY PUBLISHED MAX PAYOUT (Limit {args.limit})")
        print("=" * 70)
        for i, p in enumerate(valid[:args.limit], 1):
            val = float(p["payout"])
            print(f"{i:>2}. {p['name'][:36]:<38} {val:>10,.0f} {p.get('currency', 'USD'):<4} [{p['platform']:9s}]")
        print("=" * 70)
        print("Note: HackerOne does not expose payout figures in this dataset.")

    elif by == "responsive":
        valid = [p for p in progs if p.get("resp_eff")]
        valid.sort(key=lambda x: (float(x["resp_eff"]), float(x.get("bounty_assets") or 0)), reverse=True)
        print("=" * 75)
        print(f"TOP PROGRAMS BY RESPONSE EFFICIENCY (HackerOne) (Limit {args.limit})")
        print("=" * 75)
        for i, p in enumerate(valid[:args.limit], 1):
            ttr = f"{p.get('ttr_days')}d ({p.get('ttr_hours')}h)" if p.get("ttr_hours") else "NO DATA"
            print(f"{i:>2}. {p['name'][:32]:<34} Eff: {p['resp_eff']:>3s}% | Assets: {p.get('bounty_assets') or '0':>2s} | TTR: {ttr:<14} | Payout: NO DATA")
        print("=" * 75)
        print("Note: All 438 responsive programs are from HackerOne; payout figures are NO DATA.")

    elif by == "surface":
        valid = [p for p in progs if p.get("in_scope")]
        valid.sort(key=lambda x: int(x["in_scope"]), reverse=True)
        print("=" * 70)
        print(f"TOP PROGRAMS BY IN-SCOPE ATTACK SURFACE (Limit {args.limit})")
        print("=" * 70)
        for i, p in enumerate(valid[:args.limit], 1):
            payout = f"{float(p['payout']):,.0f} {p['currency']}" if p.get("payout") else "NO DATA"
            print(f"{i:>2}. {p['name'][:34]:<36} Assets: {int(p['in_scope']):>5,d} [{p['platform']:9s}] Payout: {payout}")
        print("=" * 70)


def cmd_fastest(args):
    progs = load_programs()
    metric = args.metric.lower()
    field = "ttb_hours" if metric == "ttb" else "ttr_hours"
    label = "Time to Bounty" if metric == "ttb" else "Time to Resolve"

    valid = [p for p in progs if p.get(field) and float(p[field]) > 0]
    valid.sort(key=lambda x: float(x[field]))

    print("=" * 70)
    print(f"FASTEST PROGRAMS BY {label.upper()} (Limit {args.limit})")
    print("=" * 70)
    for i, p in enumerate(valid[:args.limit], 1):
        h = float(p[field])
        d = round(h / 24.0, 1)
        print(f"{i:>2}. {p['name'][:36]:<38} {h:>6.1f} hrs ({d:>4.1f} days) [{p['platform']:9s}] Payout: NO DATA")
    print("=" * 70)
    print("Note: Upstream metric is in HOURS. Payout data for HackerOne programs is NO DATA.")


def cmd_stats(args):
    progs = load_programs()
    total = len(progs)
    p_payout = [p for p in progs if p.get("payout")]
    p_h1 = [p for p in progs if p.get("platform") == "HackerOne"]
    p_resp = [p for p in progs if p.get("resp_eff")]
    p_both = [p for p in progs if p.get("payout") and p.get("resp_eff")]

    print("=" * 65)
    print("BOUNTY TARGETS DATASET CAPABILITY & LIMITATIONS")
    print("=" * 65)
    print(f"Total Programs:               {total}")
    print(f"Programs with Published Payout: {len(p_payout)} (Bugcrowd, Intigriti, YesWeHack)")
    print(f"HackerOne Programs:           {len(p_h1)} (Payout data is 0 / UNPUBLISHED)")
    print(f"Programs with Responsiveness: {len(p_resp)} (Exclusively HackerOne)")
    print(f"Programs with BOTH:           {len(p_both)} (DISJOINT SETS: INTERSECTION IS ZERO)")
    print("=" * 65)
    print("HARD RULE: 'Pays well AND triages fast' CANNOT be ranked together.")
    print("Always present payout and responsiveness as two separate shortlists.")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="Grounded Query Tool for Bug Bounty Programs")
    sub = parser.add_subparsers(dest="cmd")

    p_find = sub.add_parser("find")
    p_find.add_argument("name", type=str, help="Program name or keyword")

    p_top = sub.add_parser("top")
    p_top.add_argument("--by", choices=["payout", "responsive", "surface"], default="payout")
    p_top.add_argument("--limit", type=int, default=10)

    p_fast = sub.add_parser("fastest")
    p_fast.add_argument("--metric", choices=["ttb", "ttr"], default="ttb")
    p_fast.add_argument("--limit", type=int, default=10)

    sub.add_parser("stats")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    cmds = {
        "find": cmd_find,
        "top": cmd_top,
        "fastest": cmd_fastest,
        "stats": cmd_stats
    }
    cmds[args.cmd](args)


if __name__ == "__main__":
    main()
