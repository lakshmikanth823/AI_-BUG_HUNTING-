"""
Antigravity AI Bug Bounty Hunter CLI.
Unified operator console for scope validation, lab testing, methodology search,
reconnaissance, and Stage 0-5 triage evaluation.
"""

import os
import sys
import json
import argparse
from pathlib import Path

# Fix Windows console encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from core.scope_guard import ScopeGuard
from core.knowledge_engine import KnowledgeEngine
from core.recon import ReconEngine
from core.reporter import ReportGenerator
from engine.triage_evaluator import TriageEvaluator, CandidateFinding
from lab.lab_controller import run_full_suite as run_lab_benchmark


def cmd_targets(args):
    guard = ScopeGuard()
    print("=" * 75)
    print("TOP RANKED AUTHORIZED BUG BOUNTY PROGRAMS (data/programs-ranked.csv)")
    print("=" * 75)
    count = 0
    for p in guard.programs[:args.limit]:
        payout = p.get("max_payout", "N/A")
        try:
            p_val = float(payout)
            p_str = f"${p_val:,.0f}" if p_val > 0 else "Points / Swag"
        except ValueError:
            p_str = payout or "Unpublished"

        print(f"[{p.get('platform', 'H1'):<9}] {p.get('name', 'Unknown'):<32} Max: {p_str:<14} Assets: {p.get('in_scope_assets', 'N/A')}")
        count += 1
    print("=" * 75)
    print(f"Total programs loaded: {len(guard.programs)} | Showing top {count}")


def cmd_scope(args):
    guard = ScopeGuard()
    info = guard.get_program_info(args.program)
    if not info:
        print(f"[-] Program '{args.program}' not found in data/programs-ranked.csv.")
        return

    print("=" * 70)
    print(f"PROGRAM SCOPE: {info.get('name')}")
    print("=" * 70)
    for k, v in info.items():
        print(f"  {k:<20}: {v}")
    print("=" * 70)


def cmd_search(args):
    ke = KnowledgeEngine()
    if not ke.is_available():
        print("[!] FTS5 database not found at data/knowledge_fts.db. Build it first.")
        return

    print(f"[*] Querying knowledge base for: '{args.query}' (limit {args.limit})...")
    results = ke.query(args.query, repo=args.repo, limit=args.limit)
    if not results:
        print("[-] No matching methodology chunks found.")
        return

    print("=" * 75)
    for r in results:
        print(f"[{r['repo']}] {r['title']} > {r['section']}")
        print(f"Path: {r['filepath']} (License: {r['license']})")
        print(f"Snippet:\n{r['snippet'].strip()}")
        print("-" * 75)


def cmd_recon(args):
    guard = ScopeGuard()
    is_lab = args.lab or any(h in args.url for h in ("localhost", "127.0.0.1"))
    in_scope, scope_msg = guard.verify_target(args.url, args.program, is_lab=is_lab)

    if not in_scope:
        print(f"[!] SCOPE REJECTION: {scope_msg}")
        return

    print(f"[+] Scope verified: {scope_msg}")
    print(f"[*] Discovering attack surface for {args.url}...")
    recon = ReconEngine()
    data = recon.map_surface(args.url, is_lab=is_lab)

    if "error" in data:
        print(f"[-] Error: {data['error']}")
        return

    print("\n" + "=" * 70)
    print(f"RECON SUMMARY: {data['target']} (Status: {data['status']})")
    print("=" * 70)
    print("Technologies Detected:")
    for t in data["technologies"]:
        print(f"  - {t}")

    print("\nSecurity Headers:")
    for k, present in data["security_headers"].items():
        state = "[OK] Present" if present else "[!] Missing"
        print(f"  - {k:<28}: {state}")

    print(f"\nDiscovered Form Actions ({len(data['forms'])}):")
    for f in data["forms"]:
        print(f"  - {f['method']} {f['action']} (Inputs: {[i['name'] for i in f['inputs']]})")

    print(f"\nDiscovered Endpoints ({len(data['endpoints'])}):")
    for ep in data["endpoints"][:10]:
        print(f"  - {ep}")

    print("=" * 70)


def cmd_lab(args):
    print("[*] Launching real lab validation benchmark suite...")
    tpr, fpr, fnr, latency = run_lab_benchmark()
    print(f"\n[+] Validation complete. TPR: {tpr:.1f}% | FPR: {fpr:.1f}% | FNR: {fnr:.1f}% | Latency: {latency:.4f}s")


def main():
    parser = argparse.ArgumentParser(description="Antigravity AI Bug Bounty Hunter CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # targets
    p_targets = subparsers.add_parser("targets", help="List top-ranked bug bounty programs")
    p_targets.add_argument("--limit", type=int, default=15, help="Number of programs to display")

    # scope
    p_scope = subparsers.add_parser("scope", help="Inspect program scope and rules")
    p_scope.add_argument("program", type=str, help="Program name or keyword")

    # search
    p_search = subparsers.add_parser("search", help="Search 51,885 chunks of methodology & playbooks")
    p_search.add_argument("query", type=str, help="Search terms")
    p_search.add_argument("--repo", type=str, default=None, help="Filter by repository name")
    p_search.add_argument("--limit", type=int, default=3, help="Number of results")

    # recon
    p_recon = subparsers.add_parser("recon", help="Run scope-bounded attack surface discovery")
    p_recon.add_argument("url", type=str, help="Target URL")
    p_recon.add_argument("--program", type=str, default="", help="Program name (required for live targets)")
    p_recon.add_argument("--lab", action="store_true", help="Mark target as authorized local lab")

    # lab
    p_lab = subparsers.add_parser("lab", help="Run automated test suite against running lab containers")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmds = {
        "targets": cmd_targets,
        "scope": cmd_scope,
        "search": cmd_search,
        "recon": cmd_recon,
        "lab": cmd_lab,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
