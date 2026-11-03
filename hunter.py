"""
Antigravity AI Bug Bounty Hunter CLI.
Unified operator console for scope validation, lab testing, methodology search,
reconnaissance, and Stage 0-5 triage evaluation.
"""

import os
import sys
import json
import argparse
import urllib.parse
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
        payout = p.get("payout") or p.get("max_payout", "N/A")
        try:
            p_val = float(payout)
            p_str = f"${p_val:,.0f}" if p_val > 0 else "Points / Swag"
        except ValueError:
            p_str = payout or "Unpublished"

        bounty_assets = p.get("bounty_assets") or p.get("in_scope") or p.get("in_scope_assets", "N/A")
        print(f"[{p.get('platform', 'H1'):<9}] {p.get('name', 'Unknown'):<36} Max: {p_str:<14} Assets: {bounty_assets}")
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


def cmd_triage(args):
    evaluator = TriageEvaluator()

    if args.interactive:
        print("=" * 70)
        print("INTERACTIVE TRIAGE GATE EVALUATION")
        print("=" * 70)
        title = input("Finding Title [Candidate Security Finding]: ").strip() or "Candidate Security Finding"
        program = input("Program Name [local_lab]: ").strip() or "local_lab"
        target_host = input("Target Host [127.0.0.1]: ").strip() or "127.0.0.1"
        method = input("HTTP Method [GET]: ").strip().upper() or "GET"
        url = input("Request URL [http://127.0.0.1:3000/rest/basket/1]: ").strip() or "http://127.0.0.1:3000/rest/basket/1"
        status_in = input("Response Status Code [200]: ").strip()
        status = int(status_in) if status_in.isdigit() else 200
        body = input("Response Body Excerpt: ").strip()
        marker = input("Victim Marker (planted cross-tenant string) []: ").strip()
        is_lab = input("Is Local Lab? (y/N): ").strip().lower() in ("y", "yes")
    else:
        title = args.title
        program = args.program
        url = args.url
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        target_host = args.host or parsed.netloc.split(":")[0] or "127.0.0.1"
        method = args.method.upper()
        status = args.status
        body = args.body
        marker = args.victim_marker
        is_lab = args.lab or any(h in url for h in ("localhost", "127.0.0.1"))

    finding = CandidateFinding(
        title=title,
        program=program,
        target_host=target_host,
        request_method=method,
        request_url=url,
        response_status=status,
        response_body=body,
        victim_marker=marker,
        is_lab=is_lab,
    )

    verdict = evaluator.evaluate(finding)
    print("\n" + "=" * 70)
    print("TRIAGE GATE OUTPUT CONTRACT")
    print("=" * 70)
    print(evaluator.format_output_contract(verdict))
    print("=" * 70)


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

    # triage
    p_triage = subparsers.add_parser("triage", help="Evaluate a candidate finding against the Stage 0-5 Triage Gate")
    p_triage.add_argument("--title", type=str, default="Candidate Security Finding", help="Finding title")
    p_triage.add_argument("--program", type=str, default="local_lab", help="Program name (default: local_lab)")
    p_triage.add_argument("--host", type=str, default="", help="Target host (derived from --url if omitted)")
    p_triage.add_argument("--method", type=str, default="GET", help="HTTP request method (GET, POST, etc.)")
    p_triage.add_argument("--url", type=str, default="http://127.0.0.1:3000/rest/basket/1", help="Full request URL")
    p_triage.add_argument("--status", type=int, default=200, help="HTTP response status code")
    p_triage.add_argument("--body", type=str, default="", help="HTTP response body snippet")
    p_triage.add_argument("--victim-marker", type=str, default="", help="Planted cross-tenant marker value")
    p_triage.add_argument("--lab", action="store_true", help="Flag as authorized local lab asset")
    p_triage.add_argument("--interactive", "-i", action="store_true", help="Prompt interactively for finding details")

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
        "triage": cmd_triage,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
