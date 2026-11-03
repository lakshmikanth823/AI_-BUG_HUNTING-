"""
CLI and Python interface to query the Master Bug Bounty Feed (4,395+ links).
Allows Antigravity, subagents, and human operators to search by:
- Vulnerability class (SQLi, XSS, SSRF, IDOR, RCE, OAuth, etc.)
- Program / MNC (Google, Uber, Shopify, Apple, Meta, DoD, etc.)
- Category (Methodology, Tools, Labs, CTF Writeups, MNC Disclosures, Books)
- Keyword and minimum bounty reward
"""

import json
import re
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

FEED_PATH = Path(__file__).resolve().parent / "master_bug_bounty_feed.json"


class BugBountyFeed:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or FEED_PATH
        if not self.path.exists():
            raise FileNotFoundError(f"Feed file not found at {self.path}. Run build_feed.py first.")
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.total_count = data.get("total_count", 0)
            self.links = data.get("links", [])

    def search(
        self,
        query: Optional[str] = None,
        vuln: Optional[str] = None,
        program: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        results = []
        q_clean = query.lower().strip() if query else None
        v_clean = vuln.lower().strip() if vuln else None
        p_clean = program.lower().strip() if program else None
        c_clean = category.lower().strip() if category else None

        for item in self.links:
            # Category filter
            if c_clean and c_clean not in item.get("category", "").lower():
                continue

            # Vulnerability filter
            if v_clean:
                item_vuln = item.get("vulnerability", "").lower()
                item_tags = " ".join(item.get("tags", [])).lower()
                if v_clean not in item_vuln and v_clean not in item_tags:
                    continue

            # Program / MNC filter
            if p_clean:
                item_prog = item.get("program", "").lower()
                item_tags = " ".join(item.get("tags", [])).lower()
                if p_clean not in item_prog and p_clean not in item_tags:
                    continue

            # General query filter
            if q_clean:
                haystack = (
                    f"{item.get('title', '')} "
                    f"{item.get('description', '')} "
                    f"{item.get('url', '')} "
                    f"{item.get('author', '')} "
                    f"{' '.join(item.get('tags', []))}"
                ).lower()
                if q_clean not in haystack:
                    continue

            results.append(item)
            if len(results) >= limit:
                break

        return results


def main():
    parser = argparse.ArgumentParser(description="Query Master Bug Bounty Feed (4,395+ Links)")
    parser.add_argument("--query", "-q", type=str, help="Keyword search across all fields")
    parser.add_argument("--vuln", "-v", type=str, help="Filter by vulnerability (e.g. ssrf, rce, idor, sqli, xss)")
    parser.add_argument("--program", "-p", type=str, help="Filter by program/MNC (e.g. google, uber, apple, shopify)")
    parser.add_argument("--category", "-c", type=str, help="Filter by category (Methodology, Tools, Labs, Books, etc.)")
    parser.add_argument("--limit", "-l", type=int, default=10, help="Max results to display (default: 10)")

    args = parser.parse_args()
    feed = BugBountyFeed()

    print(f"[*] Searching through {feed.total_count:,} indexed bug bounty links...")
    matches = feed.search(
        query=args.query,
        vuln=args.vuln,
        program=args.program,
        category=args.category,
        limit=args.limit
    )

    print(f"[+] Found {len(matches)} matching resources (limit={args.limit}):\n")
    for idx, item in enumerate(matches, 1):
        print(f"[{idx}] {item.get('title')}")
        print(f"    URL:      {item.get('url')}")
        print(f"    Category: {item.get('category')}")
        if item.get("program"):
            print(f"    Program:  {item.get('program')} | Vuln: {item.get('vulnerability')} | Reward: {item.get('reward', 'N/A')}")
        if item.get("description"):
            print(f"    Summary:  {item.get('description')}")
        print()


if __name__ == "__main__":
    main()
