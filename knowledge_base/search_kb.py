"""
Fast, context-safe search CLI for Antigravity Knowledge Base.
Allows searching across 15,000+ files by category, file extension, and keyword,
returning compact matches with file paths and snippet line numbers.
"""

import os
import sys
import re
import argparse
from pathlib import Path
from typing import List, Dict, Any

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

KB_DIR = Path(__file__).resolve().parent


def search_kb(query: str, category: str = None, ext: str = None, limit: int = 10) -> List[Dict[str, Any]]:
    query_lower = query.lower().strip()
    matches = []

    # Use regex word boundary for short queries (<= 5 chars like IDOR, SSRF, XSS, RCE, SQLi)
    if len(query_lower) <= 5 and query_lower.isalnum():
        pattern = re.compile(rf"\b{re.escape(query_lower)}\b", re.IGNORECASE)
    else:
        pattern = re.compile(re.escape(query_lower), re.IGNORECASE)

    search_root = KB_DIR / category if category else KB_DIR
    if not search_root.exists():
        search_root = KB_DIR

    for root, dirs, files in os.walk(search_root):
        if ".git" in dirs:
            dirs.remove(".git")

        for fname in files:
            if ext and not fname.endswith(ext):
                continue
            if not (fname.endswith(".md") or fname.endswith(".markdown") or fname.endswith(".yaml") or fname.endswith(".yml")):
                continue

            fpath = Path(root) / fname
            rel_path = fpath.relative_to(KB_DIR)

            # Check if query in filename
            file_matched = bool(pattern.search(fname))

            # Search in file content line-by-line
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    matched_lines = []
                    for idx, line in enumerate(f, 1):
                        if pattern.search(line):
                            matched_lines.append((idx, line.strip()))
                            if len(matched_lines) >= 3:
                                break

                    if file_matched or matched_lines:
                        matches.append({
                            "file": str(rel_path).replace("\\", "/"),
                            "full_path": str(fpath),
                            "matched_in_name": file_matched,
                            "snippets": matched_lines
                        })
                        if len(matches) >= limit:
                            return matches
            except Exception:
                continue

    return matches


def main():
    parser = argparse.ArgumentParser(description="Antigravity Knowledge Base Context-Safe Search Tool")
    parser.add_argument("--query", "-q", required=True, help="Search keyword (e.g. 'SSRF', 'IDOR', 'JWT', '169.254')")
    parser.add_argument("--category", "-c", choices=["methodologies", "payloads", "writeups", "templates", "ctf_archives"], help="Filter by KB subcategory")
    parser.add_argument("--ext", "-e", choices=[".md", ".yaml"], help="Filter by file extension")
    parser.add_argument("--limit", "-l", type=int, default=10, help="Max results to return (default: 10)")

    args = parser.parse_args()

    print(f"[*] Searching for '{args.query}' in knowledge_base (category={args.category or 'all'})...")
    results = search_kb(args.query, category=args.category, ext=args.ext, limit=args.limit)

    print(f"[+] Found {len(results)} matches (limit={args.limit}):\n")
    for idx, r in enumerate(results, 1):
        print(f"[{idx}] {r['file']}")
        if r['matched_in_name']:
            print("    (Matched in filename)")
        for line_no, snippet in r["snippets"]:
            print(f"    Line {line_no:4d}: {snippet[:120]}")
        print()


if __name__ == "__main__":
    main()
