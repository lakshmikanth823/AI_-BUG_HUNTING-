"""
Content Indexer & Fast Retrieval Engine for Antigravity Bug Bounty Agent.
Builds an SQLite FTS5 (Full-Text Search) index over the local knowledge_base/
markdown files, chunking by semantic headers.
Provides instant, context-safe retrieval without reading entire repositories into memory.
"""

import os
import re
import sys
import sqlite3
import argparse
import time
from pathlib import Path
from typing import List, Dict, Any, Generator

# UTF-8 stdout
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent.parent
KB_DIR = BASE_DIR / "knowledge_base"
DB_PATH = BASE_DIR / "data" / "knowledge_fts.db"

# License registry for provenance
LICENSES = {
    "owasp-wstg": "CC-BY-SA-4.0",
    "hacktricks": "CC-BY-NC-SA-4.0",
    "hacktricks-cloud": "CC-BY-NC-SA-4.0",
    "tbhm": "MIT",
    "howtohunt": "MIT",
    "bugbounty-cheatsheet": "MIT",
    "api-security-checklist": "MIT",
    "PayloadsAllTheThings": "MIT",
    "can-i-take-over-xyz": "MIT",
    "Awesome-Bugbounty-Writeups": "MIT",
    "bug-bounty-reference": "MIT",
    "hackerone-reports": "MIT",
    "awesome-bug-bounty-2026": "MIT",
    "nuclei-templates": "MIT",
    "ctf-wiki": "CC-BY-NC-SA-4.0"
}


def get_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    return con


def init_db(con: sqlite3.Connection):
    con.execute("DROP TABLE IF EXISTS chunks")
    con.execute("DROP TABLE IF EXISTS chunks_fts")
    con.execute("""
        CREATE TABLE chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            repo TEXT,
            filepath TEXT,
            title TEXT,
            section TEXT,
            body TEXT,
            license TEXT,
            bytes INTEGER
        )
    """)
    con.execute("""
        CREATE VIRTUAL TABLE chunks_fts USING fts5(
            title,
            section,
            body,
            content='chunks',
            content_rowid='id'
        )
    """)
    con.commit()


def chunk_markdown_file(fpath: Path, rel_path: Path) -> Generator[Dict[str, Any], None, None]:
    parts = rel_path.parts
    category = parts[0] if len(parts) > 1 else "root"
    repo = parts[1] if len(parts) > 2 else parts[0]
    license_type = LICENSES.get(repo, "Open-Source/Community")

    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return

    doc_title = fpath.stem.replace("-", " ").replace("_", " ").title()
    current_section = "Overview"
    current_lines = []

    header_re = re.compile(r"^(#{1,3})\s+(.+)$")

    for line in lines:
        m = header_re.match(line.strip())
        if m:
            if current_lines:
                chunk_body = "".join(current_lines).strip()
                if len(chunk_body) > 40:  # skip trivial empty blocks
                    yield {
                        "category": category,
                        "repo": repo,
                        "filepath": str(rel_path).replace("\\", "/"),
                        "title": doc_title,
                        "section": current_section,
                        "body": chunk_body[:3000],  # cap maximum chunk size
                        "license": license_type,
                        "bytes": len(chunk_body.encode("utf-8"))
                    }
                current_lines = []
            current_section = m.group(2).strip()
        else:
            current_lines.append(line)

    if current_lines:
        chunk_body = "".join(current_lines).strip()
        if len(chunk_body) > 40:
            yield {
                "category": category,
                "repo": repo,
                "filepath": str(rel_path).replace("\\", "/"),
                "title": doc_title,
                "section": current_section,
                "body": chunk_body[:3000],
                "license": license_type,
                "bytes": len(chunk_body.encode("utf-8"))
            }


def build_index():
    if not KB_DIR.exists():
        print(f"[!] Knowledge base directory not found at {KB_DIR}")
        return

    print("=" * 65)
    print("Building Full-Text Search Index (FTS5) for Local Knowledge Base")
    print("=" * 65)

    con = get_db()
    init_db(con)

    total_chunks = 0
    total_files = 0
    start_t = time.time()

    cursor = con.cursor()
    cursor.execute("BEGIN TRANSACTION")

    for root, dirs, files in os.walk(KB_DIR):
        if ".git" in dirs:
            dirs.remove(".git")

        for f in files:
            if f.endswith((".md", ".markdown")):
                total_files += 1
                fpath = Path(root) / f
                rel_path = fpath.relative_to(KB_DIR)

                for chunk in chunk_markdown_file(fpath, rel_path):
                    total_chunks += 1
                    cursor.execute("""
                        INSERT INTO chunks (category, repo, filepath, title, section, body, license, bytes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        chunk["category"],
                        chunk["repo"],
                        chunk["filepath"],
                        chunk["title"],
                        chunk["section"],
                        chunk["body"],
                        chunk["license"],
                        chunk["bytes"]
                    ))
                    rowid = cursor.lastrowid
                    cursor.execute("""
                        INSERT INTO chunks_fts (rowid, title, section, body)
                        VALUES (?, ?, ?, ?)
                    """, (rowid, chunk["title"], chunk["section"], chunk["body"]))

                    if total_chunks % 5000 == 0:
                        print(f"  [*] Indexed {total_chunks:,} chunks ({total_files:,} files)...")

    con.commit()
    elapsed = time.time() - start_t
    db_size_mb = DB_PATH.stat().st_size / (1024 * 1024)

    print("=" * 65)
    print("FTS5 Index Build Complete!")
    print(f"  Files Indexed:     {total_files:,}")
    print(f"  Chunks Created:    {total_chunks:,}")
    print(f"  Database Size:     {db_size_mb:.2f} MB ({DB_PATH.name})")
    print(f"  Elapsed Time:      {elapsed:.2f} seconds")
    print("=" * 65)


def search_index(query: str, repo: str = None, limit: int = 5) -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        print("[!] Index does not exist. Run with --build first.")
        return []

    con = get_db()
    # Format FTS query
    clean_q = re.sub(r"[^\w\s]", " ", query).strip()
    if not clean_q:
        return []

    tokens = clean_q.split()
    # Require all words or phrase match
    match_expr = " AND ".join(tokens)

    sql = """
        SELECT c.id, c.category, c.repo, c.filepath, c.title, c.section, c.body, c.license,
               bm25(chunks_fts) as rank
        FROM chunks_fts
        JOIN chunks c ON c.id = chunks_fts.rowid
        WHERE chunks_fts MATCH ?
    """
    params = [match_expr]

    if repo:
        sql += " AND c.repo = ?"
        params.append(repo)

    sql += " ORDER BY rank LIMIT ?"
    params.append(limit)

    results = []
    try:
        rows = con.execute(sql, params).fetchall()
        for r in rows:
            results.append(dict(r))
    except sqlite3.OperationalError as e:
        # Fallback to simple LIKE if syntax error in FTS token
        fallback_sql = """
            SELECT id, category, repo, filepath, title, section, body, license
            FROM chunks
            WHERE body LIKE ? OR title LIKE ? OR section LIKE ?
            LIMIT ?
        """
        like_expr = f"%{tokens[0]}%"
        rows = con.execute(fallback_sql, (like_expr, like_expr, like_expr, limit)).fetchall()
        for r in rows:
            results.append(dict(r))

    return results


def main():
    parser = argparse.ArgumentParser(description="Antigravity Knowledge Store Indexer & Search")
    parser.add_argument("--build", action="store_true", help="Rebuild the SQLite FTS5 index from knowledge_base/")
    parser.add_argument("--query", "-q", type=str, help="Search query (e.g. 'IDOR authorization check', 'SSRF 169.254')")
    parser.add_argument("--repo", "-r", type=str, help="Filter by repository name (e.g. 'owasp-wstg', 'hacktricks')")
    parser.add_argument("--limit", "-l", type=int, default=3, help="Max results to return (default: 3)")

    args = parser.parse_args()

    if args.build:
        build_index()
    elif args.query:
        hits = search_index(args.query, repo=args.repo, limit=args.limit)
        print(f"\n[+] Found {len(hits)} matching knowledge chunks for '{args.query}':\n")
        for i, hit in enumerate(hits, 1):
            print(f"[{i}] {hit['title']} -> {hit['section']}")
            print(f"    Source:  {hit['repo']} ({hit['license']}) | File: {hit['filepath']}")
            print(f"    Content Preview:")
            preview = hit['body'][:400].replace("\n", " ").strip()
            print(f"    \"{preview}...\"\n")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
