"""
Knowledge Engine for AI Bug Bounty Hunter.
Provides fast FTS5 queries against 51,885 chunks indexed from:
- OWASP WSTG (Testing Guides)
- HackTricks & HackTricks Cloud
- PortSwigger Web Security Academy & Payloads
- PayloadsAllTheThings
- Nuclei Templates
- Bug Bounty Writeups
"""

import re
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ROOT_DIR / "data" / "knowledge_fts.db"


class KnowledgeEngine:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH

    def is_available(self) -> bool:
        return self.db_path.exists()

    def query(self, search_text: str, repo: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """Queries the FTS5 knowledge base for methodology, payloads, or vulnerability details."""
        if not self.is_available():
            return []

        clean_q = re.sub(r"[^\w\s]", " ", search_text).strip()
        if not clean_q:
            return []

        tokens = clean_q.split()
        match_expr = " AND ".join(tokens)

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row

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
            rows = conn.execute(sql, params).fetchall()
            for r in rows:
                content = r["body"]
                snippet = content[:500] + ("..." if len(content) > 500 else "")
                results.append({
                    "id": r["id"],
                    "category": r["category"],
                    "repo": r["repo"],
                    "filepath": r["filepath"],
                    "title": r["title"],
                    "section": r["section"],
                    "snippet": snippet,
                    "license": r["license"],
                    "rank": r["rank"]
                })
            return results
        except Exception:
            # Fallback
            like_sql = """
                SELECT id, category, repo, filepath, title, section, body, license
                FROM chunks
                WHERE body LIKE ? OR title LIKE ?
                LIMIT ?
            """
            like_expr = f"%{tokens[0]}%"
            rows = conn.execute(like_sql, (like_expr, like_expr, limit)).fetchall()
            for r in rows:
                content = r["body"]
                snippet = content[:500] + ("..." if len(content) > 500 else "")
                results.append({
                    "id": r["id"],
                    "category": r["category"],
                    "repo": r["repo"],
                    "filepath": r["filepath"],
                    "title": r["title"],
                    "section": r["section"],
                    "snippet": snippet,
                    "license": r["license"],
                    "rank": 0.0
                })
            return results
        finally:
            conn.close()

    def get_playbook(self, vuln_class: str) -> Dict[str, Any]:
        """Fetches prioritized testing instructions for a specific vulnerability class."""
        wstg_results = self.query(f"{vuln_class} testing guide", repo="owasp-wstg", limit=2)
        hacktricks_results = self.query(f"{vuln_class} bypass", repo="hacktricks", limit=2)
        payload_results = self.query(f"{vuln_class} payloads", repo="PayloadsAllTheThings", limit=2)

        return {
            "vulnerability_class": vuln_class,
            "owasp_guidance": wstg_results,
            "hacktricks_techniques": hacktricks_results,
            "payload_references": payload_results
        }
