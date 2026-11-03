"""
Knowledge Base Engine for AI Bug Bounty Research Agent.
Implements Phase 2 of PRD:
- Query methodology docs and checklists (PortSwigger, OWASP Testing Guide, public writeups).
- Evaluates candidate findings against the 7-Question Gate and Kill Criteria.
- Cites relevant checklist items for a given bug class on request.
- Retrieves few-shot fine-tuning triage examples.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional


class KnowledgeBaseEngine:
    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            self.base_dir = Path(__file__).resolve().parent
        else:
            self.base_dir = Path(base_dir)

        self.root_dir = self.base_dir.parent
        self.index_path = self.base_dir / "index.json"
        self.owasp_path = self.base_dir / "checklists" / "owasp_top10.json"
        self.portswigger_path = self.base_dir / "checklists" / "portswigger_methodology.json"
        self.kill_criteria_path = self.base_dir / "checklists" / "kill_criteria.json"
        self.bug_chains_path = self.base_dir / "checklists" / "bug_chains.json"
        self.training_path = self.root_dir / "training_data" / "bug_bounty_triage_finetune.jsonl"

        self._index = self._load_json(self.index_path)
        self._owasp = self._load_json(self.owasp_path)
        self._portswigger = self._load_json(self.portswigger_path)
        self._kill_criteria = self._load_json(self.kill_criteria_path)
        self._bug_chains = self._load_json(self.bug_chains_path)

    def _load_json(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def lookup_bug_class(self, query: str) -> List[Dict[str, Any]]:
        """Look up categories matching the query (e.g. 'sqli', 'xss', 'idor', 'ssrf')."""
        query_lower = query.lower().strip()
        results = []
        for cat in self._index.get("categories", []):
            if (
                query_lower in cat.get("id", "").lower()
                or query_lower in cat.get("name", "").lower()
                or query_lower in cat.get("cwe", "").lower()
                or any(query_lower in r.lower() for r in cat.get("rules", []))
            ):
                results.append(cat)
        return results

    ALIASES = {
        "sqli": ["sql", "sql injection", "injection"],
        "xss": ["xss", "cross-site scripting", "cross site scripting"],
        "idor": ["idor", "bola", "broken access control", "broken object level"],
        "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
        "rce": ["rce", "command injection", "remote code execution"],
        "cors": ["cors", "cross-origin", "origin"],
        "auth": ["authentication", "jwt", "oauth", "password"]
    }

    def cite_checklist_item(self, bug_class: str) -> Dict[str, Any]:
        """
        PRD Phase 2 criterion:
        Agent cites the relevant checklist item for a given bug class on request.
        Supports aliases (e.g., 'sqli', 'xss', 'idor', 'ssrf', 'rce').
        """
        raw_query = bug_class.lower().strip()
        search_terms = {raw_query}
        for alias, targets in self.ALIASES.items():
            if raw_query == alias or raw_query in targets:
                search_terms.add(alias)
                search_terms.update(targets)

        citations = []

        # Helper to check if any search term is in text
        def matches(text: str) -> bool:
            t = text.lower()
            return any(st in t for st in search_terms)

        # 1. Search in OWASP Top 10
        for item in self._owasp.get("items", []):
            item_name = item.get("id", "")
            item_cwe = " ".join(item.get("cwe_list", []))
            matching_tests = [
                t for t in item.get("tests", [])
                if matches(item_name) or matches(item_cwe) or matches(t.get("name", "")) or matches(t.get("technique", ""))
            ]
            if matching_tests:
                for t in matching_tests:
                    citations.append({
                        "source": "OWASP Top 10",
                        "framework_id": item.get("id"),
                        "cwe": item.get("cwe_list", []),
                        "test_name": t.get("name"),
                        "technique": t.get("technique"),
                        "verification_command": t.get("verification_command", "N/A"),
                        "pass_condition": t.get("pass_condition"),
                        "fail_condition": t.get("fail_condition")
                    })

        # 2. Search in PortSwigger Playbook
        ps_playbooks = self._portswigger.get("methodology", {}).get("vulnerability_playbooks", {})
        for pb_key, pb_val in ps_playbooks.items():
            if matches(pb_key) or matches(pb_val.get("detection_strategy", "")):
                citations.append({
                    "source": "PortSwigger Web Security Academy",
                    "framework_id": pb_key,
                    "detection_strategy": pb_val.get("detection_strategy"),
                    "subtypes": pb_val.get("subtypes", []),
                    "kill_rules": pb_val.get("kill_rules", "N/A"),
                    "poc_standard": pb_val.get("poc_standard", "N/A")
                })

        # 3. Check for matching A -> B -> C bug chains
        chains = []
        for chain in self._bug_chains.get("chains", []):
            chain_str = json.dumps(chain).lower()
            if any(st in chain_str for st in search_terms):
                chains.append(chain)

        return {
            "query": bug_class,
            "citations_found": len(citations),
            "citations": citations,
            "escalation_chains": chains
        }

    def evaluate_kill_criteria(self, finding_title: str, evidence_text: str) -> Dict[str, Any]:
        """
        Evaluate candidate finding against the 7-Question Gate and instant kill rules.
        Returns whether the finding should be killed or pursued.
        """
        text = f"{finding_title} {evidence_text}".lower()
        rejection_reasons = []

        for rule in self._kill_criteria.get("instant_kill_patterns", []):
            pattern = rule.get("pattern", "").lower()
            words = [w for w in pattern.split() if len(w) > 3]
            match_count = sum(1 for w in words if w in text)
            if match_count >= 2:
                rejection_reasons.append({
                    "matched_pattern": rule.get("pattern"),
                    "reason": rule.get("reason"),
                    "recommendation": "KILL immediately (Non-exploitable / Theoretical)"
                })

        should_kill = len(rejection_reasons) > 0
        return {
            "verdict": "KILL" if should_kill else "PASS_GATE",
            "rejection_reasons": rejection_reasons,
            "gate_applied": "7-Question Gate"
        }

    def get_training_examples(self, vuln_class: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve fine-tuning/few-shot triage training examples."""
        if not self.training_path.exists():
            return []

        examples = []
        with open(self.training_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if vuln_class:
                    if vuln_class.lower() in data.get("vuln_class", "").lower():
                        examples.append(data)
                else:
                    examples.append(data)

                if len(examples) >= limit:
                    break
        return examples


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bug Bounty Methodology Knowledge Base CLI")
    parser.add_argument("--cite", type=str, help="Cite checklist item for a bug class (e.g. sqli, xss, idor, ssrf)")
    parser.add_argument("--query", type=str, help="Search categories in knowledge base")
    parser.add_argument("--training-examples", type=str, help="Show training triage examples for a vuln class")

    args = parser.parse_args()
    engine = KnowledgeBaseEngine()

    if args.cite:
        citation = engine.cite_checklist_item(args.cite)
        print(json.dumps(citation, indent=2))
    elif args.query:
        matches = engine.lookup_bug_class(args.query)
        print(json.dumps(matches, indent=2))
    elif args.training_examples:
        ex = engine.get_training_examples(args.training_examples)
        print(json.dumps(ex, indent=2))
    else:
        print("Bug Bounty Knowledge Base Engine Initialized.")
        print("Categories loaded:", len(engine._index.get("categories", [])))
        print("OWASP Top 10 items:", len(engine._owasp.get("items", [])))
        print("Bug escalation chains:", len(engine._bug_chains.get("chains", [])))
