"""
Scanner Bridge: Connects CLI tools (ffuf, nuclei) to the Scope Gate and Triage Evaluator.
Adheres strictly to .agents/rules/08-scope-authorisation.md and 09-triage-gate.md.

Guards:
1. Target Provenance: Scope verification runs BEFORE any CLI process is spawned.
2. Deny-List Protection: Link-local metadata and RFC1918 addresses are blocked hard.
3. Raw HTTP Capture: Nuclei runs with -irr (Include Request/Response) to capture evidence.
4. Triage Gate Pipeline: Every scanner hit is piped through TriageEvaluator to eliminate noise.
"""

import os
import sys
import json
import random
import string
import tempfile
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from engine.triage_evaluator import TriageEvaluator, CandidateFinding
from core.scope_guard import pinned_dns

FFUF_BIN = ROOT_DIR / "tools" / "bin" / "ffuf.exe"
NUCLEI_BIN = ROOT_DIR / "tools" / "bin" / "nuclei.exe"

TENET_MAX_RATE_LIMIT = 10


class ScannerBridge:
    def __init__(self, evaluator: Optional[TriageEvaluator] = None):
        self.evaluator = evaluator or TriageEvaluator()
        self.ffuf_path = str(FFUF_BIN) if FFUF_BIN.exists() else "ffuf"
        self.nuclei_path = str(NUCLEI_BIN) if NUCLEI_BIN.exists() else "nuclei"

    def get_program_limits(self, program: str) -> Tuple[int, int]:
        """
        Reads program limits from in_scope_assets.json.
        Returns (rate_limit_rps, max_concurrency).
        Caps at TENET_MAX_RATE_LIMIT (10) and default max concurrency (5).
        """
        DEFAULT_RATE = 5
        DEFAULT_CONCURRENCY = 5
        if not program or program == "local_lab":
            return TENET_MAX_RATE_LIMIT, DEFAULT_CONCURRENCY

        try:
            asset_map = self.evaluator._load_asset_map()
            prog_entry = asset_map.get(program)
            if not prog_entry:
                prog_lower = program.strip().lower()
                for k, v in asset_map.items():
                    if k.strip().lower() == prog_lower:
                        prog_entry = v
                        break
            if not prog_entry:
                prog_entry = {}

            prog_rps = prog_entry.get("rate_limit_rps", DEFAULT_RATE)
            prog_concurrency = prog_entry.get("max_concurrency", DEFAULT_CONCURRENCY)
            effective_rate = min(int(prog_rps), TENET_MAX_RATE_LIMIT)
            effective_concurrency = min(int(prog_concurrency), DEFAULT_CONCURRENCY)
            return effective_rate, effective_concurrency
        except Exception:
            return DEFAULT_RATE, DEFAULT_CONCURRENCY

    def run_ffuf(
        self,
        target_url_with_fuzz: str,
        wordlist_path: str,
        program: str = "local_lab",
        is_lab: bool = True,
        rate_limit: int = TENET_MAX_RATE_LIMIT,
        max_time: int = 15,
        budget_tracker: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Runs ffuf for targeted route and parameter discovery.
        Enforces scope checks before launching. When a budget_tracker is supplied the wordlist is
        truncated to the remaining request allowance, so a large list cannot bypass blast radius.
        """
        parsed = urllib.parse.urlparse(target_url_with_fuzz)
        host = parsed.netloc.split(":")[0]

        # Provenance check first (zero network / zero DNS)
        in_scope, scope_msg = self.evaluator.verify_scope(program, host, is_lab=is_lab)
        if not in_scope:
            return {"status": "BLOCKED", "reason": scope_msg, "results": []}

        # Scope & Deny list gate check (resolves the name before any process is spawned)
        gated = self.evaluator.gate_egress(parsed.netloc, is_lab=is_lab)
        if gated["denied"]:
            return {"status": "BLOCKED", "reason": gated["reason"], "results": []}

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="replace") as wl:
                words = [line.strip() for line in wl if line.strip()]
        except OSError as exc:
            return {"status": "ERROR", "error": f"Wordlist unreadable: {exc}", "results": []}

        if not words:
            return {"status": "ERROR", "error": "Wordlist contains no entries", "results": []}

        if budget_tracker is not None and budget_tracker.remaining() <= 0:
            return {"status": "BLOCKED", "reason": "BUDGET_EXHAUSTED: no request budget remaining for fuzzing", "results": []}

        prog_rps, prog_conc = self.get_program_limits(program)
        effective_rate = min(rate_limit, prog_rps)
        effective_conc = min(prog_conc, 5)

        # Baseline Canary Probe to calibrate the SPA catch-all response length.
        # This is a real request: it is charged to the budget tracker and pinned to the
        # addresses the egress gate already validated.
        canary_requests = 0
        canary = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        clean_base = target_url_with_fuzz.split("/FUZZ")[0]
        canary_url = f"{clean_base}/_canary_{canary}"
        baseline_status = None
        baseline_length = None
        if budget_tracker is None or budget_tracker.acquire(1):
            canary_requests = 1
            req = urllib.request.Request(canary_url, headers={"User-Agent": "AntigravityBugHunter/1.0"})
            try:
                with pinned_dns(gated["host"], gated["ips"]):
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        baseline_status = resp.status
                        baseline_length = len(resp.read())
            except urllib.error.HTTPError as e:
                baseline_status = e.code
                baseline_length = len(e.read())
            except Exception:
                canary_requests = 0
                if budget_tracker is not None:
                    budget_tracker.release(1)

        truncated_to = len(words)
        temp_path = None
        if budget_tracker is not None:
            allowed = budget_tracker.remaining()
            if allowed <= 0:
                return {
                    "status": "SUCCESS",
                    "count": 0,
                    "distinct_signatures": 0,
                    "total_matches": 0,
                    "requests_sent": canary_requests,
                    "canary_requests": canary_requests,
                    "reason": "BUDGET_EXHAUSTED after baseline canary: no budget left for fuzz words",
                    "results": []
                }
            if allowed < len(words):
                words = words[:allowed]
                truncated_to = allowed
            if not budget_tracker.acquire(truncated_to):
                return {"status": "BLOCKED", "reason": "BUDGET_RACE: fuzz word budget was consumed concurrently", "results": []}
            temp_handle, temp_path = tempfile.mkstemp(prefix="ffuf_budget_", suffix=".txt")
            with os.fdopen(temp_handle, "w", encoding="utf-8") as tmp:
                tmp.write("\n".join(words) + "\n")
            wordlist_path = temp_path

        cmd = [
            self.ffuf_path,
            "-u", target_url_with_fuzz,
            "-w", wordlist_path,
            "-rate", str(effective_rate),
            "-t", str(effective_conc),
            "-maxtime", str(max_time),
            "-mc", "200,201,204,301,302,307,401,403,500",
            "-json",
            "-s"
        ]

        # If baseline length identified, explicitly filter the catch-all signature
        if baseline_length and baseline_length > 0:
            cmd.extend(["-fs", str(baseline_length)])

        try:
            res = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max_time + 5,
                encoding="utf-8",
                errors="replace"
            )
            raw_discovered = []
            seen_signatures = set()
            responsive_results = []
            distinct_signatures = 0

            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        obj = json.loads(line)
                        raw_discovered.append(obj)
                        st = obj.get("status")
                        length = obj.get("length")
                        # Every non-catch-all URL is kept: each one is a routable target.
                        if baseline_length and length == baseline_length:
                            continue
                        responsive_results.append(obj)
                        sig = (st, length)
                        if sig not in seen_signatures:
                            seen_signatures.add(sig)
                            distinct_signatures += 1
                    except json.JSONDecodeError:
                        pass

            return {
                "status": "SUCCESS",
                "count": len(responsive_results),
                "distinct_signatures": distinct_signatures,
                "total_matches": len(raw_discovered),
                "baseline_filtered_length": baseline_length,
                "canary_requests": canary_requests,
                "requests_sent": (truncated_to if budget_tracker is not None else len(words)) + canary_requests,
                "results": responsive_results
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e), "results": []}
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    def run_nuclei_triage(
        self,
        target_url: str,
        program: str = "local_lab",
        is_lab: bool = True,
        tags: Optional[List[str]] = None,
        template_id: Optional[str] = None,
        templates: Optional[List[str]] = None,
        rate_limit: int = 10,
        timeout: int = 30,
        budget_tracker: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Runs nuclei with -irr (Include Request/Response) and -jsonl,
        then pipes every finding through TriageEvaluator.
        Enforces rate limits and budget tracker constraints before execution.
        """
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.netloc.split(":")[0]

        # Provenance check first (zero network / zero DNS)
        in_scope, scope_msg = self.evaluator.verify_scope(program, host, is_lab=is_lab)
        if not in_scope:
            return [{
                "id": "SCOPE_DENIED",
                "verdict": "KILL",
                "stage_reached": 0,
                "blocking_gap": scope_msg,
                "contract": f"VERDICT: KILL\nSTAGE REACHED: 0\nBLOCKING GAP: {scope_msg}"
            }]

        # A scoped template set is mandatory: an unscoped nuclei run loads the whole community
        # repo (459+ files in the misconfiguration dir alone), exceeds any sane wall-clock
        # budget, and sends far more requests than the caller accounted for.
        if not templates and not template_id:
            return [{
                "status": "NOT_RUN",
                "id": "UNSCOPED_TEMPLATE_SET",
                "error": "Refusing to spawn nuclei without an explicit template set; request volume cannot be bounded.",
                "matched_at": target_url
            }]

        expected_requests = 1 if template_id and not templates else len(templates or [template_id])

        # Budget Check: charge one request per template before the process is spawned.
        if budget_tracker is not None:
            if budget_tracker.remaining() < expected_requests:
                return [{
                    "status": "NOT_RUN",
                    "id": "BUDGET_EXHAUSTED",
                    "error": f"Request budget too small for {expected_requests}-request nuclei scan; scan skipped to preserve blast radius.",
                    "matched_at": target_url
                }]
            budget_tracker.acquire(expected_requests)

        # Scope & Deny list gate check (resolves the name before any process is spawned)
        gated = self.evaluator.gate_egress(parsed.netloc, is_lab=is_lab)
        if gated["denied"]:
            return [{
                "id": "SCOPE_DENIED",
                "verdict": "KILL",
                "stage_reached": 0,
                "blocking_gap": gated["reason"],
                "contract": f"VERDICT: KILL\nSTAGE REACHED: 0\nBLOCKING GAP: {gated['reason']}"
            }]

        prog_rps, prog_conc = self.get_program_limits(program)
        effective_rate = min(rate_limit, prog_rps)
        effective_conc = min(prog_conc, 5)
        if budget_tracker is not None:
            effective_conc = min(effective_conc, max(1, budget_tracker.remaining()))

        cmd = [
            self.nuclei_path,
            "-u", target_url,
            "-silent",
            "-jsonl",
            "-irr",  # Crucial: captures exact raw request and response
            "-duc",  # Disable update checks
            "-ni",   # Non-interactive mode
            "-rl", str(effective_rate),
            "-c", str(effective_conc),
            "-timeout", "5"
        ]

        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        for tpl in (templates or []):
            cmd.extend(["-t", tpl])
        if template_id:
            cmd.extend(["-t", template_id])

        triaged_findings = []

        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace"
            )
            raw_hits = 0
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not (line.startswith("{") and line.endswith("}")):
                    continue
                try:
                    hit = json.loads(line)
                    raw_hits += 1
                except json.JSONDecodeError:
                    continue

                # Extract evidence
                t_id = hit.get("template-id", "nuclei-alert")
                title = hit.get("info", {}).get("name", t_id)
                matched_at = hit.get("matched-at", target_url)
                if matched_at and "://" not in matched_at:
                    matched_at = f"{parsed.scheme}://{matched_at}"
                raw_req = hit.get("request", "")
                raw_resp = hit.get("response", "")

                # Parse status code and headers from response
                status_code = None
                resp_headers = {}
                resp_body = raw_resp
                if raw_resp.startswith("HTTP/"):
                    parts = raw_resp.split("\r\n\r\n", 1) if "\r\n\r\n" in raw_resp else raw_resp.split("\n\n", 1)
                    header_block = parts[0]
                    resp_body = parts[1] if len(parts) > 1 else ""
                    first_line = header_block.splitlines()[0] if header_block else ""
                    if len(first_line.split()) >= 2:
                        try:
                            status_code = int(first_line.split()[1])
                        except ValueError:
                            pass
                    for h_line in header_block.splitlines()[1:]:
                        if ":" in h_line:
                            hk, hv = h_line.split(":", 1)
                            resp_headers[hk.strip()] = hv.strip()

                method = "GET"
                if raw_req:
                    method = raw_req.split()[0] if raw_req.split() else "GET"

                f = CandidateFinding(
                    title=title,
                    program=program,
                    target_host=host,
                    request_method=method,
                    request_url=matched_at,
                    request_body="",
                    response_status=status_code or 200,
                    response_headers=resp_headers,
                    response_body=resp_body,
                    second_account_tested=False,
                    attacker_controlled_proof=f"Nuclei template {t_id} matched response pattern",
                    is_lab=is_lab,
                    notes=f"Discovered via Nuclei template: {t_id}"
                )

                triage_res = self.evaluator.evaluate(f)
                contract = self.evaluator.format_output_contract(triage_res)
                triaged_findings.append({
                    "template_id": t_id,
                    "title": title,
                    "matched_at": matched_at,
                    "nuclei_severity": hit.get("info", {}).get("severity", "unknown"),
                    "verdict": triage_res["verdict"],
                    "stage_reached": triage_res["stage_reached"],
                    "blocking_gap": triage_res["blocking_gap"],
                    "cvss": triage_res["cvss"],
                    "contract": contract,
                    "finding": f
                })
        except subprocess.TimeoutExpired as e:
            return [{
                "status": "NOT_RUN",
                "id": "TIMEOUT",
                "error": f"Nuclei scan timed out after {timeout}s: {e}",
                "matched_at": target_url
            }]
        except Exception as e:
            return [{
                "status": "ERROR",
                "id": "EXECUTION_ERROR",
                "error": f"Nuclei Execution Error: {e}",
                "matched_at": target_url
            }]

        return triaged_findings
