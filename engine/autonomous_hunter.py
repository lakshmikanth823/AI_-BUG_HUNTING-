"""
Autonomous AI Bug Bounty Hunter Pipeline.
Orchestrates the 5-phase hunting lifecycle:
1. Scope Verification & Provenance Check
2. Attack Surface & Endpoint Discovery (ReconEngine + FFUF)
3. Targeted Probing & Evidence Collection (ScannerBridge / Nuclei -irr)
4. Evidence-Based Triage Gate Evaluation (TriageEvaluator Stage 0-5)
5. Formal Submission-Ready Report Generation

Guards:
- Strict target provenance against data/programs-ranked.csv (or local lab carve-out).
- Permanent deny list enforcement (zero cloud metadata / RFC 1918 scans).
- Request budget limits to prevent WAF / DoS risks.
- Evidence-based CVSS 3.1 arithmetic.
"""

import os
import sys
import json
import time
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from engine.triage_evaluator import TriageEvaluator, CandidateFinding
from engine.scanner_bridge import ScannerBridge
from engine.authz_probe import AuthzProbe, ProbeRefused
from core.recon import ReconEngine
from core.scope_guard import RequestBudgetTracker, admission_failure


class AutonomousHunter:
    def __init__(self, is_lab: bool = True):
        self.is_lab = is_lab
        self.evaluator = TriageEvaluator()
        self.recon = ReconEngine(user_agent="AntigravityBugHunter/1.0")
        self.scanner = ScannerBridge(evaluator=self.evaluator)
        self.budget_tracker = RequestBudgetTracker(max_budget=10)

    def load_authz_probes(self) -> List[Dict[str, Any]]:
        """Operator-authored cross-tenant probe configs; absent file simply means no probes run."""
        path = ROOT_DIR / "data" / "authz_probes.json"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        if isinstance(data, list):
            probes = data
        elif isinstance(data, dict):
            probes = data.get("probes", []) if "probes" in data else [data]
        else:
            probes = []
        return [p for p in probes if isinstance(p, dict) and p.get("base_url")]

    def load_curated_templates(self) -> List[str]:
        """Absolute paths for the bounded nuclei template set; an unscoped run cannot be budgeted."""
        list_path = ROOT_DIR / "data" / "nuclei_curated.txt"
        base = ROOT_DIR / "knowledge_base" / "templates" / "nuclei-templates"
        try:
            with open(list_path, "r", encoding="utf-8") as fh:
                rels = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError:
            return []
        return [str(base / rel) for rel in rels if (base / rel).exists()]

    def hunt(
        self,
        program_name: str,
        target_url: str,
        wordlist_path: Optional[str] = None,
        max_probe_budget: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes the autonomous hunting lifecycle against the target asset.
        Lab-vs-live budget split:
        - Non-lab programs default to 10 requests (08-scope blast radius). An operator who has
          written an admitted, fully attested entry may raise that with 'max_request_budget',
          hard-capped at 150 per run. Unattested entries never raise the ceiling.
        - Loopback / local lab targets are permitted up to 150 requests to allow full wordlist runs.
        """
        if self.is_lab:
            effective_budget = max_probe_budget if max_probe_budget is not None else 150
        else:
            asset_map = {}
            try:
                asset_map = self.evaluator._load_asset_map()
            except Exception:
                pass

            prog_entry = asset_map.get(program_name)
            if not prog_entry:
                prog_lower = program_name.strip().lower()
                for k, v in asset_map.items():
                    if k.strip().lower() == prog_lower:
                        prog_entry = v
                        break
            if not prog_entry:
                prog_entry = {}

            # Same predicate that admits the target: an entry that would be refused for scope
            # must not be able to arm a larger blast radius.
            admitted = not admission_failure(prog_entry, program_name, automated=True)
            attested_budget = prog_entry.get("max_request_budget") if admitted else None
            if isinstance(attested_budget, int) and not isinstance(attested_budget, bool) and attested_budget > 0:
                live_ceiling = min(attested_budget, 150)
            else:
                live_ceiling = 10

            if max_probe_budget is not None:
                effective_budget = min(max_probe_budget, live_ceiling)
            else:
                effective_budget = live_ceiling

        self.budget_tracker.reset()
        self.budget_tracker.max_budget = effective_budget

        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc.split(":")[0]
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        print("=" * 75)
        print(f"AUTONOMOUS BUG BOUNTY HUNTING AGENT — SESSION START")
        print(f"Target Program: {program_name}")
        print(f"Target Asset:   {target_url}")
        print(f"Timestamp:      {timestamp}")
        print("=" * 75)

        # -------------------------------------------------------------
        # PHASE 1: Scope & Authorisation Gate
        # -------------------------------------------------------------
        print("\n[PHASE 1] Scope Verification & Target Provenance...")
        in_scope, scope_msg = self.evaluator.verify_scope(program_name, target_host, is_lab=self.is_lab, automated=True)
        if not in_scope:
            print(f"[-] OUT OF SCOPE: {scope_msg}")
            return {
                "status": "STOPPED",
                "stage": 0,
                "reason": scope_msg,
                "verdict": "KILL",
                "reports": []
            }

        gated = self.evaluator.gate_egress(parsed.netloc, is_lab=self.is_lab)
        if gated["denied"]:
            print(f"[-] HARD STOP: {gated['reason']}")
            return {
                "status": "STOPPED",
                "stage": 0,
                "reason": gated["reason"],
                "verdict": "KILL",
                "reports": []
            }

        print(f"[+] Provenance Confirmed: {target_host} is authorized under {program_name}.")

        # -------------------------------------------------------------
        # PHASE 2: Attack Surface Discovery & Route Recon
        # -------------------------------------------------------------
        print("\n[PHASE 2] Mapping Attack Surface (ReconEngine)...")
        surface = self.recon.map_surface(target_url, budget_tracker=self.budget_tracker, is_lab=self.is_lab, program=program_name)
        if "error" in surface and surface.get("status") is None:
            print(f"[-] RECON HALTED: {surface['error']}")
            return {
                "status": "STOPPED",
                "stage": 2,
                "reason": surface["error"],
                "verdict": "KILL",
                "reports": []
            }
        discovered_endpoints = list(surface.get("endpoints", []))
        crawled_count = len(discovered_endpoints)
        api_routes = list(surface.get("api_routes", []))
        forms = surface.get("forms", [])

        # Step 2a: Active FFUF route discovery (uses default lab wordlist if none supplied)
        active_wl = wordlist_path or str(ROOT_DIR / "data" / "lab_common_routes.txt")
        ffuf_discovered_routes = []
        if os.path.exists(active_wl):
            allowed = self.budget_tracker.remaining()
            # Reserve at least half the budget for subsequent targeted probes if possible
            ffuf_budget = max(1, allowed // 2) if allowed > 2 else allowed
            print(f"[*] Running FFUF route discovery (budget: {ffuf_budget} requests, rate <= 10 req/s)...")
            if ffuf_budget > 0:
                fuzz_target = f"{target_url.rstrip('/')}/FUZZ"
                ffuf_tracker = RequestBudgetTracker(max_budget=ffuf_budget)
                ffuf_res = self.scanner.run_ffuf(
                    fuzz_target,
                    active_wl,
                    program=program_name,
                    is_lab=self.is_lab,
                    rate_limit=10,
                    budget_tracker=ffuf_tracker
                )
                sent = ffuf_res.get("requests_sent", 0)
                self.budget_tracker.acquire(sent)
                for r_hit in ffuf_res.get("results", []):
                    r_url = r_hit.get("url", "")
                    if r_url:
                        if r_url not in discovered_endpoints:
                            discovered_endpoints.append(r_url)
                        ffuf_discovered_routes.append(r_url)
                ffuf_signatures = ffuf_res.get("distinct_signatures", 0)
                print(f"[+] FFUF completed: {sent} requests sent "
                      f"(incl. baseline canary), {len(ffuf_discovered_routes)} responsive routes "
                      f"({ffuf_signatures} distinct response signatures), "
                      f"catch-all length filtered: {ffuf_res.get('baseline_filtered_length')}.")
            else:
                print("[-] FFUF skipped: request budget exhausted.")

        print(f"[+] Status: HTTP {surface.get('status')}")
        print(f"[+] Technologies Detected: {', '.join(surface.get('technologies', [])) or 'None identified'}")
        print(f"[+] Forms Extracted: {len(forms)}")
        print(f"[+] API Routes Discovered: {len(api_routes)}")
        print(f"[+] Crawled Endpoints: {crawled_count}")
        dm = surface.get("discovery_metrics", {})
        if dm:
            print(f"[+] Recon Detail: {dm.get('js_bundles_analyzed')} JS bundles parsed, "
                  f"{dm.get('path_candidates')} path candidates, "
                  f"{dm.get('validated_responsive')}/{dm.get('candidates_validated')} validated responsive, "
                  f"catch-all length {dm.get('catch_all_length')}, "
                  f"recon requests {dm.get('requests_used_by_recon')}")
        print(f"[+] FFUF Routes: {len(ffuf_discovered_routes)}")
        print(f"[+] Total In-Scope Endpoints: {len(discovered_endpoints)}")

        # -------------------------------------------------------------
        # PHASE 3 & 4: Probing & Triage Gate Evaluation
        # -------------------------------------------------------------
        print("\n[PHASE 3 & 4] Targeted Probing & Evidence Triage...")
        findings_to_triage: List[CandidateFinding] = []

        # 1. Missing Security Headers check (Uses real response evidence)
        sec_hdrs = surface.get("security_headers", {})
        missing_sec = [k for k, present in sec_hdrs.items() if not present]
        if missing_sec and surface.get("status"):
            findings_to_triage.append(CandidateFinding(
                title=f"Missing Security Headers ({', '.join(missing_sec)}) on {target_host}",
                program=program_name,
                target_host=target_host,
                request_method="GET",
                request_url=target_url,
                request_headers={"User-Agent": self.recon.user_agent},
                response_status=surface.get("status"),
                response_headers=surface.get("headers", {}),
                response_body=surface.get("body", "")[:2000],
                second_account_tested=False,
                attacker_controlled_proof=f"Headers absent from HTTP response: {', '.join(missing_sec)}",
                is_lab=self.is_lab
            ))

        # 2. Extract Forms and probe with real HTTP requests within budget
        for form in forms:
            if self.budget_tracker.remaining() <= 0:
                print("[-] Blast radius limit reached: Cumulative probe request budget exhausted.")
                break

            action = urllib.parse.urljoin(target_url, form.get("action", ""))
            method = form.get("method", "GET").upper()
            inputs = [inp.get("name") for inp in form.get("inputs", []) if inp.get("name")]
            if inputs:
                probe_query = "&".join(f"{inp}=probe_test" for inp in inputs)
                probe_url = f"{action}?{probe_query}" if method == "GET" else action
                probe_data = probe_query if method == "POST" else None

                resp = self.recon.fetch_endpoint(
                    url=probe_url,
                    method=method,
                    data=probe_data,
                    budget_tracker=self.budget_tracker,
                    is_lab=self.is_lab
                )
                if resp.get("status"):
                    findings_to_triage.append(CandidateFinding(
                        title=f"Form Probe on {action}",
                        program=program_name,
                        target_host=target_host,
                        request_method=method,
                        request_url=probe_url,
                        request_body=probe_data or "",
                        response_status=resp.get("status"),
                        response_headers=resp.get("headers", {}),
                        response_body=resp.get("body", "")[:2000],
                        second_account_tested=False,
                        attacker_controlled_proof="Active form submission probe executed",
                        is_lab=self.is_lab
                    ))

        # 3. Targeted Nuclei Vulnerability Discovery with -irr
        nuclei_candidates = 0
        seen_nuclei_candidates = set()
        tool_failures = []
        curated_templates = self.load_curated_templates()
        remaining_budget = self.budget_tracker.remaining()
        if remaining_budget > 0 and curated_templates and self.scanner.nuclei_path:
            # Probe target url and responsive routes with nuclei
            scan_targets = [target_url]
            if discovered_endpoints:
                for ep in discovered_endpoints[:3]:
                    if ep not in scan_targets:
                        scan_targets.append(ep)

            # Measured floor: 15 curated templates against one loopback target completes in
            # ~8s; an unscoped run exceeds 180s and yields nothing.
            nuclei_wall = 45
            # The header sweep above already submitted this evidence for the base URL, so
            # nuclei's per-header matches on the same URL are duplicates, not new findings.
            if sec_hdrs:
                seen_nuclei_candidates.add(("http-missing-security-headers", target_url.split("?")[0]))
            print(f"[*] Running targeted Nuclei scans on {len(scan_targets)} targets "
                  f"({len(curated_templates)} curated templates/target, ~{len(curated_templates) * len(scan_targets)} req, "
                  f"budget: {remaining_budget} req)...")
            for s_target in scan_targets:
                if self.budget_tracker.remaining() < len(curated_templates):
                    print(f"[-] Nuclei skipped for {s_target}: budget {self.budget_tracker.remaining()} < "
                          f"{len(curated_templates)} required requests.")
                    tool_failures.append({
                        "tool": "nuclei",
                        "target": s_target,
                        "status": "NOT_RUN",
                        "id": "BUDGET_EXHAUSTED",
                        "error": "Insufficient remaining budget for the curated template set"
                    })
                    break
                try:
                    hits = self.scanner.run_nuclei_triage(
                        s_target,
                        program=program_name,
                        tags=["misconfig", "exposure", "cve", "default-login"],
                        templates=curated_templates,
                        is_lab=self.is_lab,
                        rate_limit=5,
                        timeout=nuclei_wall,
                        budget_tracker=self.budget_tracker
                    )

                    for hit in hits:
                        hit_status = hit.get("status")
                        if hit_status in ("NOT_RUN", "ERROR"):
                            err_msg = hit.get("error", "Unknown tool error")
                            print(f"[-] Nuclei {hit.get('id', 'FAIL')} on {s_target}: {err_msg}")
                            tool_failures.append({
                                "tool": "nuclei",
                                "target": s_target,
                                "status": hit_status,
                                "id": hit.get("id"),
                                "error": err_msg
                            })
                        elif hit.get("id") != "SCOPE_DENIED" and hit.get("finding"):
                            # A multi-match template (e.g. one match per absent header) would
                            # otherwise enter the gate once per match against the same response.
                            dedupe_key = (hit.get("template_id"), hit["finding"].request_url.split("?")[0])
                            if dedupe_key in seen_nuclei_candidates:
                                continue
                            seen_nuclei_candidates.add(dedupe_key)
                            findings_to_triage.append(hit["finding"])
                            nuclei_candidates += 1
                            print(f"[+] Nuclei candidate: {hit.get('template_id')} ({hit.get('nuclei_severity')}) "
                                  f"pre-triaged {hit.get('verdict')} on {s_target}")
                except Exception as n_err:
                    print(f"[-] Nuclei pass exception on {s_target}: {n_err}")
                    tool_failures.append({
                        "tool": "nuclei",
                        "target": s_target,
                        "status": "EXCEPTION",
                        "error": str(n_err)
                    })

        # 4. Cross-tenant authorization probes (operator-configured, two declared sessions)
        authz_probe_runs = 0
        if self.budget_tracker.remaining() >= 12:
            for raw_cfg in self.load_authz_probes():
                cfg = dict(raw_cfg)
                if not cfg.get("program"):
                    cfg["program"] = program_name
                probe_base = cfg.get("base_url", "")
                if urllib.parse.urlparse(probe_base).netloc != urllib.parse.urlparse(target_url).netloc:
                    continue
                if self.budget_tracker.remaining() < 12:
                    print("[-] Authz probe skipped for "
                          f"{cfg.get('name')}: insufficient remaining budget ({self.budget_tracker.remaining()}).")
                    tool_failures.append({
                        "tool": "authz_probe", "target": probe_base, "status": "NOT_RUN",
                        "id": "BUDGET_EXHAUSTED", "error": "cross-tenant probe needs ~8 requests"
                    })
                    continue
                try:
                    probes = AuthzProbe(self.recon).run(
                        probe_base, cfg, budget_tracker=self.budget_tracker, is_lab=self.is_lab
                    )
                    authz_probe_runs += 1
                    for pf in probes:
                        findings_to_triage.append(pf)
                        verdict = self.evaluator.evaluate(pf)["verdict"]
                        print(f"[+] Authz probe '{cfg.get('name')}': evidence captured on "
                              f"{pf.request_url} -> triaged {verdict}")
                except ProbeRefused as pr:
                    print(f"[-] Authz probe '{cfg.get('name')}' refused: {pr}")
                    tool_failures.append({
                        "tool": "authz_probe", "target": probe_base, "status": "REFUSED",
                        "id": "PROBE_REFUSED", "error": str(pr)
                    })
                except Exception as pz:
                    print(f"[-] Authz probe '{cfg.get('name')}' error: {pz}")
                    tool_failures.append({
                        "tool": "authz_probe", "target": probe_base, "status": "ERROR",
                        "id": "EXECUTION_ERROR", "error": str(pz)
                    })

        # Evaluate all candidate findings through Triage Gate
        triaged_results = []
        for f in findings_to_triage[:max_probe_budget]:
            res = self.evaluator.evaluate(f)
            contract = self.evaluator.format_output_contract(res)
            triaged_results.append({
                "finding": f,
                "triage": res,
                "contract": contract
            })

        # -------------------------------------------------------------
        # PHASE 5: Triage Summary & Report Synthesis
        # -------------------------------------------------------------
        payable_reports = []
        leads = []
        killed = []

        for item in triaged_results:
            verd = item["triage"]["verdict"]
            if verd == "VALID-PAYABLE":
                payable_reports.append(item)
            elif verd == "LEAD":
                leads.append(item)
            else:
                killed.append(item)

        print("\n" + "=" * 75)
        print("HUNTING CYCLE TRIAGE SUMMARY & DISCOVERY YIELD")
        print("=" * 75)
        print(f"Attack Surface Discovery Yield:")
        print(f"  -> Crawled Endpoints:     {crawled_count}")
        print(f"  -> FFUF Distinct Routes:  {len(ffuf_discovered_routes)}")
        print(f"  -> Nuclei Candidates:     {nuclei_candidates}")
        print(f"  -> Authz Probes Run:      {authz_probe_runs}")
        print(f"  -> Total Candidates:      {len(findings_to_triage)}")
        print(f"Tool Operational Status:")
        print(f"  -> Tool Failures/Skips:   {len(tool_failures)}")
        for tf in tool_failures:
            print(f"     * [{tf['tool'].upper()} {tf.get('id', tf.get('status'))}] on {tf['target']}: {tf['error']}")
        print(f"Triage Gate Decisions:")
        print(f"  -> Total Findings Judged: {len(triaged_results)}")
        print(f"  -> VALID-PAYABLE:         {len(payable_reports)}")
        print(f"  -> LEAD (Needs Proof):    {len(leads)}")
        print(f"  -> KILL (Noise/Benign):   {len(killed)}")
        print("=" * 75)

        for item in killed:
            f = item["finding"]
            t = item["triage"]
            print(f"[*] KILLED NOISE: {f.title}")
            print(f"    Evidence URL: {f.request_method} {f.request_url}")
            print(f"    Reason: {t.get('blocking_gap')}")

        for item in payable_reports:
            f = item["finding"]
            t = item["triage"]
            print(f"\n[!] VALID PAYABLE VULNERABILITY CONFIRMED: {f.title}")
            print(f"    CVSS 3.1: {t.get('cvss')}")
            print(f"    Action:   {t.get('next_action')}")

        return {
            "status": "COMPLETED",
            "program": program_name,
            "target": target_url,
            "surface": surface,
            "discovery_yield": {
                "crawled_endpoints": crawled_count,
                "ffuf_routes": len(ffuf_discovered_routes),
                "nuclei_candidates": nuclei_candidates,
                "authz_probes_run": authz_probe_runs,
                "total_candidates": len(findings_to_triage)
            },
            "tool_failures": tool_failures,
            "payable_count": len(payable_reports),
            "lead_count": len(leads),
            "killed_count": len(killed),
            "payable_reports": payable_reports,
            "leads": leads,
            "killed": killed
        }


if __name__ == "__main__":
    hunter = AutonomousHunter(is_lab=True)
    # Test against local lab Juice Shop
    res = hunter.hunt("local_lab", "http://127.0.0.1:3000")
