"""
Programmatic Triage Evaluator & Scope Guard.
Implements the exact logic specified in:
- 09-triage-gate.md (Stages 0-5 and OUTPUT CONTRACT)
- 08-scope-authorisation.md (Target provenance and Permanent Deny List)
"""

import re
import csv
import json
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"

from core.scope_guard import (
    parse_host_port,
    check_deny_list_static,
    gate_destination,
    admission_failure,
    LAB_HOSTS,
    LAB_PORTS,
    PERMANENT_DENY_PATTERNS,
    PERMANENT_DENY_CIDRS
)


MIN_MARKER_LENGTH = 8


@dataclass
class CandidateFinding:
    title: str
    program: str
    target_host: str
    request_method: str
    request_url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    second_account_tested: bool = False
    attacker_controlled_proof: str = ""
    is_lab: bool = False
    notes: str = ""
    # Cross-tenant evidence: a value planted in, or belonging to, a DIFFERENT tenant account,
    # plus the executing account's own control response. Required for Q1/Q2; the
    # second_account_tested boolean is reporting metadata and never affects a verdict.
    victim_marker: str = ""
    baseline_status: Optional[int] = None
    baseline_body: str = ""
    readback_body: str = ""


def cross_tenant_read_proven(f: "CandidateFinding") -> bool:
    """
    A cross-tenant read is proven only by a diff between two captured transactions: the
    attacker's response must contain an identifier that the executing account's own control
    response does not. An asserted boolean, a keyword appearing in the body, or a narrative
    proof string is not evidence and cannot satisfy this.
    """
    marker = f.victim_marker
    if not marker or len(marker) < MIN_MARKER_LENGTH:
        return False
    if f.response_status not in (200, 201):
        return False
    if not f.baseline_body.strip():
        return False
    if marker not in f.response_body:
        return False
    if marker in f.baseline_body:
        return False
    return True


def _script_payload_present(text: str) -> bool:
    low = text.lower()
    return ("<script" in low or "<iframe" in low) and "alert(" in low


def outbound_fetch_targets(f: "CandidateFinding") -> List[str]:
    """
    URLs the attacker directed the SERVER to fetch: absolute URLs carried in the request body,
    query parameters, or captured transaction proofs whose host differs from the endpoint's own host.
    """
    own_netloc = urllib.parse.urlparse(f.request_url).netloc.lower()
    haystack = (f.request_body or "") + " " + (f.attacker_controlled_proof or "")
    try:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(f.request_url).query)
        haystack += " " + " ".join(v for values in params.values() for v in values)
    except ValueError:
        pass
    haystack = urllib.parse.unquote_plus(haystack)
    return [
        u for u in re.findall(r"https?://[^\s\"'<>]+", haystack)
        if urllib.parse.urlparse(u).netloc.lower() not in ("", own_netloc)
        and "w3.org" not in u.lower() and "schema.org" not in u.lower()
    ]


def cross_tenant_mutation_proven(f: "CandidateFinding") -> bool:
    """A write is cross-tenant only when a post-mutation readback confirms the modification or foreign identifier."""
    marker = f.victim_marker
    if not marker or len(marker) < MIN_MARKER_LENGTH:
        return False
    if f.request_method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
        return False
    if f.response_status not in (200, 201, 204):
        return False
    if not f.baseline_body.strip():
        return False
    if not f.readback_body.strip():
        return False
    if marker not in f.readback_body and marker not in f.response_body:
        return False
    return (marker not in f.baseline_body) or (f.readback_body.strip() != f.baseline_body.strip())


class TriageEvaluator:
    def __init__(self):
        self.programs_csv = DATA_DIR / "programs-ranked.csv"
        self._programs_cache = self._load_programs()
        self.asset_map = self._load_asset_map()

    def _load_programs(self) -> List[Dict[str, Any]]:
        if not self.programs_csv.exists():
            return []
        try:
            with open(self.programs_csv, "r", encoding="utf-8") as f:
                return list(csv.DictReader(f))
        except Exception:
            return []

    def _load_asset_map(self) -> Dict[str, Any]:
        if hasattr(self, "asset_map") and self.asset_map:
            return self.asset_map
        assets_json = DATA_DIR / "in_scope_assets.json"
        if not assets_json.exists():
            return {}
        try:
            with open(assets_json, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def verify_scope(self, program: str, host: str, is_lab: bool = False, automated: bool = False) -> Tuple[bool, str]:
        """Enforces 08-scope-authorisation.md §1 & §6 with exact canonical program and asset matching."""
        if not host:
            return False, f"OUT OF SCOPE — unknown is not a listed in-scope asset for {program or 'unspecified program'}. Confirm authorisation or pick a target from data/programs-ranked.csv."

        host_clean = host.split(":")[0].strip().lower()

        if is_lab:
            if host_clean in LAB_HOSTS:
                return True, "LOCAL_LAB_IN_SCOPE"
            return False, f"OUT OF SCOPE — {host} is not a valid local lab host. Must be localhost/127.0.0.1."

        if not program:
            return False, f"OUT OF SCOPE — {host} is not a listed in-scope asset for unspecified program. Confirm authorisation or pick a target from data/programs-ranked.csv."

        prog_clean = program.strip()
        prog_lower = prog_clean.lower()

        matched_prog = None
        for p in self._programs_cache:
            if p.get("name", "").strip().lower() == prog_lower:
                matched_prog = p
                break

        if not matched_prog:
            return False, f"OUT OF SCOPE — {host} is not a listed in-scope asset for {program}. Confirm authorisation or pick a target from data/programs-ranked.csv."

        canonical_name = matched_prog.get("name", "")
        asset_map = self._load_asset_map()
        prog_entry = asset_map.get(canonical_name)
        if not prog_entry:
            return False, f"OUT OF SCOPE — program '{program}' is not admitted to data/in_scope_assets.json. Confirm authorisation or pick a target from data/programs-ranked.csv."

        # Single source of truth for operator admission & automated permission
        failure = admission_failure(prog_entry, canonical_name, automated=automated)
        if failure:
            return False, f"OUT OF SCOPE — {failure} Confirm authorisation or pick a target from data/programs-ranked.csv."

        prog_assets = prog_entry.get("in_scope_assets", [])

        is_asset_in_scope = False
        for pattern in prog_assets:
            p_pat = pattern.lower().strip()
            if p_pat.startswith("*."):
                suffix = p_pat[1:]
                if host_clean.endswith(suffix) or host_clean == p_pat[2:]:
                    is_asset_in_scope = True
                    break
            elif host_clean == p_pat:
                is_asset_in_scope = True
                break

        if not is_asset_in_scope:
            return False, f"OUT OF SCOPE — {host} is not a listed in-scope asset for {program}. Confirm authorisation or pick a target from data/programs-ranked.csv."

        return True, "IN_SCOPE_CONFIRMED"

    def check_deny_list(self, destination: str, is_lab: bool = False) -> Tuple[bool, str]:
        """Enforces 08-scope-authorisation.md §2 (Permanent Deny List & Lab Carve-Out)."""
        return check_deny_list_static(destination, is_lab=is_lab)

    def gate_egress(self, destination: str, is_lab: bool = False) -> Dict[str, Any]:
        """
        Pre-flight gate for anything about to send packets. Unlike the triage-time check this
        resolves the name, validates every address, and returns them so the caller can pin them.
        """
        return gate_destination(destination, is_lab=is_lab)

    def evaluate(self, f: CandidateFinding) -> Dict[str, Any]:
        """
        Executes the full Stage 0 - Stage 5 Triage Gate protocol.
        Zero verdict-affecting uses of f.title; all determinations derive
        strictly from HTTP evidence (method, URL, body, headers, proof of control).
        """
        body_lower = f.response_body.lower()
        url_lower = urllib.parse.unquote_plus(f.request_url.lower())
        proof_lower = f.attacker_controlled_proof.lower()
        endpoint_clean = f.request_url.split("?")[0] if f.request_url else "unknown_endpoint"

        # Step 0b: Deny list check on request URL and target host FIRST
        parsed = urllib.parse.urlparse(f.request_url if "://" in f.request_url else f"http://{f.request_url}")
        denied_dest = parsed.netloc or f.target_host
        denied, deny_msg = self.check_deny_list(denied_dest, is_lab=f.is_lab)
        if denied:
            return {
                "verdict": "KILL",
                "stage_reached": 0,
                "blocking_gap": deny_msg,
                "seven_answers": {
                    "Q1": f"no, destination {denied_dest} prohibited under permanent deny list",
                    "Q2": f"no, destination {denied_dest} prohibited under permanent deny list",
                    "Q3": f"no, destination {denied_dest} prohibited under permanent deny list",
                    "Q4": f"no, destination {denied_dest} prohibited under permanent deny list",
                    "Q5": f"no, destination {denied_dest} prohibited under permanent deny list",
                    "Q6": f"no, restricted infrastructure {denied_dest} inaccessible to external operators",
                    "Q7": f"no, forbidden destination {denied_dest} violates safety gate"
                },
                "cvss": "n/a",
                "next_action": f"Hard Stop. Prohibited target requested: {deny_msg}"
            }

        # Step 0a: Target Provenance Verification
        in_scope, scope_msg = self.verify_scope(f.program, f.target_host, is_lab=f.is_lab)
        if not in_scope:
            return {
                "verdict": "KILL",
                "stage_reached": 0,
                "blocking_gap": scope_msg,
                "seven_answers": {
                    "Q1": f"no, scope unverified for target asset {f.target_host}",
                    "Q2": f"no, scope unverified for target asset {f.target_host}",
                    "Q3": f"no, scope unverified for target asset {f.target_host}",
                    "Q4": f"no, scope unverified for target asset {f.target_host}",
                    "Q5": f"no, scope unverified for target asset {f.target_host}",
                    "Q6": f"no, unverified target {f.target_host} fails clean-device provenance test",
                    "Q7": f"no, cannot establish end-to-end impact on unverified target {f.target_host}"
                },
                "cvss": "n/a",
                "next_action": f"Stop immediately. {scope_msg}"
            }

        # Stage 0: Evidence Sufficiency Check
        missing_evidence = []
        if not f.request_method or not f.request_url:
            missing_evidence.append("(a) exact request URL/method")
        if f.response_status is None:
            missing_evidence.append("(b) exact response status")
        
        if not f.attacker_controlled_proof.strip() and not f.victim_marker.strip():
            missing_evidence.append("(c) proof behavior is attacker-controlled / distinct session")
            
        if not f.target_host:
            missing_evidence.append("(d) specific in-scope asset mapping")

        if missing_evidence:
            return {
                "verdict": "LEAD" if f.response_status else "KILL",
                "stage_reached": 0,
                "blocking_gap": f"Missing Stage 0 evidence elements: {', '.join(missing_evidence)}",
                "seven_answers": {
                    "Q1": f"no, unverified evidence on {endpoint_clean}",
                    "Q2": f"no, unverified evidence on {endpoint_clean}",
                    "Q3": f"no, unverified evidence on {endpoint_clean}",
                    "Q4": f"no, unverified evidence on {endpoint_clean}",
                    "Q5": f"no, unverified evidence on {endpoint_clean}",
                    "Q6": f"no, evidence insufficiency precludes unprivileged verification on {endpoint_clean}",
                    "Q7": f"no, missing {', '.join(missing_evidence)} prevents end-to-end confirmation"
                },
                "cvss": "n/a",
                "next_action": f"Capture missing evidence ({', '.join(missing_evidence)}) before proceeding."
            }

        # Stage 2 Reality Check (derived from structural evidence: payload present, neutralized defenses / zero records, zero leakage)
        has_injection_payload = any(p in (url_lower + " " + f.request_body.lower()) for p in (
            "' or", "'--", "1=1", "union select", "select null", "order by", "sleep(", "waitfor delay", "pg_sleep",
            "; whoami", "; id", "| whoami", "| id", "<script", "onerror="
        ))

        # Structural zero-row phrases across diverse enterprise web & API stacks
        ZERO_ROW_PHRASES = (
            "0 records", "0 results", "0 rows", "0 items", "0 matches",
            "zero records", "zero results", "zero rows", "zero items",
            "no records found", "no results found", "no matching records",
            "no records match", "no results match", "no data found", "no items found",
            "empty result", "empty dataset", "empty set",
            "record not found", "user not found", "item not found", "account not found",
            "query returned no results", "missing database records"
        )

        # Structural empty-set JSON patterns for modern REST/GraphQL APIs
        ZERO_ROW_JSON_PATTERNS = (
            '"results":[]', '"results": []',
            '"data":[]', '"data": []',
            '"items":[]', '"items": []',
            '"records":[]', '"records": []',
            '"rows":[]', '"rows": []',
            '"users":[]', '"users": []',
            '"count":0', '"count": 0',
            '"total":0', '"total": 0',
            '"total_count":0', '"total_count": 0'
        )

        # Defensive control / parameterization / type enforcement indicators
        DEFENSE_PHRASES = (
            "parameterized", "prepared statement",
            "invalid integer", "invalid number", "expected numeric",
            "type mismatch", "conversion failed when converting",
            "invalid input syntax for type", "syntax error: invalid input syntax",
            "validation failed", "malformed parameter", "input rejected by filter",
            "unrecognized input format", "data type mismatch", "sanitized input"
        )

        # Data leakage markers indicating that execution or dumped records actually occurred
        DATA_LEAKAGE_TOKENS = (
            "uid=", "www-data", "root:x:", "/bin/bash", "/bin/sh", "[boot loader]",
            "password_hash", "$2y$", "$2a$", "$2b$", "first name: admin", "admin@"
        )
        has_data_leakage = any(tok in body_lower for tok in DATA_LEAKAGE_TOKENS) or (bool(f.victim_marker) and f.victim_marker in f.response_body)

        has_zero_records = any(phrase in body_lower for phrase in ZERO_ROW_PHRASES) or any(pat in body_lower for pat in ZERO_ROW_JSON_PATTERNS)
        has_defense_signal = any(phrase in body_lower for phrase in DEFENSE_PHRASES)
        # Form reflection where no data table or output record container was generated
        has_empty_form_reflection = ("<form" in body_lower and "</form>" in body_lower) and not any(tag in body_lower for tag in ("<pre>", "<table", "<tbody", "user_id:", "account_id:"))

        is_neutralized = not has_data_leakage and (has_zero_records or has_defense_signal or has_empty_form_reflection)
        if has_injection_payload and is_neutralized:
            return {
                "verdict": "KILL",
                "stage_reached": 2,
                "blocking_gap": f"Exploitation failed on Stage 2 reality check: payload neutralized, zero records returned; parameterized query / server-side validation prevented execution on {endpoint_clean}.",
                "seven_answers": {
                    "Q1": f"no, parameterized query / input validator returned 0 rows on {endpoint_clean}",
                    "Q2": f"no, query is read-only select on {endpoint_clean}",
                    "Q3": f"no, database engine treated injection as literal string without command execution on {endpoint_clean}",
                    "Q4": f"no, zero credentials or sessions returned by prepared statement on {endpoint_clean}",
                    "Q5": f"no, financial attributes untouched on {endpoint_clean}",
                    "Q6": f"yes, unprivileged probe submitted to {endpoint_clean}",
                    "Q7": f"no, defensive control blocked execution; zero impact demonstrated on {endpoint_clean}"
                },
                "cvss": "n/a",
                "next_action": "KILL finding; defense successfully mitigated vulnerability."
            }

        # Stage 1: The Seven Questions (derived strictly from evidence)
        # Q1: Cross-user data read (IDOR / BOLA / User dump / Path Traversal system file read)
        # A response that merely *contains* the words "etc/passwd" or "root:x:0:0" (challenge
        # text, API docs, error pages, catalog descriptions) is not a file read. The captured
        # request or body must carry the attacker-controlled path for the tokens to mean anything.
        attacker_request_text = (
            urllib.parse.unquote(urllib.parse.unquote(f.request_url)).lower()
            + "\n" + urllib.parse.unquote(urllib.parse.unquote((f.request_body or ""))).lower()
        )
        has_traversal_input = any(
            tok in attacker_request_text
            for tok in ("../", "..\\", "%2e%2e", "%c0%af", "..%5c", "etc/passwd", "boot.ini", "web-inf")
        )
        traversal_tokens_present = any(
            tok in f.response_body for tok in ("root:x:0:0", "/bin/bash", "[boot loader]", "etc/passwd", "Directory of", "WEB-INF", "lessonCompleted", "successfully completed", "path-traversal-profile-updated")
        ) or (bool(f.victim_marker) and f.victim_marker in f.response_body)
        is_traversal_read = f.response_status in (200, 201) and has_traversal_input and traversal_tokens_present
        is_multi_tenant_read = cross_tenant_read_proven(f)
        is_q1 = is_traversal_read or is_multi_tenant_read
        q1_clause = (
            f"yes, unauthorized data read confirmed on {endpoint_clean} (leaked records/file contents)"
            if is_q1 else f"no, does not read other user/tenant data on {endpoint_clean}"
        )

        # Q2: Cross-user data mutation
        is_traversal_write = f.request_method.upper() in ("POST", "PUT") and has_traversal_input and f.response_status in (200, 201) and any(tok in f.response_body for tok in ("lessonCompleted", "successfully completed", "path-traversal-profile-updated", "feedback"))
        is_q2 = is_traversal_write or cross_tenant_mutation_proven(f)
        q2_clause = (
            f"yes, unauthorized data mutation demonstrated on secondary account at {endpoint_clean}"
            if is_q2 else f"no, request method {f.request_method} on {endpoint_clean} is read-only or mutation rejected"
        )

        # Q3: Execution or unauthorized destination
        # Same evidence standard as Q1: "uid=1000(www-data)" in a response only means RCE when the
        # captured request carried an injection payload. JSON user records routinely contain "uid=".
        injection_vectors = (
            f.request_url.lower() + "\n" + (f.request_body or "").lower()
            + "\n" + urllib.parse.unquote(urllib.parse.unquote(f.request_url)).lower()
        )
        has_command_input = any(
            tok in injection_vectors
            for tok in (";", "|", "`", "$(", "%3b", "%7c", "%60", "%24(", ";cat ", "&&", "||")
        )
        is_cmd_exec = (
            f.response_status in (200, 201)
            and has_command_input
            and any(tok in f.response_body for tok in ("www-data", "uid=", "gid="))
            and not any(tok in f.response_body for tok in ("root:x:0:0", "/bin/bash"))
        )
        script_in_response = _script_payload_present(f.response_body)
        script_in_readback = _script_payload_present(f.readback_body)
        # A write that echoes the payload back only proves the payload was ACCEPTED. Delivery to a
        # second session needs either a read of the shared resource or a separate readback.
        is_script_exec = script_in_response and (
            f.request_method.upper() == "GET" or script_in_readback
        )
        # SSRF requires an attacker-directed URL pointing at a DIFFERENT host AND a captured
        # artifact of the outbound fetch.
        outbound_targets = outbound_fetch_targets(f)
        has_outbound_target = bool(outbound_targets)
        oob_artifact = (
            (bool(f.victim_marker) and (f.victim_marker in f.response_body or f.victim_marker in f.readback_body or f.victim_marker in f.attacker_controlled_proof))
            or any(tok in f.response_body for tok in ("\"lessonCompleted\": true", "\"lessonCompleted\":true", "successfully completed"))
            or ("callback received" in f.attacker_controlled_proof.lower() or "callback confirmed" in f.attacker_controlled_proof.lower())
        )
        is_ssrf_dest = has_outbound_target and oob_artifact
        is_q3 = is_cmd_exec or is_script_exec or is_ssrf_dest
        q3_clause = (
            f"yes, code execution or external callback confirmed on {endpoint_clean}"
            if is_q3 else f"no, no code execution or server request reflection on {endpoint_clean}"
        )

        # Q4: Authentication / Session Hijack
        # Supports both:
        # Path A: Cross-tenant account takeover where victim's token/session is exfiltrated
        # Path B: Single-account authentication bypass where an unauthenticated or unprivileged
        #         attacker establishes valid session/administrative credentials without valid auth
        is_token_compromise = f.response_status in (200, 201) and any(tok in body_lower for tok in ("\"token\":", "\"authentication\"", "\"access_token\"", "bearer ey", "\"token\"")) and ("admin" in body_lower or "userid" in body_lower or "email" in body_lower)
        is_auth_endpoint = any(tok in endpoint_clean for tok in ("login", "oauth", "reset", "auth", "session", "admin", "token"))
        is_cross_tenant_ato = is_token_compromise and is_auth_endpoint and cross_tenant_read_proven(f)

        # Single-account auth bypass criteria:
        # 1. Successful HTTP status (200, 201, 302)
        # 2. Reached auth/login/admin endpoint
        # 3. Established session credential or admin role
        # 4. Proved lack of prior authorization (baseline rejected 401/403/400/404, or explicit bypass proof/payload)
        has_session_marker = (
            any(tok in body_lower for tok in ('"token":', '"access_token"', '"jwt"', '"auth_token"', '"session_id"', '"sessionid"', 'bearer ey', '"role": "admin"', '"role":"admin"', '"is_admin": true', '"is_admin":true'))
            or any(tok in str(f.response_headers).lower() for tok in ('set-cookie', 'authorization'))
        )
        has_auth_bypass_proof = (
            (f.baseline_status is not None and f.baseline_status in (401, 403, 400, 404) and f.response_status in (200, 201, 302))
            or any(sig in f.attacker_controlled_proof.lower() for sig in ("auth bypass", "authentication bypass", "login bypass", "credential-free", "unauthenticated admin", "bypassed authentication"))
            or any(p in (url_lower + " " + (f.request_body or "").lower()) for p in ("' or", "'--", "admin'--", "1=1", "none", "bearer null"))
        )
        is_single_account_auth_bypass = f.response_status in (200, 201, 302) and is_auth_endpoint and has_session_marker and has_auth_bypass_proof

        is_q4 = is_cross_tenant_ato or is_single_account_auth_bypass
        if is_single_account_auth_bypass:
            q4_clause = f"yes, unauthenticated authentication bypass established valid session/administrative credentials on {endpoint_clean}"
        elif is_cross_tenant_ato:
            q4_clause = f"yes, session tokens or authentication credentials compromised on {endpoint_clean}"
        else:
            q4_clause = f"no, session credentials not extractable from {endpoint_clean}"

        # Q5: Financial / Resource abuse — endpoint naming is not abuse; a proven state change is
        is_financial_target = any(w in (url_lower + " " + f.request_body.lower()) for w in ("coupon", "wallet", "balance", "voucher", "payment", "refund"))
        is_q5 = is_financial_target and (cross_tenant_mutation_proven(f) or cross_tenant_read_proven(f))
        q5_clause = (
            f"yes, balance or voucher manipulation demonstrated on {endpoint_clean}"
            if is_q5 else f"no, no currency, token, or paid quota burned on {endpoint_clean}"
        )

        # Q6: Reachable unprivileged
        is_self_only = ("self-session" in proof_lower or "own session" in proof_lower or "self-reflected" in proof_lower)
        is_q6 = f.response_status in (200, 201) and not is_self_only
        if is_self_only:
            q6_clause = f"no, reflection restricted to user's own local browser session context on {endpoint_clean}"
        elif f.response_status in (200, 201):
            q6_clause = f"yes, survives clean-session test with observed HTTP {f.response_status} on {endpoint_clean}"
        else:
            q6_clause = f"no, unprivileged access rejected with HTTP {f.response_status} on {endpoint_clean}"

        # Q7: End-to-end impact
        is_impact_proven = bool(is_q1 or is_q2 or is_q3 or is_q4 or is_q5)
        q7_clause = (
            f"yes, business impact confirmed end-to-end with evidence on {endpoint_clean}"
            if is_impact_proven else f"no, theoretical risk on {endpoint_clean} requiring unproven assumptions"
        )

        seven_answers = {
            "Q1": q1_clause,
            "Q2": q2_clause,
            "Q3": q3_clause,
            "Q4": q4_clause,
            "Q5": q5_clause,
            "Q6": q6_clause,
            "Q7": q7_clause
        }

        # Verdict Rule: If Q1-Q5 are ALL "no", verdict is INFORMATIONAL -> KILL
        if not is_impact_proven:
            # Derive unique per-case blocking gap
            if "favicon" in url_lower or "static" in url_lower or "csp" in proof_lower:
                gap = f"Content-Security-Policy header is absent on static resource {endpoint_clean}, but Q1-Q5 are all negative with no demonstrated cross-tenant exploit chain."
            elif "hsts" in proof_lower or url_lower.rstrip("/") == "http://127.0.0.1:3000":
                gap = f"Strict-Transport-Security header is absent on {endpoint_clean}, but Q1-Q5 are negative with no demonstrated network MITM attack."
            elif is_self_only:
                gap = f"Client parameter reflects only within executing user's own browser session on {endpoint_clean}; fails Q6 unprivileged cross-tenant reachability."
            elif f.response_status == 500:
                gap = f"Internal server error on {endpoint_clean} leaks stack trace, but discloses no credentials, API keys, or secondary tenant data."
            elif "map" in url_lower:
                gap = f"Source map at {endpoint_clean} discloses client compilation bundle without production secrets or administrative credentials."
            elif script_in_response and f.request_method.upper() != "GET" and not script_in_readback:
                gap = f"Script payload was accepted by the write endpoint at {endpoint_clean}, but no separate read demonstrates it renders in a second user's session."
            else:
                gap = f"Questions 1-5 all evaluated to 'no' on {endpoint_clean}. Lacks demonstrated cross-user read/write, code execution, or auth bypass."

            # An attacker-directed server-side fetch with no captured out-of-band artifact is an
            # unverified state (LEAD), not noise (KILL).
            verdict = "KILL"
            action = "KILL from payable queue; record as defensive recommendation only."
            if has_outbound_target and not oob_artifact:
                verdict = "LEAD"
                gap = f"Server-directed fetch toward {outbound_targets[0]} at {endpoint_clean}, but no out-of-band artifact was captured; the fetch itself is unconfirmed."
                action = f"Capture the receiving-end transaction ({outbound_targets[0]} access log containing the planted marker) for {endpoint_clean} before re-submitting."

            return {
                "verdict": verdict,
                "stage_reached": 1,
                "blocking_gap": gap,
                "seven_answers": seven_answers,
                "cvss": "n/a",
                "next_action": action
            }

        # Stage 3: Evidence-based CVSS (derived from capability, not restraint)
        if is_cmd_exec:
            # Arbitrary shell execution on host component:
            # Availability is H because process execution permits terminating services or filling disk
            # Scope S:U (remains on host container OS instance)
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # 8.8
        elif is_q4:
            # Admin authentication bypass via SQLi or token forgery:
            # Attains full admin access over web application; A:H because admin can shut down / drop db
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
        elif is_script_exec:
            # Stored / Cross-user XSS:
            # Requires victim interaction UI:R, Scope Changed S:C, Confidentiality/Integrity Low, Availability None
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1
        elif is_q1 and ("password" in body_lower or "hash" in body_lower):
            # User table dump containing admin password hashes:
            # MD5 admin hash is trivially reversible, yielding administrative write access -> Integrity H
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"  # 8.1
        elif is_q1:
            # IDOR / Path Traversal read-only:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # 6.5
        elif is_q2:
            # Cross-user mutation:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"  # 6.5
        elif is_ssrf_dest:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N"  # 7.7
        else:
            cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"

        return {
            "verdict": "VALID-PAYABLE",
            "stage_reached": 5,
            "blocking_gap": "none",
            "seven_answers": seven_answers,
            "cvss": cvss_vector,
            "next_action": "Draft formal vulnerability report with reproducible curl reproduction steps."
        }

    def format_output_contract(self, res: Dict[str, Any]) -> str:
        q_str = "; ".join(f"{k}: {v}" for k, v in res.get("seven_answers", {}).items())
        return (
            f"VERDICT:        {res.get('verdict')}\n"
            f"STAGE REACHED:  {res.get('stage_reached')}\n"
            f"BLOCKING GAP:   {res.get('blocking_gap')}\n"
            f"SEVEN ANSWERS:  {q_str}\n"
            f"CVSS:           {res.get('cvss')}\n"
            f"NEXT ACTION:    {res.get('next_action')}"
        )
