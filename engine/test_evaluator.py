"""
Unit Tests for TriageEvaluator & Scope Guard.
Tests:
- Scope matching & refusal
- Deny list violations
- Stage 0 evidence drops
- Stage 1 Impact Seven Questions
- Full OUTPUT CONTRACT compliance
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from engine.triage_evaluator import TriageEvaluator, CandidateFinding

def test_scope_refusal():
    e = TriageEvaluator()
    f = CandidateFinding(
        title="Unverified XSS",
        program="NonExistentProgramXYZ",
        target_host="random.evil.com",
        request_method="GET",
        request_url="https://random.evil.com/search?q=test",
        response_status=200
    )
    res = e.evaluate(f)
    assert res["verdict"] == "KILL"
    assert "OUT OF SCOPE" in res["blocking_gap"]
    print("[+] Test Scope Refusal: PASS")

def test_deny_list_refusal():
    e = TriageEvaluator()
    f = CandidateFinding(
        title="SSRF to AWS Metadata",
        program="Bugcrowd",
        target_host="169.254.169.254",
        request_method="GET",
        request_url="http://169.254.169.254/latest/meta-data/",
        response_status=200
    )
    res = e.evaluate(f)
    assert res["verdict"] == "KILL"
    assert "PERMANENT_DENY_VIOLATION" in res["blocking_gap"]
    print("[+] Test Deny List Refusal: PASS")

def test_idor_payable():
    e = TriageEvaluator()
    # Payable only because two captured transactions differ: the executing account's own invoice
    # (control) does not contain the identifier disclosed by the object reference it does not own.
    f = CandidateFinding(
        title="IDOR in GET /api/v1/users/1001/invoices",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/api/v1/users/1001/invoices",
        response_status=200,
        response_body='{"invoice_id": "INV-1001-7f3a9c2b", "amount": 450, "wallet": "0xabc123"}',
        baseline_status=200,
        baseline_body='{"invoice_id": "INV-2002-1a1a1a1a", "amount": 12, "wallet": "0xown999"}',
        victim_marker='"invoice_id": "INV-1001-7f3a9c2b"',
        second_account_tested=True,
        attacker_controlled_proof="Executed from a session authenticated as user 2002",
        is_lab=True
    )
    res = e.evaluate(f)
    assert res["verdict"] == "VALID-PAYABLE"
    assert res["stage_reached"] == 5
    assert "CVSS:3.1" in res["cvss"]
    print("[+] Test IDOR Payable: PASS")

def test_asserted_cross_account_without_evidence_is_not_payable():
    """
    Regression for R1: a benign response body plus an asserted second-account boolean and a
    narrative proof string used to be certified VALID-PAYABLE. Assertions are not evidence.
    """
    e = TriageEvaluator()
    f = CandidateFinding(
        title="IDOR in GET /api/v1/users/1001/invoices",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/api/v1/users/1001/invoices",
        response_status=200,
        response_body='{"invoice_id": 1001, "amount": 450}',
        second_account_tested=True,
        attacker_controlled_proof="Secondary account retrieved victim data",
        is_lab=True
    )
    res = e.evaluate(f)
    assert res["verdict"] != "VALID-PAYABLE", f"assertion-only finding must not pay out, got {res['verdict']}"
    assert res["stage_reached"] <= 1
    print("[+] Test Asserted Cross-Account Not Payable: PASS")

def test_missing_header_informational():
    e = TriageEvaluator()
    f = CandidateFinding(
        title="Missing Content-Security-Policy Header",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/about",
        response_status=200,
        response_body="<html>...</html>",
        second_account_tested=False,
        attacker_controlled_proof="Header is absent from HTTP response",
        is_lab=True
    )
    res = e.evaluate(f)
    assert res["verdict"] in ("KILL", "VALID-INFORMATIONAL")
    assert res["stage_reached"] == 1
    print("[+] Test Missing Header Informational: PASS")

def test_firewall_and_scope_hardening():
    e = TriageEvaluator()
    # 1. Hostname-based loopback bypass (e.g. localhost:5432)
    denied, msg = e.check_deny_list("localhost:5432", is_lab=True)
    assert denied is True, "localhost:5432 must be DENIED"
    assert "PERMANENT_DENY_VIOLATION" in msg

    # 2. nip.io metadata bypass
    denied, msg = e.check_deny_list("169.254.169.254.nip.io", is_lab=False)
    assert denied is True, "169.254.169.254.nip.io must be DENIED"
    assert "PERMANENT_DENY_VIOLATION" in msg

    # 3. Lab non-carveout loopback port
    denied, msg = e.check_deny_list("127.0.0.1:8080", is_lab=True)
    assert denied is True, "127.0.0.1:8080 must be DENIED"
    assert "PERMANENT_DENY_VIOLATION" in msg

    # 4. Authorized lab carveout port (3000)
    denied, msg = e.check_deny_list("localhost:3000", is_lab=True)
    assert denied is False, "localhost:3000 with is_lab=True must be CLEAN"

    # 5. Loose substring matching rejection (S1)
    in_scope, msg = e.verify_scope("a", "random.evil.com", is_lab=False)
    assert in_scope is False, "Single letter 'a' substring must NOT match any program"
    assert "OUT OF SCOPE" in msg

    # 6. Unadmitted / Unattested program is refused
    in_scope, msg = e.verify_scope("1win", "1win.com", is_lab=False)
    assert in_scope is False, "Unattested program must be REFUSED"
    assert "OUT OF SCOPE" in msg

    # 7. Operator-attested program passes
    e.asset_map["Mock Attested Program"] = {
        "status": "OPERATOR_AUTHORIZED",
        "source_url": "https://example.com/bounty",
        "policy_snapshot_path": str(Path(__file__).resolve()),
        "automated_scanning_permitted": True,
        "in_scope_assets": ["target.example.com"],
        "authorized_by": {
            "operator_handle": "qa-lead",
            "timestamp": "2026-10-29T00:00:00Z",
            "operator_quote": "Explicitly authorizing target.example.com for test verification"
        }
    }
    e._programs_cache.append({"name": "Mock Attested Program"})
    in_scope, msg = e.verify_scope("Mock Attested Program", "target.example.com", is_lab=False)
    assert in_scope is True, f"Operator-attested target must pass, got {msg}"

    # 8. Program with status REFERENCE_ONLY or missing authorized_by is refused
    e.asset_map["Mock Reference Program"] = {
        "status": "REFERENCE_ONLY",
        "source_url": "https://example.com/bounty",
        "in_scope_assets": ["ref.example.com"]
    }
    e._programs_cache.append({"name": "Mock Reference Program"})
    in_scope, msg = e.verify_scope("Mock Reference Program", "ref.example.com", is_lab=False)
    assert in_scope is False, "REFERENCE_ONLY target must be refused"
    assert "OUT OF SCOPE" in msg

    # 9. Automated scanning refused when automated_scanning_permitted is False or missing
    e.asset_map["Mock Manual Only Program"] = {
        "status": "OPERATOR_AUTHORIZED",
        "source_url": "https://example.com/bounty",
        "policy_snapshot_path": str(Path(__file__).resolve()),
        "automated_scanning_permitted": False,
        "in_scope_assets": ["manual.example.com"],
        "authorized_by": {
            "operator_handle": "qa-lead",
            "timestamp": "2026-10-29T00:00:00Z",
            "operator_quote": "Authorizing manual testing only"
        }
    }
    e._programs_cache.append({"name": "Mock Manual Only Program"})
    in_scope, msg = e.verify_scope("Mock Manual Only Program", "manual.example.com", is_lab=False, automated=False)
    assert in_scope is True, f"Manual request must pass, got {msg}"
    in_scope, msg = e.verify_scope("Mock Manual Only Program", "manual.example.com", is_lab=False, automated=True)
    assert in_scope is False, "Automated scanning must be REFUSED when automated_scanning_permitted is False"
    assert "automated_scanning_permitted" in msg

    # 10. Missing policy_snapshot_path refuses admission entirely
    e.asset_map["Mock No Snapshot Program"] = {
        "status": "OPERATOR_AUTHORIZED",
        "source_url": "https://example.com/bounty",
        "automated_scanning_permitted": True,
        "in_scope_assets": ["nosnap.example.com"],
        "authorized_by": {
            "operator_handle": "qa-lead",
            "timestamp": "2026-10-29T00:00:00Z",
            "operator_quote": "Missing policy snapshot"
        }
    }
    e._programs_cache.append({"name": "Mock No Snapshot Program"})
    in_scope, msg = e.verify_scope("Mock No Snapshot Program", "nosnap.example.com", is_lab=False, automated=False)
    assert in_scope is False, "Missing policy_snapshot_path must refuse admission entirely"
    assert "policy_snapshot_path" in msg

    print("[+] Test Firewall & Scope Hardening (D1, S1, S2, Operator Attestation Gate): PASS")

def test_stage2_generalized_neutralized_sqli():
    """
    Stage 2 Reality Check generalization:
    Verifies that non-lab, real-world target phrasing (JSON APIs, enterprise error strings,
    type mismatch defenses, zero-match phrasing) correctly triggers Stage 2 KILL.
    """
    e = TriageEvaluator()

    # Case A: Enterprise REST API returning JSON empty results array
    f_json = CandidateFinding(
        title="SQL Injection Probe in Product Catalog API",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/api/v2/products?filter=%27+OR+1%3D1--",
        response_status=200,
        response_body='{"status": "ok", "total_count": 0, "results": []}',
        attacker_controlled_proof="Query payload echoed with empty JSON dataset",
        is_lab=True
    )
    res_a = e.evaluate(f_json)
    assert res_a["verdict"] == "KILL", f"Empty JSON results must trigger Stage 2 KILL, got {res_a['verdict']}"
    assert res_a["stage_reached"] == 2
    assert "Stage 2 reality check" in res_a["blocking_gap"]

    # Case B: Enterprise parameterized defense / type enforcement
    f_type = CandidateFinding(
        title="Union SQL Injection Probe in Billing Search",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/v1/invoices?account_id=123+UNION+SELECT+null,null",
        response_status=400,
        response_body='{"error": "Validation failed: invalid input syntax for type integer: malformed parameter"}',
        attacker_controlled_proof="Server returned validation error without data leakage",
        is_lab=True
    )
    res_b = e.evaluate(f_type)
    assert res_b["verdict"] == "KILL", f"Type enforcement must trigger Stage 2 KILL, got {res_b['verdict']}"
    assert res_b["stage_reached"] == 2
    assert "Stage 2 reality check" in res_b["blocking_gap"]

    # Case C: Diverse natural language zero-row phrasing in HTML portal
    f_html = CandidateFinding(
        title="Blind SQL Injection Probe in Medical Portal",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/portal/records?patient_id=%27+or+%271%27=%271",
        response_status=200,
        response_body='<div class="results-box"><p>No matching records found for criteria.</p></div>',
        attacker_controlled_proof="Zero records returned by database search",
        is_lab=True
    )
    res_c = e.evaluate(f_html)
    assert res_c["verdict"] == "KILL", f"Zero matching records must trigger Stage 2 KILL, got {res_c['verdict']}"
    assert res_c["stage_reached"] == 2
    assert "Stage 2 reality check" in res_c["blocking_gap"]

    print("[+] Test Stage 2 Generalized Neutralized Injections: PASS")

def test_single_account_auth_bypass():
    """
    Q4 Authentication / Session Hijack:
    Verifies that a genuine single-account authentication bypass (no secondary account /
    no victim_marker involved) satisfies Q4 and reaches VALID-PAYABLE when unauthenticated
    baseline check was rejected (401/403) and the bypass obtains valid admin session tokens.
    """
    e = TriageEvaluator()

    f_bypass = CandidateFinding(
        title="Single-Account Authentication Bypass on Administrative Login",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="POST",
        request_url="http://127.0.0.1:3000/api/v1/admin/login",
        request_headers={"Content-Type": "application/json"},
        request_body='{"username": "admin\'--", "password": "x"}',
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"status": "authenticated", "role": "admin", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.signature", "is_admin": true}',
        baseline_status=401,
        baseline_body='{"error": "Unauthorized: invalid credentials"}',
        second_account_tested=False,
        victim_marker="",
        attacker_controlled_proof="Unauthenticated login bypass established active administrative session token; baseline 401 rejected",
        is_lab=True
    )

    res = e.evaluate(f_bypass)
    assert res["verdict"] == "VALID-PAYABLE", f"Genuine single-account auth bypass must be VALID-PAYABLE, got {res['verdict']}"
    assert res["stage_reached"] == 5
    assert "yes" in res["seven_answers"]["Q4"]
    assert "authentication bypass" in res["seven_answers"]["Q4"]
    assert "CVSS:3.1" in res["cvss"]
    print("[+] Test Single-Account Auth Bypass (Q4): PASS")

def test_reporter_verdict_guard():
    """
    ReportGenerator Guard:
    Verifies that ReportGenerator.generate_report() refuses and returns an explanatory
    string unless the triage verdict is explicitly 'VALID-PAYABLE'.
    """
    from core.reporter import ReportGenerator

    finding = CandidateFinding(
        title="Informational Server Banner",
        program="local_lab",
        target_host="127.0.0.1",
        request_method="GET",
        request_url="http://127.0.0.1:3000/",
        response_status=200,
        response_body="<html>Home</html>",
        is_lab=True
    )

    # 1. Refusal on KILL
    kill_triage = {
        "verdict": "KILL",
        "stage_reached": 1,
        "blocking_gap": "No cross-tenant data read or mutation observed.",
        "cvss": "n/a"
    }
    report_kill = ReportGenerator.generate_report(finding, kill_triage)
    assert report_kill.startswith("[REPORT_GENERATION_REFUSED]"), f"Must refuse report for KILL, got: {report_kill}"
    assert "KILL" in report_kill

    # 2. Refusal on LEAD
    lead_triage = {
        "verdict": "LEAD",
        "stage_reached": 0,
        "blocking_gap": "Missing attacker controlled proof.",
        "cvss": "n/a"
    }
    report_lead = ReportGenerator.generate_report(finding, lead_triage)
    assert report_lead.startswith("[REPORT_GENERATION_REFUSED]"), f"Must refuse report for LEAD, got: {report_lead}"
    assert "LEAD" in report_lead

    # 3. Accepted on VALID-PAYABLE
    payable_triage = {
        "verdict": "VALID-PAYABLE",
        "stage_reached": 5,
        "blocking_gap": "none",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    }
    report_payable = ReportGenerator.generate_report(finding, payable_triage)
    assert not report_payable.startswith("[REPORT_GENERATION_REFUSED]")
    assert "# [Vulnerability Report]" in report_payable
    assert "curl -i -s -k" in report_payable

    print("[+] Test ReportGenerator Verdict Guard: PASS")

if __name__ == "__main__":
    test_scope_refusal()
    test_deny_list_refusal()
    test_idor_payable()
    test_asserted_cross_account_without_evidence_is_not_payable()
    test_missing_header_informational()
    test_firewall_and_scope_hardening()
    test_stage2_generalized_neutralized_sqli()
    test_single_account_auth_bypass()
    test_reporter_verdict_guard()
    print("\n[+] All TriageEvaluator unit tests PASSED successfully!")
