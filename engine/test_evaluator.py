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

    print("[+] Test Firewall & Scope Hardening (D1, S1, S2, Operator Attestation Gate): PASS")

if __name__ == "__main__":
    test_scope_refusal()
    test_deny_list_refusal()
    test_idor_payable()
    test_asserted_cross_account_without_evidence_is_not_payable()
    test_missing_header_informational()
    test_firewall_and_scope_hardening()
    print("\n[+] All TriageEvaluator unit tests PASSED successfully!")
