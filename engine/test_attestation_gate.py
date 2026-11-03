"""
Unit Tests for Operator Attestation & Automated Scanning Gate.
Enforces:
1. Entry with complete attestation but 'automated_scanning_permitted': False (or missing)
   refuses automated tool calls (ffuf, nuclei, recon, scanner_bridge, authz_probe),
   while manual requests may pass.
2. Removing 'policy_snapshot_path' refuses admission entirely.
3. Specifying a non-existent policy snapshot file refuses admission entirely.
4. 'flipkart' block is completely absent from data/in_scope_assets.json.
"""

import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.scope_guard import ScopeGuard, admission_failure
from engine.triage_evaluator import TriageEvaluator
from engine.scanner_bridge import ScannerBridge
from engine.authz_probe import AuthzProbe, ProbeRefused
from core.recon import ReconEngine


def test_attestation_and_automated_gate():
    print("[*] Running Attestation & Automated Scanning Gate Tests...")

    # Create a real policy snapshot file on disk for the test
    with tempfile.NamedTemporaryFile("w", delete=False, suffix="_policy.txt", encoding="utf-8") as tf:
        tf.write("Policy Page: Testing is permitted under HackerOne safe harbor.\nAutomated scanning is prohibited.\n")
        temp_policy_path = tf.name

    try:
        evaluator = TriageEvaluator()
        guard = ScopeGuard()

        base_entry = {
            "status": "OPERATOR_AUTHORIZED",
            "source_url": "https://example.com/policy",
            "policy_snapshot_path": temp_policy_path,
            "in_scope_assets": ["target.example.com"],
            "authorized_by": {
                "operator_handle": "lead-hunter",
                "timestamp": "2026-11-03T00:00:00Z",
                "operator_quote": "Explicit authorization with local policy text verified."
            }
        }

        # -------------------------------------------------------------
        # 1. 'automated_scanning_permitted': False
        # -------------------------------------------------------------
        entry_auto_false = dict(base_entry)
        entry_auto_false["automated_scanning_permitted"] = False

        # Manual single request passes admission
        err_manual = admission_failure(entry_auto_false, "TestProgram", automated=False)
        assert err_manual == "", f"Manual admission should succeed, got: {err_manual}"

        # Automated request is REFUSED by admission_failure
        err_auto = admission_failure(entry_auto_false, "TestProgram", automated=True)
        assert "automated_scanning_permitted" in err_auto, f"Expected automated scanning refusal, got: {err_auto}"

        # Verify via TriageEvaluator.verify_scope
        evaluator.asset_map["TestProgram"] = entry_auto_false
        evaluator._programs_cache.append({"name": "TestProgram"})

        manual_ok, manual_msg = evaluator.verify_scope("TestProgram", "target.example.com", is_lab=False, automated=False)
        assert manual_ok is True, f"Manual request must pass, got: {manual_msg}"

        auto_ok, auto_msg = evaluator.verify_scope("TestProgram", "target.example.com", is_lab=False, automated=True)
        assert auto_ok is False, "Automated request must be REFUSED"
        assert "automated_scanning_permitted" in auto_msg

        # Verify via ScopeGuard.verify_target
        guard.asset_map["TestProgram"] = entry_auto_false
        guard.programs.append({"name": "TestProgram", "platform": "HackerOne"})

        sg_auto_ok, sg_auto_msg = guard.verify_target("https://target.example.com", "TestProgram", is_lab=False, automated=True)
        assert sg_auto_ok is False, "ScopeGuard must refuse automated target"
        assert "automated_scanning_permitted" in sg_auto_msg

        # Verify ScannerBridge (ffuf & nuclei) refuses when automated_scanning_permitted is False
        bridge = ScannerBridge(evaluator=evaluator)
        ffuf_res = bridge.run_ffuf("https://target.example.com/FUZZ", __file__, program="TestProgram", is_lab=False)
        assert ffuf_res["status"] == "BLOCKED"
        assert "automated_scanning_permitted" in ffuf_res["reason"]

        nuclei_res = bridge.run_nuclei_triage("https://target.example.com", program="TestProgram", is_lab=False, template_id="cve-test")
        assert nuclei_res[0]["verdict"] == "KILL"
        assert "automated_scanning_permitted" in nuclei_res[0]["blocking_gap"]

        # Verify ReconEngine refuses automated fetch
        recon = ReconEngine(scope_guard=guard)
        recon_res = recon.fetch_endpoint("https://target.example.com/test", program="TestProgram", is_lab=False)
        assert recon_res["status"] is None
        assert "PROVENANCE_BLOCKED" in recon_res["error"]
        assert "automated_scanning_permitted" in recon_res["error"]

        # Verify AuthzProbe raises ProbeRefused on live program when automated scanning is False
        probe = AuthzProbe(recon=recon)
        authz_config = {
            "name": "test_authz",
            "title": "IDOR test",
            "program": "TestProgram",
            "accounts_owned_by_operator": True,
            "attacker": {"label": "att", "login": {"method": "GET", "path": "/login", "extract": {}}},
            "victim": {"label": "vic", "login": {"method": "GET", "path": "/login", "extract": {}}}
        }
        try:
            probe.run("https://target.example.com", authz_config, is_lab=False)
            assert False, "AuthzProbe should have raised ProbeRefused"
        except ProbeRefused as e:
            assert "automated_scanning_permitted" in str(e) or "probe automation refused" in str(e)

        print("[PASS] 1. automated_scanning_permitted: False correctly blocks ffuf, nuclei, recon, and authz_probe.")

        # -------------------------------------------------------------
        # 2. 'automated_scanning_permitted': Missing / None
        # -------------------------------------------------------------
        entry_auto_missing = dict(base_entry)
        entry_auto_missing.pop("automated_scanning_permitted", None)

        err_missing = admission_failure(entry_auto_missing, "TestProgram", automated=True)
        assert "automated_scanning_permitted" in err_missing, f"Missing automated_scanning_permitted must refuse automated: {err_missing}"

        evaluator.asset_map["TestProgram"] = entry_auto_missing
        auto_ok, auto_msg = evaluator.verify_scope("TestProgram", "target.example.com", is_lab=False, automated=True)
        assert auto_ok is False, "Missing automated_scanning_permitted must refuse automated call"

        print("[PASS] 2. Missing automated_scanning_permitted correctly refuses automated requests.")

        # -------------------------------------------------------------
        # 3. Removing 'policy_snapshot_path' refuses admission entirely
        # -------------------------------------------------------------
        entry_no_snapshot = dict(base_entry)
        entry_no_snapshot["automated_scanning_permitted"] = True
        del entry_no_snapshot["policy_snapshot_path"]

        # Manual single request must now ALSO be refused (complete admission refusal)
        err_no_snap_manual = admission_failure(entry_no_snapshot, "TestProgram", automated=False)
        assert "policy_snapshot_path" in err_no_snap_manual, f"Expected policy_snapshot_path failure, got: {err_no_snap_manual}"

        err_no_snap_auto = admission_failure(entry_no_snapshot, "TestProgram", automated=True)
        assert "policy_snapshot_path" in err_no_snap_auto

        evaluator.asset_map["TestProgram"] = entry_no_snapshot
        ok, msg = evaluator.verify_scope("TestProgram", "target.example.com", is_lab=False, automated=False)
        assert ok is False, "Missing policy_snapshot_path must refuse admission entirely"
        assert "policy_snapshot_path" in msg

        print("[PASS] 3. Removing policy_snapshot_path refuses admission entirely (both manual and automated).")

        # -------------------------------------------------------------
        # 4. Non-existent snapshot path refuses admission
        # -------------------------------------------------------------
        entry_bad_snapshot = dict(base_entry)
        entry_bad_snapshot["policy_snapshot_path"] = "data/non_existent_policy_file_xyz.txt"

        err_bad_snap = admission_failure(entry_bad_snapshot, "TestProgram", automated=False)
        assert "does not exist on disk" in err_bad_snap

        print("[PASS] 4. Non-existent policy_snapshot_path file refuses admission.")

        # -------------------------------------------------------------
        # 5. Flipkart entry verified absent from in_scope_assets.json
        # -------------------------------------------------------------
        real_guard = ScopeGuard()
        assert "flipkart" not in real_guard.asset_map, "flipkart must be completely removed from in_scope_assets.json"
        for k in real_guard.asset_map.keys():
            assert "flipkart" not in k.lower(), f"No flipkart block permitted, found {k}"

        flip_ok, flip_msg = real_guard.verify_target("https://www.flipkart.com", "Flipkart", is_lab=False)
        assert flip_ok is False, "Flipkart must be refused as unadmitted"
        assert "OUT OF SCOPE" in flip_msg

        print("[PASS] 5. Flipkart block completely absent from in_scope_assets.json; live target rejected.")

    finally:
        if Path(temp_policy_path).exists():
            Path(temp_policy_path).unlink()

    print("\n[+] ALL ATTESTATION GATE TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    test_attestation_and_automated_gate()
