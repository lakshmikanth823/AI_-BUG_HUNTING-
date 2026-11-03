"""
Regression tests for the cross-tenant authorization probe.

Covers both failure directions: a real missing-authorization check must become a payable
finding from captured bytes, and an app that enforces ownership must NOT produce one.
"""

import io
import json
import os
import sys
import urllib.request
import contextlib

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from core.recon import ReconEngine
from core.scope_guard import RequestBudgetTracker
from engine.triage_evaluator import TriageEvaluator
from engine.authz_probe import AuthzProbe, ProbeRefused
import lab.authz_fixture_server as fixture

PASS = 0
FAIL = 0


def chk(cond: bool, label: str):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {label}")
    else:
        FAIL += 1
        print(f"[FAIL] {label}")


def load_probe():
    with open(os.path.join(ROOT_DIR, "data", "authz_probes.json"), encoding="utf-8") as fh:
        return json.load(fh)["probes"][0]


def run_probe(cfg, port=8888, budget=150):
    tracker = RequestBudgetTracker(max_budget=budget)
    findings = AuthzProbe(ReconEngine()).run(
        f"http://127.0.0.1:{port}", cfg, budget_tracker=tracker, is_lab=True
    )
    return findings[0], tracker


def main():
    httpd = fixture.serve(fixture.PORT)
    try:
        # --- 1. vulnerable app -> payable from captured evidence ---
        fixture.ENFORCE_OWNERSHIP = False
        cfg = load_probe()
        f, tracker = run_probe(cfg)
        res = TriageEvaluator().evaluate(f)
        chk(res["verdict"] == "VALID-PAYABLE", f"unenforced ownership yields VALID-PAYABLE (got {res['verdict']})")
        chk(f.victim_marker and len(f.victim_marker) >= 8, "marker captured and >= 8 chars")
        chk(f.victim_marker in f.response_body, "marker present in attacker capture")
        chk(f.victim_marker not in f.baseline_body, "marker absent from attacker's own control response")
        chk(tracker.current_count <= 12, f"probe stayed inside budget ({tracker.current_count} requests)")

        # --- 2. secured app -> must NOT claim a finding ---
        fixture.ENFORCE_OWNERSHIP = True
        cfg2 = load_probe()
        f2, _ = run_probe(cfg2)
        res2 = TriageEvaluator().evaluate(f2)
        chk(res2["verdict"] == "KILL", f"enforced ownership yields KILL (got {res2['verdict']})")
        chk("403" in res2["blocking_gap"] or "absent" in f2.attacker_controlled_proof.lower(),
            "no-payment reasoning states the marker was not exposed")

        # --- 3. operator attestation is load-bearing ---
        fixture.ENFORCE_OWNERSHIP = False
        cfg3 = load_probe()
        cfg3["accounts_owned_by_operator"] = False
        try:
            run_probe(cfg3)
            chk(False, "probe must refuse when accounts_owned_by_operator is not true")
        except ProbeRefused as exc:
            chk("accounts_owned_by_operator" in str(exc), "probe refuses without operator attestation")

        # --- 4. destination outside the lab carve-out is refused, no request sent ---
        cfg4 = load_probe()
        trk4 = RequestBudgetTracker(max_budget=50)
        try:
            AuthzProbe(ReconEngine()).run("http://127.0.0.1:8890", cfg4, budget_tracker=trk4, is_lab=True)
            chk(False, "probe must refuse a loopback port outside the authorized carve-out")
        except ProbeRefused as exc:
            chk("8890" in str(exc) or "EGRESS_BLOCKED" in str(exc) or "carve-out" in str(exc),
                f"port outside carve-out refused fail-closed ({str(exc)[:80]})")
            chk(trk4.current_count <= 1,
                f"at most one conservative charge for a refused destination ({trk4.current_count})")

        # --- 5. bad credentials -> no silent success ---
        cfg5 = load_probe()
        cfg5["victim"]["login"]["body"] = '{"username":"alice","password":"wrong"}'
        try:
            run_probe(cfg5)
            chk(False, "probe must refuse when a session cannot be established")
        except ProbeRefused as exc:
            chk("no token" in str(exc) or "401" in str(exc), "login failure surfaces instead of fabricating a session")

        # --- 6. unresolved template placeholder is refused ---
        cfg6 = load_probe()
        cfg6["cross_tenant_request"]["path"] = "/documents/{not_a_real_value}"
        try:
            run_probe(cfg6)
            chk(False, "probe must refuse on an unresolved placeholder")
        except ProbeRefused as exc:
            chk("placeholder" in str(exc), "unresolved placeholder refused")

    finally:
        httpd.shutdown()
    print("=" * 60)
    print(f"AUTHZ PROBE REGRESSIONS: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
