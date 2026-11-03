"""
Regression tests for the scope firewall and blast-radius controls (R2, R3).

Loopback-only: the single live fuzz test targets the Juice Shop lab container on 127.0.0.1:3000.
Everything else exercises the gate without sending a packet to the denied destination.
"""

import socket
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.scope_guard import gate_destination, pinned_dns, resolve_destination, RequestBudgetTracker
from engine.scanner_bridge import ScannerBridge
from engine.triage_evaluator import TriageEvaluator

LAB_URL = "http://127.0.0.1:3000"

failures = []


def check(name, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def test_fail_closed_dns():
    """A name that cannot be resolved must be denied, never treated as 'nothing to block'."""
    gated = gate_destination("nonexistent-xyz-abc.invalid:5432", is_lab=False)
    check("NXDOMAIN (non-lab) is denied fail-closed", gated["denied"] is True, str(gated))
    check("NXDOMAIN denial names the resolution failure",
          "DNS_RESOLUTION" in gated["reason"], gated["reason"])
    check("NXDOMAIN exposes no usable addresses", gated["ips"] == [], str(gated["ips"]))


def test_rebinding_style_denials():
    """Hostnames that encode a forbidden address are denied before any connection."""
    for dest in ("169.254.169.254.nip.io", "127.0.0.1.sslip.io", "10.0.0.5.example.com"):
        gated = gate_destination(dest, is_lab=False)
        check(f"{dest} is denied", gated["denied"] is True, gated["reason"])


def test_lab_carve_out_survives():
    for dest in ("localhost:3000", "127.0.0.1:3000", "[::1]:3000"):
        gated = gate_destination(dest, is_lab=True)
        check(f"lab carve-out {dest} stays clean", gated["denied"] is False, gated["reason"])
    gated = gate_destination("localhost:5432", is_lab=True)
    check("lab host outside the port carve-out is denied", gated["denied"] is True, gated["reason"])


def test_dns_pinning():
    """pinned_dns must return only the gate-validated address for the host it pinned."""
    ips, err = resolve_destination("localhost")
    check("localhost resolves", err is None and ips, str(err))
    with pinned_dns("localhost", ["127.0.0.1"]):
        got = sorted({addr[4][0] for addr in socket.getaddrinfo("localhost", 3000)})
    check("pinned host returns exactly the validated address", got == ["127.0.0.1"], str(got))

    other = sorted({addr[4][0] for addr in socket.getaddrinfo("127.0.0.1", 3000)})
    check("resolver restored after the pinned context exits", other == ["127.0.0.1"], str(other))


def test_triage_does_not_resolve():
    """
    Triage judges captured evidence; it must not emit DNS for the host a finding describes.
    An unresolvable, non-literal hostname with an out-of-scope program must be refused on
    provenance, not on a resolution error.
    """
    e = TriageEvaluator()
    res = e.evaluate(_stub_finding("https://host-that-need-not-exist-qa.invalid/x"))
    check("triage refuses on provenance rather than resolving",
          "OUT OF SCOPE" in res["blocking_gap"], res["blocking_gap"])


def _stub_finding(url):
    from engine.triage_evaluator import CandidateFinding
    return CandidateFinding(
        title="Stub", program="", target_host=urllib.parse.urlparse(url).netloc,
        request_method="GET", request_url=url, response_status=200, response_body="{}"
    )


def test_ffuf_respects_remaining_budget():
    """A 20-word list against a 4-request budget must send at most 4 requests, and the
    exhausted budget must block the next call before ffuf is spawned."""
    tracker = RequestBudgetTracker(max_budget=4)
    bridge = ScannerBridge()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(f"route{i}" for i in range(20)) + "\n")
        wordlist = fh.name

    try:
        parsed = urllib.parse.urlparse(LAB_URL)
        gated = bridge.evaluator.gate_egress(parsed.netloc, is_lab=True)
        if gated["denied"]:
            check("lab container reachable for budget test", False, gated["reason"])
            return

        res = bridge.run_ffuf(f"{LAB_URL}/FUZZ", wordlist, program="local_lab",
                              is_lab=True, rate_limit=10, budget_tracker=tracker)
        check("ffuf ran under the budget", res["status"] == "SUCCESS", str(res))
        sent = res.get("requests_sent", 10 ** 6)
        check("requests sent did not exceed the declared budget", sent <= 4, f"sent={sent}")
        check("budget fully consumed by the run", tracker.remaining() == 0,
              f"remaining={tracker.remaining()}")

        res2 = bridge.run_ffuf(f"{LAB_URL}/FUZZ", wordlist, program="local_lab",
                               is_lab=True, rate_limit=10, budget_tracker=tracker)
        check("exhausted budget blocks ffuf before it is spawned",
              res2["status"] == "BLOCKED" and "BUDGET_EXHAUSTED" in res2["reason"], str(res2))
    finally:
        Path(wordlist).unlink(missing_ok=True)


def test_provenance_precedes_dns_resolution():
    """
    Provenance check must precede DNS resolution.
    Targeting an unadmitted or unauthorized program/host must be rejected on provenance
    with ZERO DNS queries emitted.
    """
    resolved = []
    real_getaddrinfo = socket.getaddrinfo

    def stub_getaddrinfo(host, *args, **kwargs):
        resolved.append(str(host))
        raise socket.gaierror(-2, "Name or service not known")

    socket.getaddrinfo = stub_getaddrinfo
    try:
        from engine.autonomous_hunter import AutonomousHunter
        from core.scope_guard import ScopeGuard

        bridge = ScannerBridge()
        # 1. ScannerBridge.run_ffuf
        res_ffuf = bridge.run_ffuf("https://unadmitted-target.invalid/FUZZ", "data/all-links-core.txt", program="unadmitted_prog", is_lab=False)
        check("run_ffuf rejects unadmitted target on provenance", "OUT OF SCOPE" in res_ffuf.get("reason", ""), str(res_ffuf))

        # 2. ScannerBridge.run_nuclei_triage
        res_nuclei = bridge.run_nuclei_triage("https://unadmitted-target.invalid", program="unadmitted_prog", is_lab=False)
        check("run_nuclei_triage rejects unadmitted target on provenance", "OUT OF SCOPE" in res_nuclei[0]["blocking_gap"], str(res_nuclei))

        # 3. AutonomousHunter.hunt
        hunter = AutonomousHunter(is_lab=False)
        res_hunter = hunter.hunt("unadmitted_prog", "https://unadmitted-target.invalid")
        check("AutonomousHunter rejects unadmitted target on provenance", "OUT OF SCOPE" in res_hunter["reason"], str(res_hunter))

        # 4. ScopeGuard.verify_target
        sg = ScopeGuard()
        in_scope, reason = sg.verify_target("https://unadmitted-target.invalid", "unadmitted_prog", is_lab=False)
        check("ScopeGuard.verify_target rejects unadmitted target on provenance", not in_scope and "OUT OF SCOPE" in reason, reason)

        # Invariant: ZERO DNS queries emitted
        check("zero DNS lookups emitted during unadmitted provenance refusals", len(resolved) == 0, f"emitted: {resolved}")
    finally:
        socket.getaddrinfo = real_getaddrinfo


if __name__ == "__main__":
    test_fail_closed_dns()
    test_rebinding_style_denials()
    test_lab_carve_out_survives()
    test_dns_pinning()
    test_triage_does_not_resolve()
    test_ffuf_respects_remaining_budget()
    test_provenance_precedes_dns_resolution()

    print("=" * 60)
    if failures:
        print(f"FAILED {len(failures)}: {failures}")
        sys.exit(1)
    print("ALL EGRESS & BUDGET REGRESSION TESTS PASSED")
