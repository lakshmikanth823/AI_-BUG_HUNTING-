import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.triage_evaluator import (
    TriageEvaluator,
    CandidateFinding,
    cross_tenant_read_proven,
    cross_tenant_mutation_proven,
    outbound_fetch_targets,
)

evaluator = TriageEvaluator()

BASE = "http://127.0.0.1:3000"

# PROBE-A1 (title lies low, a real two-transaction diff proves impact)
# The marker is admin@juice-sh.op: it is the first identifier the list endpoint discloses that
# the executing session's own control record does not contain.
f_a1 = CandidateFinding(
    title="Missing security header on /rest/admin",
    program="local_lab",
    target_host="127.0.0.1",
    request_method="GET",
    request_url=f"{BASE}/api/Users/",
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status":"success","data":[{"id":1,"email":"admin@juice-sh.op","role":"admin","password":"0dc417a73335a9b9a452e2c76a08c2c4"},{"id":3,"email":"bender@juice-sh.op","role":"customer","password":"617c4802cf1d9e6a9a26c26e9f2b7a3d"}]}',
    baseline_status=200,
    baseline_body='{"status":"success","data":[{"id":4,"email":"own-account@juice-sh.op","role":"customer","password":"3a4b7f9c1d2e5f6a7b8c9d0e1f2a3b4c"}]}',
    victim_marker='"email":"admin@juice-sh.op"',
    second_account_tested=True,
    attacker_controlled_proof="Secondary account data exfiltrated via endpoint",
    is_lab=True
)
res_a1 = evaluator.evaluate(f_a1)

# PROBE-A2 (title lies high, body proves nothing)
f_a2 = CandidateFinding(
    title="Critical RCE via unauthenticated command injection",
    program="local_lab",
    target_host="127.0.0.1",
    request_method="POST",
    request_url="http://127.0.0.1:8082/vulnerabilities/exec/",
    request_body="ip=127.0.0.1%3B+whoami&Submit=Submit",
    response_status=200,
    response_headers={"Content-Type": "text/html"},
    response_body="<html><body><h3>Normal Application Page</h3><p>Enter IP:</p></body></html>",
    attacker_controlled_proof="Submitted ; whoami payload through the ip parameter",
    second_account_tested=False,
    is_lab=True
)
res_a2 = evaluator.evaluate(f_a2)

# PROBE-A3 (payload echoed back into the created record — no second-session readback proves delivery)
f_a3 = CandidateFinding(
    title="Stored Cross-Site Scripting in Customer Feedback",
    program="local_lab",
    target_host="127.0.0.1",
    request_method="POST",
    request_url=f"{BASE}/api/Feedbacks/",
    request_body='{"comment": "<iframe src=\\"javascript:alert(document.domain)\\">", "rating": 5}',
    response_status=201,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status":"success","data":{"id":12,"comment":"<iframe src=\\"javascript:alert(document.domain)\\">"}}',
    second_account_tested=True,
    attacker_controlled_proof="Payload persistently stored in database and executed in secondary user session",
    is_lab=True
)
res_a3 = evaluator.evaluate(f_a3)

# PROBE-A4 (benign body + everything asserted: second_account boolean, narrative proof, title)
# This is the exact shape the pre-R1 gate paid out. Nothing here is a captured transaction.
f_a4 = CandidateFinding(
    title="Critical IDOR exposing all customer orders",
    program="local_lab",
    target_host="127.0.0.1",
    request_method="GET",
    request_url=f"{BASE}/rest/order-history",
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status":"success","data":[]}',
    second_account_tested=True,
    attacker_controlled_proof="Read another tenant's private records, took over their account, dumped credentials, and gained admin access",
    is_lab=True
)
res_a4 = evaluator.evaluate(f_a4)

# PROBE-A5 (the only channel left open to an operator who genuinely has no second session:
# an out-of-band artifact captured from the receiving end)
f_a5 = CandidateFinding(
    title="Blind SSRF via profile image URL fetcher",
    program="local_lab",
    target_host="127.0.0.1",
    request_method="POST",
    request_url=f"{BASE}/profile/image/url",
    request_body='{"imageUrl":"http://127.0.0.1:9099/WebWolf/landing?marker=ssrfdeadbeefcafe"}',
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status":"success"}',
    readback_body='{"requests":[{"url":"/WebWolf/landing?marker=ssrfdeadbeefcafe","ip":"172.17.0.3"}]}',
    victim_marker="marker=ssrfdeadbeefcafe",
    second_account_tested=False,
    attacker_controlled_proof="Server fetched the attacker-controlled origin",
    is_lab=True
)
res_a5 = evaluator.evaluate(f_a5)

# PROBE-A6 (the self-write trap: POST changes my own resource, readback shows my own new value.
# With no control transaction from before the change, nothing distinguishes this from ordinary use.)
f_a6 = CandidateFinding(
    title="Profile overwrite in own session",
    program="local_lab",
    target_host="127.0.0.1",
    request_method="POST",
    request_url=f"{BASE}/profile",
    request_body='{"username":"my-own-new-value-1234"}',
    response_status=200,
    response_headers={"Content-Type": "application/json"},
    response_body='{"status":"success","username":"my-own-new-value-1234"}',
    readback_body='{"status":"success","data":{"username":"my-own-new-value-1234"}}',
    victim_marker="my-own-new-value-1234",
    second_account_tested=True,
    attacker_controlled_proof="Mutated state and confirmed it persisted",
    is_lab=True
)
res_a6 = evaluator.evaluate(f_a6)

checks = [
    ("PROBE-A1 real two-transaction diff -> VALID-PAYABLE", res_a1["verdict"] == "VALID-PAYABLE"),
    ("PROBE-A2 injected command with benign body -> KILL", res_a2["verdict"] == "KILL"),
    ("PROBE-A3 stored payload echoed only into own write -> not payable", res_a3["verdict"] != "VALID-PAYABLE"),
    ("PROBE-A4 benign body + asserted cross-account -> not payable", res_a4["verdict"] != "VALID-PAYABLE"),
    ("PROBE-A5 directed fetch + captured OOB artifact -> VALID-PAYABLE", res_a5["verdict"] == "VALID-PAYABLE"),
    ("PROBE-A5 scored as SSRF (scope changed), not as a tenant mutation", "S:C/C:H" in res_a5["cvss"]),
    ("PROBE-A6 self-write + own readback is not cross-tenant mutation", cross_tenant_mutation_proven(f_a6) is False),
    ("PROBE-A6 self-write with asserted second account -> not payable", res_a6["verdict"] != "VALID-PAYABLE"),
    ("A4 has no outbound target of its own host", outbound_fetch_targets(f_a4) == []),
    ("A4 marker-less read is not 'proven'", cross_tenant_read_proven(f_a4) is False),
]

for name, res in (("PROBE-A1", res_a1), ("PROBE-A2", res_a2), ("PROBE-A3", res_a3), ("PROBE-A4", res_a4), ("PROBE-A5", res_a5), ("PROBE-A6", res_a6)):
    print(f"{name}: {res['verdict']} | Stage: {res['stage_reached']} | CVSS: {res['cvss']}")
    print(evaluator.format_output_contract(res))
    print("=" * 60)

failures = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")

if failures:
    print(f"\nADVERSARIAL SUITE FAILED: {failures}")
    sys.exit(1)
print(f"\nADVERSARIAL SUITE PASSED ({len(checks)}/{len(checks)})")
