"""
Publication-Grade Bug Bounty Vulnerability Report Generator.
Emits clear, evidence-based, copy-pasteable reports compliant with
HackerOne and Bugcrowd standards.
"""

from pathlib import Path
from typing import Dict, Any, Optional

from engine.triage_evaluator import CandidateFinding


class ReportGenerator:
    @staticmethod
    def generate_report(finding: CandidateFinding, triage_result: Dict[str, Any]) -> str:
        """Emits a complete, triage-ready markdown vulnerability report."""
        cvss = triage_result.get("cvss", "n/a")
        verdict = triage_result.get("verdict", "LEAD")
        stage = triage_result.get("stage_reached", 0)

        # Build clean minimal curl reproduction
        headers_str = ""
        for k, v in finding.request_headers.items():
            if k.lower() != "content-length":
                headers_str += f'  -H "{k}: {v}" \\\n'

        body_str = ""
        if finding.request_body:
            body_str = f"  --data '{finding.request_body}' \\\n"

        curl_cmd = f"curl -i -s -k -X {finding.request_method} \\\n{headers_str}{body_str}  \"{finding.request_url}\""

        report = f"""# [Vulnerability Report] {finding.title}

## Summary
A security vulnerability was identified on `{finding.target_host}` ({finding.program}).
- **Vulnerability Class**: {finding.title.split(' via ')[0].split(' on ')[0]}
- **Triage Gate Verdict**: `{verdict}` (Stage {stage})
- **Severity (CVSS 3.1)**: `{cvss}`
- **Target Asset**: `{finding.request_url}`

---

## Technical Details & Root Cause
The endpoint fails to properly validate, authorize, or sanitize client-supplied input during request processing. 

### Vulnerable Request
```http
{finding.request_method} {finding.request_url} HTTP/1.1
Host: {finding.target_host}
{chr(10).join(f"{k}: {v}" for k, v in finding.request_headers.items())}

{finding.request_body}
```

### Server Response
```http
HTTP/1.1 {finding.response_status or 'N/A'}
{chr(10).join(f"{k}: {v}" for k, v in finding.response_headers.items() if k.lower() in ('content-type', 'set-cookie', 'location', 'server'))}

{finding.response_body[:800]}
```

---

## Step-by-Step Reproduction Steps

1. Send the following minimal HTTP request targeting `{finding.request_url}`:

```bash
{curl_cmd}
```

2. Inspect the HTTP response status code (`{finding.response_status}`) and response payload.
3. Observe that {finding.attacker_controlled_proof or 'the unauthorized action completes successfully.'}

---

## Impact
{triage_result.get('seven_answers', {}).get('Q7', 'Demonstrated impact end-to-end.')}

- **Second Independent Session Verification**: {'Verified using a distinct secondary account/session' if finding.second_account_tested else 'Single session execution'}.
- **Data Minimization & Blast Radius**: Only minimal proof-of-concept data was queried/transmitted; no persistent changes or denial of service were performed.

---

## Remediation Guidance
1. Enforce strict server-side authorization checks and input validation at the controller or model layer.
2. Ensure object-level access controls verify the current authenticated user's permission to access or mutate the requested resource.
3. Sanitize or encode all user-supplied data prior to rendering or downstream database query execution.
"""
        return report
