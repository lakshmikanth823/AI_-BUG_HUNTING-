# Lab Validation & Triage Gate Accuracy Benchmark

- **Target Environment**: Real Live Localhost Lab (`http://localhost:3000`)
- **Execution Timestamp**: 2026-10-31T06:24:02Z
- **Total Probes Evaluated**: 8
- **True Positive Rate (TPR)**: 0.0%
- **False Positive Rate (FPR)**: 0.0%
- **False Negative Rate (FNR)**: 100.0%
- **Average Triage Latency**: 3.3168s

## Detailed Probe Transcripts & OUTPUT CONTRACT Blocks

### CASE-01-SQLI: SQL Injection Authentication Bypass via Email Parameter

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: SQL Injection
- **Target URL**: `http://127.0.0.1:3000/rest/user/login`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `http://127.0.0.1:3000/rest/user/login` (HTTP `None`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `4.0668s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/rest/user/login; Q2: no, unverified evidence on http://127.0.0.1:3000/rest/user/login; Q3: no, unverified evidence on http://127.0.0.1:3000/rest/user/login; Q4: no, unverified evidence on http://127.0.0.1:3000/rest/user/login; Q5: no, unverified evidence on http://127.0.0.1:3000/rest/user/login; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/rest/user/login; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-02-IDOR: Insecure Direct Object Reference (IDOR) on User Basket

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: IDOR
- **Target URL**: `http://127.0.0.1:3000/rest/basket/2`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `http://127.0.0.1:3000/rest/basket/1` (HTTP `None`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `4.1252s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/rest/basket/2; Q2: no, unverified evidence on http://127.0.0.1:3000/rest/basket/2; Q3: no, unverified evidence on http://127.0.0.1:3000/rest/basket/2; Q4: no, unverified evidence on http://127.0.0.1:3000/rest/basket/2; Q5: no, unverified evidence on http://127.0.0.1:3000/rest/basket/2; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/rest/basket/2; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-03-RXSS: Reflected Query Parameter in Local Search Session

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Self-XSS / Informational
- **Target URL**: `http://127.0.0.1:3000/rest/products/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `n/a` (HTTP `n/a`)
- **Expected Verdicts**: `VALID-INFORMATIONAL, KILL`
- **Probe Latency**: `2.0400s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/rest/products/search; Q2: no, unverified evidence on http://127.0.0.1:3000/rest/products/search; Q3: no, unverified evidence on http://127.0.0.1:3000/rest/products/search; Q4: no, unverified evidence on http://127.0.0.1:3000/rest/products/search; Q5: no, unverified evidence on http://127.0.0.1:3000/rest/products/search; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/rest/products/search; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-04-SXSS: Stored Cross-Site Scripting via Customer Feedback

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Defended (server-side input sanitization)
- **Target URL**: `http://127.0.0.1:3000/api/Feedbacks/`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `http://127.0.0.1:3000/api/Feedbacks/` (HTTP `n/a`)
- **Expected Verdicts**: `VALID-INFORMATIONAL, KILL`
- **Probe Latency**: `4.0930s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/api/Feedbacks/; Q2: no, unverified evidence on http://127.0.0.1:3000/api/Feedbacks/; Q3: no, unverified evidence on http://127.0.0.1:3000/api/Feedbacks/; Q4: no, unverified evidence on http://127.0.0.1:3000/api/Feedbacks/; Q5: no, unverified evidence on http://127.0.0.1:3000/api/Feedbacks/; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/api/Feedbacks/; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-05-BFLA: Broken Function Level Auth (IDOR on /api/Users Exposing Password Hashes)

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: Broken Access Control (BFLA)
- **Target URL**: `http://127.0.0.1:3000/api/Users/`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `http://127.0.0.1:3000/api/Users/1` (HTTP `None`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `4.0675s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/api/Users/; Q2: no, unverified evidence on http://127.0.0.1:3000/api/Users/; Q3: no, unverified evidence on http://127.0.0.1:3000/api/Users/; Q4: no, unverified evidence on http://127.0.0.1:3000/api/Users/; Q5: no, unverified evidence on http://127.0.0.1:3000/api/Users/; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/api/Users/; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-06-SSRF: Server-Side Request Forgery via Profile Image URL Fetcher

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Unconfirmed SSRF (evidence insufficient)
- **Target URL**: `http://127.0.0.1:3000/profile/image/url`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `n/a` (HTTP `n/a`)
- **Expected Verdicts**: `LEAD`
- **Probe Latency**: `2.0112s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/profile/image/url; Q2: no, unverified evidence on http://127.0.0.1:3000/profile/image/url; Q3: no, unverified evidence on http://127.0.0.1:3000/profile/image/url; Q4: no, unverified evidence on http://127.0.0.1:3000/profile/image/url; Q5: no, unverified evidence on http://127.0.0.1:3000/profile/image/url; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/profile/image/url; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-07-AUTH: Authentication Bypass & Account Takeover via Predictable Security Question

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: Auth / Account Takeover
- **Target URL**: `http://127.0.0.1:3000/rest/user/reset-password`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `http://127.0.0.1:3000/rest/user/reset-password` (HTTP `None`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `4.1033s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/rest/user/reset-password; Q2: no, unverified evidence on http://127.0.0.1:3000/rest/user/reset-password; Q3: no, unverified evidence on http://127.0.0.1:3000/rest/user/reset-password; Q4: no, unverified evidence on http://127.0.0.1:3000/rest/user/reset-password; Q5: no, unverified evidence on http://127.0.0.1:3000/rest/user/reset-password; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/rest/user/reset-password; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

### CASE-08-BENIGN: Missing Strict-Transport-Security (HSTS) Header on Static Resource

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Informational / Best Practice
- **Target URL**: `http://127.0.0.1:3000/assets/public/favicon_js.ico`
- **Observed HTTP Status**: `None`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `n/a` (HTTP `n/a`)
- **Expected Verdicts**: `VALID-INFORMATIONAL, KILL`
- **Probe Latency**: `2.0270s`

```text
VERDICT:        KILL
STAGE REACHED:  0
BLOCKING GAP:   Missing Stage 0 evidence elements: (b) exact response status
SEVEN ANSWERS:  Q1: no, unverified evidence on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q2: no, unverified evidence on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q3: no, unverified evidence on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q4: no, unverified evidence on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q5: no, unverified evidence on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q6: no, evidence insufficiency precludes unprivileged verification on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q7: no, missing (b) exact response status prevents end-to-end confirmation
CVSS:           n/a
NEXT ACTION:    Capture missing evidence ((b) exact response status) before proceeding.
```

---

