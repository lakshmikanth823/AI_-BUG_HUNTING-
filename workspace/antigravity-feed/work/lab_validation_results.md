# Lab Validation & Triage Gate Accuracy Benchmark

- **Target Environment**: Real Live Localhost Lab (`http://localhost:3000`)
- **Execution Timestamp**: 2026-10-31T09:27:39Z
- **Total Probes Evaluated**: 8
- **True Positive Rate (TPR)**: 100.0%
- **False Positive Rate (FPR)**: 0.0%
- **False Negative Rate (FNR)**: 0.0%
- **Average Triage Latency**: 0.0477s

## Detailed Probe Transcripts & OUTPUT CONTRACT Blocks

### CASE-01-SQLI: SQL Injection Authentication Bypass via Email Parameter

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: SQL Injection
- **Target URL**: `http://127.0.0.1:3000/rest/user/login`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `"umail":"admin@juice-sh.op"`
- **Control Transaction**: `http://127.0.0.1:3000/rest/user/login` (HTTP `401`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `0.0395s`

```text
VERDICT:        VALID-PAYABLE
STAGE REACHED:  5
BLOCKING GAP:   none
SEVEN ANSWERS:  Q1: yes, unauthorized data read confirmed on http://127.0.0.1:3000/rest/user/login (leaked records/file contents); Q2: no, request method POST on http://127.0.0.1:3000/rest/user/login is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/rest/user/login; Q4: yes, session tokens or authentication credentials compromised on http://127.0.0.1:3000/rest/user/login; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/rest/user/login; Q6: yes, survives clean-session test with observed HTTP 200 on http://127.0.0.1:3000/rest/user/login; Q7: yes, business impact confirmed end-to-end with evidence on http://127.0.0.1:3000/rest/user/login
CVSS:           CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
NEXT ACTION:    Draft formal vulnerability report with reproducible curl reproduction steps.
```

---

### CASE-02-IDOR: Insecure Direct Object Reference (IDOR) on User Basket

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: IDOR
- **Target URL**: `http://127.0.0.1:3000/rest/basket/2`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `"name":"Raspberry Juice (1000ml)"`
- **Control Transaction**: `http://127.0.0.1:3000/rest/basket/1` (HTTP `200`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `0.1045s`

```text
VERDICT:        VALID-PAYABLE
STAGE REACHED:  5
BLOCKING GAP:   none
SEVEN ANSWERS:  Q1: yes, unauthorized data read confirmed on http://127.0.0.1:3000/rest/basket/2 (leaked records/file contents); Q2: no, request method GET on http://127.0.0.1:3000/rest/basket/2 is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/rest/basket/2; Q4: no, session credentials not extractable from http://127.0.0.1:3000/rest/basket/2; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/rest/basket/2; Q6: yes, survives clean-session test with observed HTTP 200 on http://127.0.0.1:3000/rest/basket/2; Q7: yes, business impact confirmed end-to-end with evidence on http://127.0.0.1:3000/rest/basket/2
CVSS:           CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
NEXT ACTION:    Draft formal vulnerability report with reproducible curl reproduction steps.
```

---

### CASE-03-RXSS: Reflected Query Parameter in Local Search Session

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Self-XSS / Informational
- **Target URL**: `http://127.0.0.1:3000/rest/products/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `n/a` (HTTP `n/a`)
- **Expected Verdicts**: `VALID-INFORMATIONAL, KILL`
- **Probe Latency**: `0.0086s`

```text
VERDICT:        KILL
STAGE REACHED:  1
BLOCKING GAP:   Client parameter reflects only within executing user's own browser session on http://127.0.0.1:3000/rest/products/search; fails Q6 unprivileged cross-tenant reachability.
SEVEN ANSWERS:  Q1: no, does not read other user/tenant data on http://127.0.0.1:3000/rest/products/search; Q2: no, request method GET on http://127.0.0.1:3000/rest/products/search is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/rest/products/search; Q4: no, session credentials not extractable from http://127.0.0.1:3000/rest/products/search; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/rest/products/search; Q6: no, reflection restricted to user's own local browser session context on http://127.0.0.1:3000/rest/products/search; Q7: no, theoretical risk on http://127.0.0.1:3000/rest/products/search requiring unproven assumptions
CVSS:           n/a
NEXT ACTION:    KILL from payable queue; record as defensive recommendation only.
```

---

### CASE-04-SXSS: Stored Cross-Site Scripting via Customer Feedback

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Defended (server-side input sanitization)
- **Target URL**: `http://127.0.0.1:3000/api/Feedbacks/`
- **Observed HTTP Status**: `201`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `http://127.0.0.1:3000/api/Feedbacks/` (HTTP `n/a`)
- **Expected Verdicts**: `VALID-INFORMATIONAL, KILL`
- **Probe Latency**: `0.0879s`

```text
VERDICT:        KILL
STAGE REACHED:  1
BLOCKING GAP:   Questions 1-5 all evaluated to 'no' on http://127.0.0.1:3000/api/Feedbacks/. Lacks demonstrated cross-user read/write, code execution, or auth bypass.
SEVEN ANSWERS:  Q1: no, does not read other user/tenant data on http://127.0.0.1:3000/api/Feedbacks/; Q2: no, request method POST on http://127.0.0.1:3000/api/Feedbacks/ is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/api/Feedbacks/; Q4: no, session credentials not extractable from http://127.0.0.1:3000/api/Feedbacks/; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/api/Feedbacks/; Q6: yes, survives clean-session test with observed HTTP 201 on http://127.0.0.1:3000/api/Feedbacks/; Q7: no, theoretical risk on http://127.0.0.1:3000/api/Feedbacks/ requiring unproven assumptions
CVSS:           n/a
NEXT ACTION:    KILL from payable queue; record as defensive recommendation only.
```

---

### CASE-05-BFLA: Broken Function Level Auth (IDOR on /api/Users Exposing Password Hashes)

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: Broken Access Control (BFLA)
- **Target URL**: `http://127.0.0.1:3000/api/Users/`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `"email":"jim@juice-sh.op"`
- **Control Transaction**: `http://127.0.0.1:3000/api/Users/1` (HTTP `200`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `0.0704s`

```text
VERDICT:        VALID-PAYABLE
STAGE REACHED:  5
BLOCKING GAP:   none
SEVEN ANSWERS:  Q1: yes, unauthorized data read confirmed on http://127.0.0.1:3000/api/Users/ (leaked records/file contents); Q2: no, request method GET on http://127.0.0.1:3000/api/Users/ is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/api/Users/; Q4: no, session credentials not extractable from http://127.0.0.1:3000/api/Users/; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/api/Users/; Q6: yes, survives clean-session test with observed HTTP 200 on http://127.0.0.1:3000/api/Users/; Q7: yes, business impact confirmed end-to-end with evidence on http://127.0.0.1:3000/api/Users/
CVSS:           CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
NEXT ACTION:    Draft formal vulnerability report with reproducible curl reproduction steps.
```

---

### CASE-06-SSRF: Server-Side Request Forgery via Profile Image URL Fetcher

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Unconfirmed SSRF (evidence insufficient)
- **Target URL**: `http://127.0.0.1:3000/profile/image/url`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `n/a` (HTTP `n/a`)
- **Expected Verdicts**: `LEAD`
- **Probe Latency**: `0.0408s`

```text
VERDICT:        LEAD
STAGE REACHED:  1
BLOCKING GAP:   Server-directed fetch toward http://127.0.0.1:9099/WebWolf/landing at http://127.0.0.1:3000/profile/image/url, but no out-of-band artifact was captured; the fetch itself is unconfirmed.
SEVEN ANSWERS:  Q1: no, does not read other user/tenant data on http://127.0.0.1:3000/profile/image/url; Q2: no, request method POST on http://127.0.0.1:3000/profile/image/url is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/profile/image/url; Q4: no, session credentials not extractable from http://127.0.0.1:3000/profile/image/url; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/profile/image/url; Q6: yes, survives clean-session test with observed HTTP 200 on http://127.0.0.1:3000/profile/image/url; Q7: no, theoretical risk on http://127.0.0.1:3000/profile/image/url requiring unproven assumptions
CVSS:           n/a
NEXT ACTION:    Capture the receiving-end transaction (http://127.0.0.1:9099/WebWolf/landing access log containing the planted marker) for http://127.0.0.1:3000/profile/image/url before re-submitting.
```

---

### CASE-07-AUTH: Authentication Bypass & Account Takeover via Predictable Security Question

- **Ground Truth**: PLANTED VULNERABILITY
- **Vulnerability Class**: Auth / Account Takeover
- **Target URL**: `http://127.0.0.1:3000/rest/user/reset-password`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `"email":"bender@juice-sh.op"`
- **Control Transaction**: `http://127.0.0.1:3000/rest/user/reset-password` (HTTP `401`)
- **Expected Verdicts**: `VALID-PAYABLE`
- **Probe Latency**: `0.0275s`

```text
VERDICT:        VALID-PAYABLE
STAGE REACHED:  5
BLOCKING GAP:   none
SEVEN ANSWERS:  Q1: yes, unauthorized data read confirmed on http://127.0.0.1:3000/rest/user/reset-password (leaked records/file contents); Q2: no, request method POST on http://127.0.0.1:3000/rest/user/reset-password is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/rest/user/reset-password; Q4: no, session credentials not extractable from http://127.0.0.1:3000/rest/user/reset-password; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/rest/user/reset-password; Q6: yes, survives clean-session test with observed HTTP 200 on http://127.0.0.1:3000/rest/user/reset-password; Q7: yes, business impact confirmed end-to-end with evidence on http://127.0.0.1:3000/rest/user/reset-password
CVSS:           CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
NEXT ACTION:    Draft formal vulnerability report with reproducible curl reproduction steps.
```

---

### CASE-08-BENIGN: Missing Strict-Transport-Security (HSTS) Header on Static Resource

- **Ground Truth**: BENIGN NON-ISSUE
- **Vulnerability Class**: Informational / Best Practice
- **Target URL**: `http://127.0.0.1:3000/assets/public/favicon_js.ico`
- **Observed HTTP Status**: `200`
- **Cross-tenant Marker (derived from captured diff)**: `none`
- **Control Transaction**: `n/a` (HTTP `n/a`)
- **Expected Verdicts**: `VALID-INFORMATIONAL, KILL`
- **Probe Latency**: `0.0024s`

```text
VERDICT:        KILL
STAGE REACHED:  1
BLOCKING GAP:   Content-Security-Policy header is absent on static resource http://127.0.0.1:3000/assets/public/favicon_js.ico, but Q1-Q5 are all negative with no demonstrated cross-tenant exploit chain.
SEVEN ANSWERS:  Q1: no, does not read other user/tenant data on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q2: no, request method GET on http://127.0.0.1:3000/assets/public/favicon_js.ico is read-only or mutation rejected; Q3: no, no code execution or server request reflection on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q4: no, session credentials not extractable from http://127.0.0.1:3000/assets/public/favicon_js.ico; Q5: no, no currency, token, or paid quota burned on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q6: yes, survives clean-session test with observed HTTP 200 on http://127.0.0.1:3000/assets/public/favicon_js.ico; Q7: no, theoretical risk on http://127.0.0.1:3000/assets/public/favicon_js.ico requiring unproven assumptions
CVSS:           n/a
NEXT ACTION:    KILL from payable queue; record as defensive recommendation only.
```

---

