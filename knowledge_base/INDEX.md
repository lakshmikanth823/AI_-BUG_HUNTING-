# Antigravity Knowledge Base — Root Index & Ingestion Guide

> **CRITICAL CONTEXT WINDOW RULE**:
> This directory contains **15,000+ localized Markdown files and YAML templates**.
> **NEVER attempt to dump whole directories or load full multi-megabyte files into your prompt context.**
> Instead, follow the **Targeted Retrieval Protocols** and query tools documented below.

---

## 1. Directory Architecture

```
knowledge_base/
├── methodologies/             # Attack surface mapping & systematic test playbooks
│   ├── owasp-wstg/            # OWASP Web Security Testing Guide (100+ module guides)
│   ├── hacktricks/            # HackTricks complete web/system pentest playbooks
│   ├── hacktricks-cloud/      # HackTricks Cloud (AWS, GCP, Azure, Kubernetes, CI/CD)
│   ├── tbhm/                  # Jason Haddix The Bug Hunter's Methodology
│   ├── howtohunt/             # Step-by-step hunting checklists per vulnerability class
│   ├── bugbounty-cheatsheet/  # High-density bypasses and checklists
│   └── api-security-checklist/# Shieldfy API security & REST verification
├── payloads/                  # Concrete payloads, bypasses & fingerprint matrices
│   ├── PayloadsAllTheThings/  # 70+ vulnerability classes (SQLi, XSS, SSRF, Deserialization, etc.)
│   └── can-i-take-over-xyz/   # Fingerprint signatures for 80+ cloud provider subdomain takeovers
├── writeups/                  # Real-world disclosed reports & escalation chains
│   ├── Awesome-Bugbounty-Writeups/ # Disclosures categorized by vulnerability type
│   ├── bug-bounty-reference/  # Real reports categorized by tech company (Google, Uber, Shopify, etc.)
│   ├── hackerone-reports/     # Top-voted HackerOne Hacktivity disclosed reports
│   └── awesome-bug-bounty-2026/ # Up-to-date program indexes & writeup collections
├── templates/                 # Automated scanner signatures
│   └── nuclei-templates/      # 9,000+ community-curated vulnerability detection YAML templates
└── ctf_archives/              # Exploit chains & reverse-engineering techniques
    └── ctf-wiki/              # Theoretical foundations and advanced exploit primitives
```

---

## 2. Topic-to-Directory Routing Protocol

When an agent needs guidance on a specific bug class, route directly to the corresponding path:

| Vulnerability / Task | Primary Ingestion Path | Secondary Reference |
| :--- | :--- | :--- |
| **SSRF (Server-Side Request Forgery)** | `payloads/PayloadsAllTheThings/Server Side Request Forgery/` | `methodologies/hacktricks/src/pentesting-web/ssrf-server-side-request-forgery/` |
| **BOLA / IDOR (Broken Access Control)** | `methodologies/howtohunt/IDOR/` | `methodologies/api-security-checklist/` |
| **SQL Injection (SQLi)** | `payloads/PayloadsAllTheThings/SQL Injection/` | `templates/nuclei-templates/http/vulnerabilities/generic/` |
| **Cross-Site Scripting (XSS)** | `payloads/PayloadsAllTheThings/XSS Injection/` | `methodologies/hacktricks/src/pentesting-web/xss-cross-site-scripting/` |
| **Subdomain Takeover** | `payloads/can-i-take-over-xyz/` | `methodologies/tbhm/` |
| **OAuth / OIDC / SAML Flaws** | `methodologies/hacktricks/src/pentesting-web/oauth-to-account-takeover.md` | `payloads/PayloadsAllTheThings/OAuth/` |
| **Cloud Metadata / AWS / GCP** | `methodologies/hacktricks-cloud/src/pentesting-cloud/aws-security/` | `payloads/PayloadsAllTheThings/Server Side Request Forgery/` |
| **HTTP Request Smuggling** | `methodologies/hacktricks/src/pentesting-web/http-request-smuggling/` | `payloads/PayloadsAllTheThings/HTTP Request Smuggling/` |
| **Race Conditions** | `payloads/PayloadsAllTheThings/Race Condition/` | `methodologies/howtohunt/Race-Condition/` |

---

## 3. Safe Querying Without Overflowing Context Window

### Method A: Use the Local Knowledge Base Search CLI
Run the fast grep/search utility:
```bash
# Search for IDOR checklists:
python knowledge_base/search_kb.py --query "IDOR" --category "methodologies"

# Search for SSRF payloads:
python knowledge_base/search_kb.py --query "169.254.169.254" --category "payloads"

# Search for real-world writeups:
python knowledge_base/search_kb.py --query "account takeover" --category "writeups"
```

### Method B: Targeted Line-Ranged Reads
When reading a file located by the search tool, always specify an explicit line range (e.g. lines 1–80):
- Never load files larger than 100KB without specifying `StartLine` and `EndLine`.
- Focus on `README.md` and specific sub-playbooks within each vulnerability folder.
