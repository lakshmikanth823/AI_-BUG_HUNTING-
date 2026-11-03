# Third-Party Knowledge Base License Audit & Compliance Specification

This document records the legal licensing status, redistribution permissions, and attribution obligations for all 15 third-party repositories previously vendored in `knowledge_base/`.

---

## 1. Executive Summary & Legal Risk Assessment

A granular file-by-file audit of all 15 repositories reveals that **7 out of 15 repositories (46.7%) CANNOT be legally vendored as static files inside an MIT-licensed public repository**:

1. **Non-Commercial Restrictions (3 Repositories)**: `hacktricks` and `hacktricks-cloud` are licensed under **CC BY-NC 4.0**, and `ctf-wiki` is licensed under **CC BY-NC-SA 4.0**. The Creative Commons "NonCommercial" covenant strictly prohibits redistribution primarily intended for commercial advantage or monetary compensation. Vendoring these into a bug bounty hunting framework (which targets commercial monetary rewards) and claiming MIT licensing is a direct license violation.
2. **Unlicensed / All Rights Reserved (4 Repositories)**: `tbhm`, `Awesome-Bugbounty-Writeups`, `bug-bounty-reference`, and `hackerone-reports` contain **no license file** in their repositories. Under international copyright law, the absence of an open-source license leaves all rights reserved to the respective authors. GitHub's Terms of Service permit viewing/forking on GitHub, but do **not** grant rights to vendor or redistribute copies in third-party projects.
3. **Strong Copyleft Incompatibility (1 Repository)**: `howtohunt` is licensed under **GNU General Public License v3.0 (GPLv3)**. Static vendoring into a project advertised as MIT creates a licensing conflict, as GPLv3 requires any combined or containing work to be licensed under GPLv3.

---

## 2. Granular Repository Audit Matrix

| # | Repository Name | Category | Upstream URL | Declared License | Redistribution Permitted? | Attribution Required? | Critical Conditions & Compliance Notes |
|---|---|---|---|---|---|---|---|
| 1 | `owasp-wstg` | Methodologies | `https://github.com/OWASP/wstg.git` | **CC BY-SA 4.0** | Conditional | **Yes** | Share-Alike copyleft: derivative works and redistributed sections must retain CC BY-SA 4.0 and credit OWASP. |
| 2 | `hacktricks` | Methodologies | `https://github.com/Carlospolop/hacktricks.git` | **CC BY-NC 4.0** | **NO (Commercial)** / Conditional | **Yes** (Carlos Polop) | **FLAGGED.** Explicit `LICENSE.md` sets CC BY-NC 4.0. Incompatible with top-level MIT license and commercial bounty hunting. |
| 3 | `hacktricks-cloud` | Methodologies | `https://github.com/Carlospolop/hacktricks-cloud.git` | **No Grant Found / CC BY-NC 4.0 (Parent)** | **NO** | N/A | **FLAGGED.** No license file found in repository clone. Either inherits parent HackTricks CC BY-NC 4.0 terms or defaults to All Rights Reserved; static vendoring is unauthorized in either case. |
| 4 | `tbhm` | Methodologies | `https://github.com/jhaddix/tbhm.git` | **No License** (All Rights Reserved) | **NO** | N/A | **FLAGGED.** Zero open-source license grant. Commercial or public static vendoring is unauthorized. |
| 5 | `howtohunt` | Methodologies | `https://github.com/KathanP19/HowToHunt.git` | **GPL-3.0** | Conditional | **Yes** | **FLAGGED.** Strong copyleft. Vendoring GPL-3.0 material into an MIT repo infects the containing project with GPL obligations. |
| 6 | `bugbounty-cheatsheet` | Methodologies | `https://github.com/EdOverflow/bugbounty-cheatsheet.git` | **CC BY-SA 4.0** | Conditional | **Yes** (EdOverflow) | Share-Alike copyleft: requires identical CC BY-SA 4.0 terms for adaptations and explicit author credit. |
| 7 | `api-security-checklist` | Methodologies | `https://github.com/shieldfy/API-Security-Checklist.git` | **MIT** | **Yes** | **Yes** (Shieldfy) | Fully permissive; requires retaining original copyright notice and permission notice. |
| 8 | `PayloadsAllTheThings` | Payloads | `https://github.com/swisskyrepo/PayloadsAllTheThings.git` | **MIT** | **Yes** | **Yes** (Swissky) | Fully permissive; requires retaining original copyright notice and permission notice. |
| 9 | `can-i-take-over-xyz` | Payloads | `https://github.com/EdOverflow/can-i-take-over-xyz.git` | **CC BY 4.0** | **Yes** | **Yes** (EdOverflow) | Permissive attribution license; permits commercial redistribution with credit and license link. |
| 10 | `Awesome-Bugbounty-Writeups` | Writeups | `https://github.com/devanshbatham/Awesome-Bugbounty-Writeups.git` | **No License** (All Rights Reserved) | **NO** | N/A | **FLAGGED.** Curation repository without open-source license; author retains all rights. |
| 11 | `bug-bounty-reference` | Writeups | `https://github.com/ngalongc/bug-bounty-reference.git` | **No License** (All Rights Reserved) | **NO** | N/A | **FLAGGED.** Curation repository without open-source license; author retains all rights. |
| 12 | `hackerone-reports` | Writeups | `https://github.com/reddelexc/hackerone-reports.git` | **No License** (All Rights Reserved) | **NO** | N/A | **FLAGGED.** Scraped writeup archive; underlying report copyrights belong to individual researchers and HackerOne. |
| 13 | `awesome-bug-bounty-2026` | Writeups | `https://github.com/itsmohitnarayan/awesome-bug-bounty.git` | **CC0 1.0** | **Yes** | No | Dedicated to the public domain; zero restrictions. |
| 14 | `nuclei-templates` | Templates | `https://github.com/projectdiscovery/nuclei-templates.git` | **MIT** | **Yes** | **Yes** (ProjectDiscovery) | Fully permissive; requires retaining original copyright and permission notice. |
| 15 | `ctf-wiki` | CTF Archives | `https://github.com/ctf-wiki/ctf-wiki.git` | **CC BY-NC-SA 4.0** | **NO (Commercial)** / Conditional | **Yes** | **FLAGGED.** Strict Non-Commercial and Share-Alike restrictions. Incompatible with top-level MIT license. |

---

## 3. Detailed Per-Repository Breakdown

### Repositories with Non-Commercial Restrictions (CC BY-NC 4.0 / CC BY-NC-SA 4.0)
- **`Carlospolop/hacktricks` and `Carlospolop/hacktricks-cloud`**:
  - *Terms:* "Licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)."
  - *Legal Barrier:* Section 2(a)(1) explicitly limits the grant to NonCommercial purposes: *"not primarily intended for or directed towards commercial advantage or monetary compensation."* Because this repository is a tool designed for bug bounty hunting (which awards monetary payouts), vendoring this text directly into an MIT repository exposes users and operators to non-compliance.
- **`ctf-wiki/ctf-wiki`**:
  - *Terms:* "Licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)."
  - *Legal Barrier:* Combines NonCommercial restriction with ShareAlike viral copyleft.

### Repositories with Zero License Grant (All Rights Reserved)
- **`jhaddix/tbhm`**, **`devanshbatham/Awesome-Bugbounty-Writeups`**, **`ngalongc/bug-bounty-reference`**, **`reddelexc/hackerone-reports`**:
  - *Terms:* No LICENSE file exists in any of these repositories.
  - *Legal Barrier:* Under Title 17 of the U.S. Code and the Berne Convention, the creator automatically retains exclusive copyright. Without an affirmative license, third parties have no legal right to copy, distribute, or vendor the material into their own public Git repositories.

### Repositories with Copyleft Requirements (GPLv3 / CC BY-SA 4.0)
- **`KathanP19/HowToHunt`**:
  - *Terms:* GNU General Public License v3.0 (GPLv3).
  - *Legal Barrier:* GPLv3 requires that any work containing or derived from GPLv3 code must itself be licensed under GPLv3 as a whole. Vendoring it inside an MIT project breaches the MIT warranty of unencumbered distribution.
- **`OWASP/wstg` & `EdOverflow/bugbounty-cheatsheet`**:
  - *Terms:* Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
  - *Condition:* Can be redistributed only if modifications and combined publications are shared under the exact same Share-Alike terms.

---

## 4. Proposed Migration Plan: Externalized Pipeline vs Git Submodules

### Current Footprint
- **Vendored `knowledge_base/` Working Tree**: **479.91 MB**
  - `hacktricks`: 163.35 MB
  - `ctf-wiki`: 145.19 MB
  - `hacktricks-cloud`: 57.33 MB
  - `nuclei-templates`: 45.58 MB
  - `tbhm`: 27.20 MB
  - Others: 41.26 MB
- **Current Git History (`.git`)**: **331.46 MB**
- **SQLite FTS Database (`knowledge_fts.db`)**: **88.46 MB**
- **Total Repo Disk Footprint**: **~1.1 GB**

---

### Migration Options Comparison

| Attribute | Option A: Git Submodules | Option B: Externalized Setup Pipeline (`download_kb.py`) (Recommended) |
|---|---|---|
| **Legal Compliance** | Partial. Submodules still link to unfree repos and clone them during build. | **Complete.** Zero copyrighted third-party text is stored or redistributed in this repository. |
| **Repo Clone Size** | ~340 MB (code + history) | **< 15 MB** (Pure code, CLI, documentation, benchmarks). |
| **Network & Disk Impact** | User must still pull ~480 MB during recursive clone. | User pulls only what they need on-demand via `python download_kb.py`. |
| **Windows Compatibility** | Known path-length and detached HEAD issues in Git for Windows. | Native Python script handling path resolution and shallow (`--depth 1`) clones. |
| **Licensing Purity** | Grey area regarding repository distribution bundles. | **100% Pure MIT.** The repo contains only original code and metadata pointers. |

---

### Proposed Execution Sequence for Option B (Recommended)

1. **Add `knowledge_base/` and `data/knowledge_fts.db` to `.gitignore`**:
   - Ensures third-party files are strictly local runtime assets.
2. **Remove Tracked Files from Git**:
   - Run `git rm -r --cached knowledge_base/` to drop all 480 MB of vendored files from the repository index while keeping local copies intact for local search.
3. **Enhance `download_kb.py`**:
   - Document `download_kb.py` as an optional local setup command:
     ```bash
     python download_kb.py --categories methodologies payloads
     python engine/content_indexer.py
     ```
   - Automatically display the license and terms notice for each repo when downloaded locally so the user is informed of non-commercial terms before local indexing.
4. **Clean Git History (Optional / Recommended)**:
   - Run `git filter-repo` or squash history to purge the 331 MB of historical blob storage.
5. **Estimated Post-Migration Repository Size**:
   - Working Tree: **~12 MB**
   - Git History: **< 15 MB**
   - Total Repository Size: **~25 MB** (a **97.7% reduction** in repository size).
