# Security Research Link Corpus → Antigravity Feed

**9,879 curated, de-duplicated, individually HTTP-verified security-research URLs** covering bug
bounty hunting, CTFs, offensive tooling, vulnerable labs, standards databases and the canonical
reading list — packaged so it can be dropped straight into
[Google Antigravity](https://antigravity.google/docs/rules/).

Collected **2026-10-29**. Pipeline: 22,500 raw links → 11,094 unique after normalisation and
de-duplication → 9,879 after live HTTP validation and safety filtering.

---

## Quick start

```bash
# 1. Drop the rules into your Antigravity project
cp -r antigravity/.agents   /path/to/your/project/
cp    antigravity/AGENTS.md /path/to/your/project/

# 2. Or make it global (all projects)
cp -r antigravity/.agents   ~/.gemini/config/
cp    antigravity/AGENTS.md ~/.gemini/AGENTS.md
```

That is the whole install. Antigravity discovers rules from the filesystem automatically —
no configuration step. `00-corpus-index.md` is `always_on` (small: it is just a category map and
the safety rules), and every link category is a `model_decision` rule that the agent pulls in only
when a task matches its description.

**Prefer to keep the corpus out of the rules budget?** Skip the install and just point the agent at
the flat files:

```bash
grep -i "request smuggling" data/all-links.txt
rg -i  "idor"               by-category/05-vuln-classes-reference.md
```

---

## What is in the box

```
antigravity-feed/
├── README.md                ← you are here
├── STRATEGY.md              ← methodology, what pays, target selection, the 7-phase hunt
├── TOP_PROGRAMS.md          ← data-driven guide to 946 real bounty programs
├── BOOKS.md                 ← annotated reading list + 12-month sequence
├── LABS.md                  ← three-tier home-lab build plan
├── INDEX.md                 ← human-readable index of all 17 categories + top-60 picks
│
├── antigravity/             ← DROP-IN PACKAGE
│   ├── AGENTS.md            ← workspace description (always active)
│   └── .agents/rules/
│       ├── 00-corpus-index.md                    always_on  (category map + safety rules)
│       └── 10..26-<category>[-partN].md          model_decision  (64 files, all < 24 KB)
│
├── data/                    ← MACHINE-READABLE CORPUS
│   ├── all-links.txt              9,879 URLs, one per line
│   ├── all-links-core.txt          9,012 URLs, generic OSINT noise removed
│   ├── verified-live-only.txt      7,428 URLs confirmed HTTP 200
│   ├── links.csv                   url, title, category, relevance, verified, status, source
│   ├── links.json                  same, nested, with counts
│   ├── programs-ranked.csv         946 bounty programs: payout, scope size, responsiveness
│   ├── dropped-dead-links.csv      804 dead links excluded, with the reason
│   ├── dropped-unsafe-ssrf-targets.txt   33 SSRF endpoints deliberately stripped (see below)
│   └── stats.json                  pipeline statistics
│
├── by-category/             ← FULL LISTINGS, 17 files, with titles + verification status
│   ├── 01-platforms-bounty-programs.md      (1,041)
│   ├── 02-enterprise-programs-top500.md     (381)
│   ├── 03-writeups-bug-bounty.md            (220)
│   ├── 04-methodology-cheatsheets.md        (108)
│   ├── 05-vuln-classes-reference.md       (1,521)
│   ├── 06-tools-recon.md                  (1,295)
│   ├── 07-tools-exploitation.md           (1,474)
│   ├── 08-labs-vulnerable-apps.md           (116)
│   ├── 09-ctf-platforms-labs.md             (113)
│   ├── 10-writeups-ctf.md                   (717)
│   ├── 11-standards-databases.md            (106)
│   ├── 12-books-courses.md                  (179)
│   ├── 13-mobile-api-cloud-iot.md           (136)
│   ├── 14-ai-llm-security.md                (118)
│   ├── 15-github-security-repos.md        (1,972)
│   ├── 16-youtube-media.md                  (360)
│   └── 17-communities-forums.md              (22)
│
└── work/                    ← REPRODUCIBLE PIPELINE (see "Regenerating")
```

---

## Why it is packaged this way

Antigravity enforces two hard limits on rules
([docs](https://antigravity.google/docs/rules/)):

1. **24,000 bytes per file** — anything larger is truncated.
2. **A 20,000-token aggregate budget** shared by all active `always_on` rules.

Naively dumping 9,879 links into an `AGENTS.md` would blow both. So:

| Mechanism | What it does |
|---|---|
| `00-corpus-index.md` (`always_on`) | Costs a few hundred tokens permanently. Gives the agent the category map and the safety rules. |
| `10..26-*.md` (`model_decision`) | Only the **path + description** is injected upfront. The agent reads the ~200 links in the matching file on demand — progressive disclosure. |
| `data/*.txt`, `*.csv`, `*.json` | Outside the rules budget entirely. The agent `grep`s them instead of loading them. |

64 rule files, largest **19,682 bytes**, all within limits.

---

## Provenance and verification

**Sources** (70+ curated seeds):

- **Awesome-lists** — `awesome-bug-bounty`, `Awesome-Bugbounty-Writeups`, `awesome-web-security`,
  `awesome-pentest`, `awesome-hacking`, `awesome-security`, `awesome-ctf`, `ctf-tools`,
  `awesome-osint`, `awesome-threat-intelligence`, `awesome-honeypots`, `awesome-mobile-security`,
  `android-security-awesome`, `Awesome-WAF`, `awesome-fuzzing`, `awesome-sec-talks`,
  `bugbounty-cheatsheet`, `HowToHunt`, `awesome-pentest-cheat-sheets` and ~20 more.
- **GitHub trees** (whole-repo enumeration) — `sajjadium/ctf-writeups`,
  `perfectblue/ctf-writeups`, `HackTricks-wiki/hacktricks` (1,159 pages),
  `Swisskyrepo/PayloadsAllTheThings`, `projectdiscovery/nuclei-templates` (874 templates).
- **Bounty program dataset** — [arkadiyt/bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data),
  a live scrape of HackerOne (449), Bugcrowd (297), Intigriti (144) and YesWeHack (56) programs
  with scope, payout and responsiveness metadata.
- **Hand-curation** — 722 authoritative anchors: platform directories, vendor VRP/PSIRT pages,
  OWASP standards, NVD/CVE/CWE/CVSS/EPSS/CISA KEV, publisher book pages, lab platforms,
  certifications, conference media.

**Verification** — every one of the 11,094 unique URLs was checked live (HEAD, then a plain
browser-like GET on retry, since some CDNs answer ranged requests with a spurious 404). The counts
below are for that **validation pass over all 11,094**, i.e. *before* safety and low-value
filtering:

| Validation result | Count | Handling |
|---|---|---|
| HTTP 200 (`ok`) | 6,145 | kept, marked ✓ |
| Known-good by construction (GitHub tree blobs) | 1,649 | kept, marked ✓ |
| Anti-bot 403/429 or 5xx | 2,452 | kept, marked ~ — overwhelmingly Cloudflare-protected sites |
| 404 / 410 (`dead`) | 408 | **dropped** |
| DNS failure (`dns-fail`) | 143 | **dropped** |
| Unreachable / timeout | 269 | **dropped** |
| Other HTTP error | 28 | **dropped** |
| **Total checked** | **11,094** | **10,246 passed, 848 failed** |

The `bot-blocked` bucket is dominated by `book.hacktricks.wiki` (1,159) and `hackerone.com` (566) —
both perfectly valid, both behind aggressive bot protection. They are retained but flagged `~` so
you know to confirm them in a browser before citing. A second validation pass with browser-like
headers recovered 131 links the first pass had wrongly marked dead, including 24 PortSwigger and
47 Intigriti pages.

**Filtering** — three exclusion classes were then removed from the 11,094, applied in this order:
first **33** SSRF / cloud-metadata and private-IP targets (safety, see below), then **378**
low-value links — bare GitHub user profiles, `avatars.githubusercontent.com` assets,
Telegram/Discord invites, social-share endpoints, and vendor URLs superseded by a newer official
page (e.g. `facebook.com/whitehat` → `bugbounty.meta.com`) — and finally the **804** URLs that
failed the live check. That is 1,215 removed, leaving **9,879 final**.

The two reconciliations that trip people up, spelled out: safety and low-value filtering run
*before* the status check, so 44 of the 848 validation failures were already accounted for in
those buckets and are not double-counted as dead (848 − 44 = 804). And of the 10,246 that passed
validation, 367 were unsafe or low-value, so 10,246 − 367 = 9,879.

Every exclusion is recorded, so nothing was silently discarded:
`data/dropped-dead-links.csv` (804), `data/dropped-low-value-links.csv` (378),
`data/dropped-unsafe-ssrf-targets.txt` (33).

**Relevance tagging.** 9,012 of 9,879 are `core` (security-specific); 867 are `adjacent`
(general OSINT, incident response and threat-intel material that arrived via `awesome-osint` and
`awesome-threat-intelligence`). Use `data/all-links-core.txt` if you want the tighter set.

---

## Safety filtering — read this

The corpus was harvested partly from **HackTricks**, which documents SSRF against cloud metadata
services. **33 URLs pointing at link-local and internal metadata endpoints were deliberately
stripped** and are recorded in `data/dropped-unsafe-ssrf-targets.txt`:

`169.254.169.254` · `metadata.google.internal` · `100.100.100.200` · `fd00:ec2::254` ·
`*.internal` · `localhost` · RFC-1918 ranges · any bare IP literal

**Why this matters:** if an agent auto-fetches every URL in a corpus, these would hit *its own*
cloud metadata service and could return live credentials. They are attack targets, not reading
material. The same reasoning removed social-share endpoints, tracking parameters, badges and
image assets.

The `00-corpus-index.md` rule additionally encodes standing guardrails for the agent:
authorisation is a precondition for any offensive work; scope, rate limits and safe-harbor terms
must be respected; impact is demonstrated in a local lab and never against a third party;
unreported vulnerabilities and customer data are never published.

---

## Regenerating

The whole corpus is reproducible. Network access required (~5 min end to end, validation ~2 min).

```bash
cd work
gunzip -kf validated.json.gz candidates.json.gz harvest.jsonl.gz 2>/dev/null  # if restoring a snapshot

# --- collect ---------------------------------------------------------------
python3 harvest.py       # awesome-lists, GitHub trees, bounty-targets dataset
python3 harvest2.py      # re-resolve failed seeds via HEAD ref + filename variants
python3 curated.py       # hand-curated authoritative anchors
python3 build.py         # normalise, strip junk, dedupe, classify   -> candidates.json
# --- verify ----------------------------------------------------------------
python3 validate.py      # concurrent HTTP validation (~2 min)       -> validated.json
python3 revalidate.py    # plain-GET retry: some CDNs 404 on ranged requests (recovered 131)
python3 supplement.py    # add / upgrade verified curated URLs
python3 programs.py      # bounty program ranking          -> data/programs-ranked.csv
# --- emit ------------------------------------------------------------------
python3 emit.py          # data/, by-category/, stats.json (safety + low-value filters applied here)
python3 mkantigravity.py # antigravity/.agents/rules/  (64 files, each < 24,000 B)
python3 mkdocs.py        # TOP_PROGRAMS.md, INDEX.md
# --- keep the prose honest --------------------------------------------------
python3 mknums.py        # recompute work/final_numbers.json; asserts every bucket reconciles
python3 syncdocs.py      # idempotently sync each derived figure + by-category ref in the docs
python3 checkdocs.py     # live-check every URL cited in the prose documents
python3 audit.py         # final self-audit: integrity, arithmetic, safety, limits, references
```

`mknums.py` and `audit.py` are the guard rails: `mknums.py` refuses to write a snapshot unless the
validation, drop, relevance and category buckets all sum to the same total, and `audit.py` exits
non-zero on any mismatch, stale figure or broken internal reference. Run them after every
regeneration — note that the validation-pass counts (all 11,094 URLs) and the kept-corpus counts
(9,879) are deliberately tracked as separate scopes, which is why `mknums.py` stores `v*` keys
alongside the plain ones.

**Refresh cadence:** `programs.py` monthly (program scope and payouts change constantly), the full
pipeline quarterly.

---

## Suggested first moves

1. Read `STRATEGY.md` §1–§2 — what actually pays and which bug classes to prioritise.
2. Read `TOP_PROGRAMS.md` §2 — the responsive mid-size paid programs (the realistic income tier).
3. Work through `LABS.md` Tier 1 — start the PortSwigger Academy labs today.
4. Grep the corpus for one vulnerability class and read ten writeups on it.
5. Install the Antigravity package so the corpus is available to your agent as grounding.
