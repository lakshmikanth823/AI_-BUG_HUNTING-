#!/usr/bin/env python3
"""Phase 11: idempotent sync of every derived figure + by-category filename reference."""
import json, os, re, glob
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
N = json.load(open(os.path.join(HERE, "final_numbers.json"), encoding="utf-8"))
P = json.load(open(os.path.join(HERE, "programs_summary.json"), encoding="utf-8"))
L = json.load(open(os.path.join(ROOT, "data", "links.json"), encoding="utf-8"))
C = N["cats"]
f = lambda n: f"{n:,}"

# by-category references are resolved BY NAME, never by number: the rule files are
# numbered 10..26 while by-category/ is 01..17, and a numeric remap silently corrupts
# references that were already correct. Deriving the map from the files on disk makes
# this idempotent and self-healing.
CATFILE = {}
for _p in glob.glob(os.path.join(ROOT, "by-category", "*.md")):
    _b = os.path.basename(_p)
    CATFILE[re.sub(r"^\d\d-", "", _b)[:-3]] = _b   # "books-courses.md" -> "12-books-courses.md"

# validation-stage status counts (from validated.json via links.json + dropped csv)
src = Counter(r.get("source","") for r in
              json.load(open(os.path.join(HERE, "validated.json"), encoding="utf-8"))["candidates"])
NUCLEI = sum(v for k, v in src.items() if "nuclei-templates" in k)
HACKTR = sum(v for k, v in src.items() if "HackTricks-wiki/hacktricks (tree)" in k)

PC = P["platform_counts"]
LVKEPT = N["vkept"] - N["total"]   # unsafe+low-value links that had passed validation

def sub(path, pairs):
    p = os.path.join(ROOT, path)
    s = open(p, encoding="utf-8").read()
    orig = s
    miss = []
    for pat, rep in pairs:
        s2, n = re.subn(pat, rep, s)
        if n == 0: miss.append(pat[:70])
        s = s2
    if s != orig:
        open(p, "w", encoding="utf-8").write(s)
    print(f"  {path}: {'updated' if s != orig else 'unchanged'}"
          + (f"  (unmatched: {miss})" if miss else ""))

# ------------------------------------------------------------------ fix by-category refs
for doc in ["README.md", "STRATEGY.md", "BOOKS.md", "LABS.md", "INDEX.md"]:
    p = os.path.join(ROOT, doc)
    s = open(p, encoding="utf-8").read()
    def fix(m):
        return f"by-category/{CATFILE.get(m.group(2)[:-3], m.group(1) + '-' + m.group(2))}"
    s = re.sub(r"by-category/(\d\d)-([a-z0-9\-]+\.md)", fix, s)
    open(p, "w", encoding="utf-8").write(s)
# same inside the generated always_on rule
p = os.path.join(ROOT, "antigravity/.agents/rules/00-corpus-index.md")
s = open(p, encoding="utf-8").read()
s = re.sub(r"by-category/(\d\d)-([a-z0-9\-]+\.md)",
           lambda m: f"by-category/{CATFILE.get(m.group(2)[:-3], m.group(1) + '-' + m.group(2))}", s)
open(p, "w", encoding="utf-8").write(s)
print("  by-category filename refs normalised")

# ------------------------------------------------------------------ README.md
sub("README.md", [
 (r"\*\*[\d,]+ curated, de-duplicated, individually HTTP-verified security-research URLs\*\*",
  f"**{f(N['total'])} curated, de-duplicated, individually HTTP-verified security-research URLs**"),
 (r"Pipeline: [\d,]+ raw links → [\d,]+ unique after normalisation and",
  f"Pipeline: {f(N['raw'])} raw links → {f(N['uniq'])} unique after normalisation and"),
 (r"de-duplication → [\d,]+ after live HTTP validation and safety filtering\.",
  f"de-duplication → {f(N['total'])} after live HTTP validation and safety filtering."),
 (r"all-links\.txt +[\d,]+ URLs, one per line",
  f"all-links.txt              {f(N['total'])} URLs, one per line"),
 (r"all-links-core\.txt +[\d,]+ URLs, generic OSINT noise removed",
  f"all-links-core.txt          {f(N['core'])} URLs, generic OSINT noise removed"),
 (r"verified-live-only\.txt +[\d,]+ URLs confirmed HTTP 200",
  f"verified-live-only.txt      {f(N['live'])} URLs confirmed HTTP 200"),
 (r"programs-ranked\.csv +[\d,]+ bounty programs",
  f"programs-ranked.csv         {f(N['programs'])} bounty programs"),
 (r"dropped-dead-links\.csv +[\d,]+ dead links excluded",
  f"dropped-dead-links.csv      {f(N['dead'])} dead links excluded"),
 (r"dropped-unsafe-ssrf-targets\.txt +\d+ SSRF endpoints deliberately stripped",
  f"dropped-unsafe-ssrf-targets.txt   {N['unsafe']} SSRF endpoints deliberately stripped"),
 (r"01-platforms-bounty-programs\.md +\([\d,]+\)", f"01-platforms-bounty-programs.md      ({f(C['platforms-bounty-programs'])})"),
 (r"02-enterprise-programs-top500\.md +\([\d,]+\)", f"02-enterprise-programs-top500.md     ({f(C['enterprise-programs-top500'])})"),
 (r"03-writeups-bug-bounty\.md +\([\d,]+\)", f"03-writeups-bug-bounty.md            ({f(C['writeups-bug-bounty'])})"),
 (r"04-methodology-cheatsheets\.md +\([\d,]+\)", f"04-methodology-cheatsheets.md        ({f(C['methodology-cheatsheets'])})"),
 (r"05-vuln-classes-reference\.md +\([\d,]+\)", f"05-vuln-classes-reference.md       ({f(C['vuln-classes-reference'])})"),
 (r"06-tools-recon\.md +\([\d,]+\)", f"06-tools-recon.md                  ({f(C['tools-recon'])})"),
 (r"07-tools-exploitation\.md +\([\d,]+\)", f"07-tools-exploitation.md           ({f(C['tools-exploitation'])})"),
 (r"08-labs-vulnerable-apps\.md +\([\d,]+\)", f"08-labs-vulnerable-apps.md           ({f(C['labs-vulnerable-apps'])})"),
 (r"09-ctf-platforms-labs\.md +\([\d,]+\)", f"09-ctf-platforms-labs.md             ({f(C['ctf-platforms-labs'])})"),
 (r"10-writeups-ctf\.md +\([\d,]+\)", f"10-writeups-ctf.md                   ({f(C['writeups-ctf'])})"),
 (r"11-standards-databases\.md +\([\d,]+\)", f"11-standards-databases.md            ({f(C['standards-databases'])})"),
 (r"12-books-courses\.md +\([\d,]+\)", f"12-books-courses.md                  ({f(C['books-courses'])})"),
 (r"13-mobile-api-cloud-iot\.md +\([\d,]+\)", f"13-mobile-api-cloud-iot.md           ({f(C['mobile-api-cloud-iot'])})"),
 (r"14-ai-llm-security\.md +\([\d,]+\)", f"14-ai-llm-security.md                ({f(C['ai-llm-security'])})"),
 (r"15-github-security-repos\.md +\([\d,]+\)", f"15-github-security-repos.md        ({f(C['github-security-repos'])})"),
 (r"16-youtube-media\.md +\([\d,]+\)", f"16-youtube-media.md                  ({f(C['youtube-media'])})"),
 (r"17-communities-forums\.md +\([\d,]+\)", f"17-communities-forums.md              ({f(C['communities-forums'])})"),
 (r"\d+ rule files, largest \*\*[\d,]+ bytes\*\*, all within limits\.",
  f"{N['rules']} rule files, largest **{f(N['maxb'])} bytes**, all within limits."),
 (r"model_decision  \(\d+ files, all < 24 KB\)",
  f"model_decision  ({N['rules']} files, all < 24 KB)"),
 (r"Naively dumping [\d,]+ links into an `AGENTS\.md`", f"Naively dumping {f(N['total'])} links into an `AGENTS.md`"),
 # validation-pass table (v* keys = all 11,094 uniques, NOT the kept set)
 (r"\*\*Verification\*\* — every one of the [\d,]+ unique URLs was checked live \(HEAD",
  f"**Verification** — every one of the {f(N['uniq'])} unique URLs was checked live (HEAD"),
 (r"below are for that \*\*validation pass over all [\d,]+\*\*",
  f"below are for that **validation pass over all {f(N['uniq'])}**"),
 (r"\| HTTP 200 \(`ok`\) \| [\d,]+ \|", f"| HTTP 200 (`ok`) | {f(N['vok'])} |"),
 (r"\| Known-good by construction \(GitHub tree blobs\) \| [\d,]+ \|",
  f"| Known-good by construction (GitHub tree blobs) | {f(N['vskip'])} |"),
 (r"\| Anti-bot 403/429 or 5xx \| [\d,]+ \|",
  f"| Anti-bot 403/429 or 5xx | {f(N['vblock']+N['vserr'])} |"),
 (r"\| 404 / 410 \(`dead`\) \| [\d,]+ \|", f"| 404 / 410 (`dead`) | {f(N['vdead'])} |"),
 (r"\| DNS failure \(`dns-fail`\) \| [\d,]+ \|", f"| DNS failure (`dns-fail`) | {f(N['vdns'])} |"),
 (r"\| Unreachable / timeout \| [\d,]+ \|", f"| Unreachable / timeout | {f(N['vunreach'])} |"),
 (r"\| Other HTTP error \| [\d,]+ \|", f"| Other HTTP error | {f(N['vhttp'])} |"),
 (r"\| \*\*Total checked\*\* \| \*\*[\d,]+\*\* \| \*\*[\d,]+ passed, [\d,]+ failed\*\* \|",
  f"| **Total checked** | **{f(N['uniq'])}** | **{f(N['vkept'])} passed, {f(N['vfail'])} failed** |"),
 # filtering paragraph (emit.py order: unsafe -> low-value -> dead)
 (r"first \*\*\d+\*\* SSRF / cloud-metadata and private-IP targets",
  f"first **{N['unsafe']}** SSRF / cloud-metadata and private-IP targets"),
 (r"then \*\*[\d,]+\*\*\nlow-value links", f"then **{f(N['low'])}**\nlow-value links"),
 (r"and finally the \*\*[\d,]+\*\* URLs that\nfailed the live check",
  f"and finally the **{f(N['dead'])}** URLs that\nfailed the live check"),
 (r"That is [\d,]+ removed, leaving \*\*[\d,]+ final\*\*",
  f"That is {f(N['unsafe']+N['low']+N['dead'])} removed, leaving **{f(N['total'])} final**"),
 (r"so \d+ of the [\d,]+ validation failures", f"so {N['overlap']} of the {f(N['vfail'])} validation failures"),
 (r"\([\d,]+ − \d+ = [\d,]+\)", f"({f(N['vfail'])} − {N['overlap']} = {f(N['dead'])})"),
 (r"And of the [\d,]+ that passed\nvalidation, [\d,]+ were unsafe or low-value, so [\d,]+ − [\d,]+ = [\d,]+\.",
  f"And of the {f(N['vkept'])} that passed\nvalidation, {f(LVKEPT)} were unsafe or low-value, so "
  f"{f(N['vkept'])} − {f(LVKEPT)} = {f(N['total'])}."),
 (r"`data/dropped-dead-links\.csv` \([\d,]+\), `data/dropped-low-value-links\.csv` \([\d,]+\),",
  f"`data/dropped-dead-links.csv` ({f(N['dead'])}), `data/dropped-low-value-links.csv` ({f(N['low'])}),"),
 (r"`data/dropped-unsafe-ssrf-targets\.txt` \(\d+\)\.",
  f"`data/dropped-unsafe-ssrf-targets.txt` ({N['unsafe']})."),
 (r"\*\*Relevance tagging\.\*\* [\d,]+ of [\d,]+ are `core` \(security-specific\); [\d,]+ are `adjacent`",
  f"**Relevance tagging.** {f(N['core'])} of {f(N['total'])} are `core` (security-specific); {f(N['adj'])} are `adjacent`"),
 (r"\*\*\d+ URLs pointing at link-local and internal metadata endpoints were deliberately",
  f"**{N['unsafe']} URLs pointing at link-local and internal metadata endpoints were deliberately"),
 (r"HackerOne \(\d+\), Bugcrowd \(\d+\), Intigriti \(\d+\) and YesWeHack \(\d+\) programs",
  f"HackerOne ({PC['HackerOne']}), Bugcrowd ({PC['Bugcrowd']}), Intigriti ({PC['Intigriti']}) and YesWeHack ({PC['YesWeHack']}) programs"),
 (r"nuclei-templates` \([\d,]+ templates\)", f"nuclei-templates` ({NUCLEI} templates)"),
 (r"`HackTricks-wiki/hacktricks` \([\d,]+ pages\)", f"`HackTricks-wiki/hacktricks` ({f(HACKTR)} pages)"),
 (r"← data-driven guide to [\d,]+ real bounty programs",
  f"← data-driven guide to {f(N['programs'])} real bounty programs"),
])

# ------------------------------------------------------------------ STRATEGY.md
sub("STRATEGY.md", [
 (r"a corpus of \*\*[\d,]+ verified security-research URLs\*\*", f"a corpus of **{f(N['total'])} verified security-research URLs**"),
 (r"\*\*Program data:\*\* [\d,]+ live programs", f"**Program data:** {f(N['programs'])} live programs"),
 (r"From the [\d,]+ programs in `data/programs-ranked\.csv`", f"From the {f(N['programs'])} programs in `data/programs-ranked.csv`"),
 (r"\(([\d,]+) links\): OWASP LLM Top 10", f"({f(C['ai-llm-security'])} links): OWASP LLM Top 10"),
 (r"`by-category/06-tools-recon\.md` \(([\d,]+) links\)", f"`by-category/06-tools-recon.md` ({f(C['tools-recon'])} links)"),
 (r"`by-category/05-vuln-classes-reference\.md` \(([\d,]+) links\) and", f"`by-category/05-vuln-classes-reference.md` ({f(C['vuln-classes-reference'])} links) and"),
 (r"`by-category/06-tools-recon\.md` \(([\d,]+)\) and `07-tools-exploitation\.md` \(([\d,]+)\)",
  f"`by-category/06-tools-recon.md` ({f(C['tools-recon'])}) and `07-tools-exploitation.md` ({f(C['tools-exploitation'])})"),
 (r"`by-category/08-labs-vulnerable-apps\.md` \(([\d,]+)\) · `09-ctf-platforms-labs\.md` \(([\d,]+)\) ·",
  f"`by-category/08-labs-vulnerable-apps.md` ({f(C['labs-vulnerable-apps'])}) · `09-ctf-platforms-labs.md` ({f(C['ctf-platforms-labs'])}) ·"),
 (r"`10-writeups-ctf\.md` \(([\d,]+)\)", f"`10-writeups-ctf.md` ({f(C['writeups-ctf'])})"),
 (r"`by-category/03-writeups-bug-bounty\.md`\n\(([\d,]+) links\)", f"`by-category/03-writeups-bug-bounty.md`\n({f(C['writeups-bug-bounty'])} links)"),
 (r"\(([\d,]+) links in `by-category/12-books-courses\.md`\)", f"({f(C['books-courses'])} links in `by-category/12-books-courses.md`)"),
 (r"# \d+ files total, [\d,]+ links, max [\d.]+ KB each",
  f"# {N['rules']} files total, {f(N['total'])} links, max {N['maxb']/1000:.1f} KB each"),
 (r"\*\*Verification:\*\* every URL was checked live\. [\d,]+ returned HTTP 200\. [\d,]+ returned an",
  f"**Verification:** every URL was checked live. {f(N['live'])} returned HTTP 200. {f(N['antibot'])} returned an"),
 (r"[\d,]+ confirmed-dead links were dropped", f"{f(N['dead'])} confirmed-dead links were dropped"),
 (r"\*\*Pipeline:\*\* [\d,]+ raw links harvested → [\d,]+ unique after normalisation and de-duplication →\n[\d,]+ after live validation and safety filtering\.",
  f"**Pipeline:** {f(N['raw'])} raw links harvested → {f(N['uniq'])} unique after normalisation and de-duplication →\n{f(N['total'])} after live validation and safety filtering."),
 (r"\| Methodology, checklists & cheat sheets \| [\d,]+ \|", f"| Methodology, checklists & cheat sheets | {f(C['methodology-cheatsheets'])} |"),
 (r"\| Recon & asset discovery tools \| [\d,]+ \|", f"| Recon & asset discovery tools | {f(C['tools-recon'])} |"),
 (r"\| Exploitation, scanning & fuzzing tools \| [\d,]+ \|", f"| Exploitation, scanning & fuzzing tools | {f(C['tools-exploitation'])} |"),
 (r"\| Vulnerable apps & practice labs \| [\d,]+ \|", f"| Vulnerable apps & practice labs | {f(C['labs-vulnerable-apps'])} |"),
 (r"\| CTF platforms & training ranges \| [\d,]+ \|", f"| CTF platforms & training ranges | {f(C['ctf-platforms-labs'])} |"),
 (r"\| CTF writeups & archives \| [\d,]+ \|", f"| CTF writeups & archives | {f(C['writeups-ctf'])} |"),
 (r"\| Vulnerability class reference & payloads \| [\d,]+ \|", f"| Vulnerability class reference & payloads | {f(C['vuln-classes-reference'])} |"),
 (r"\| Bug bounty platforms & program directories \| [\d,]+ \|", f"| Bug bounty platforms & program directories | {f(C['platforms-bounty-programs'])} |"),
 (r"\| Enterprise / Fortune-500 program pages \| [\d,]+ \|", f"| Enterprise / Fortune-500 program pages | {f(C['enterprise-programs-top500'])} |"),
 (r"\| Bug bounty writeups & disclosed reports \| [\d,]+ \|", f"| Bug bounty writeups & disclosed reports | {f(C['writeups-bug-bounty'])} |"),
 (r"\| Vulnerability databases, standards & threat intel \| [\d,]+ \|", f"| Vulnerability databases, standards & threat intel | {f(C['standards-databases'])} |"),
 (r"\| Books, courses & certifications \| [\d,]+ \|", f"| Books, courses & certifications | {f(C['books-courses'])} |"),
 (r"\| Mobile, API, cloud, IoT & OT security \| [\d,]+ \|", f"| Mobile, API, cloud, IoT & OT security | {f(C['mobile-api-cloud-iot'])} |"),
 (r"\| AI / LLM & agentic security \| [\d,]+ \|", f"| AI / LLM & agentic security | {f(C['ai-llm-security'])} |"),
 (r"\| GitHub security repos & awesome lists \| [\d,]+ \|", f"| GitHub security repos & awesome lists | {f(C['github-security-repos'])} |"),
 (r"\| Talks, conferences, video & podcasts \| [\d,]+ \|", f"| Talks, conferences, video & podcasts | {f(C['youtube-media'])} |"),
 (r"\| Communities, forums & Discords \| [\d,]+ \|", f"| Communities, forums & Discords | {f(C['communities-forums'])} |"),
 (r"\| \*\*Total\*\* \| \*\*[\d,]+\*\* \| \|", f"| **Total** | **{f(N['total'])}** | |"),
 (r"\*\*\d+ URLs pointing at link-local and internal metadata endpoints were stripped\*\*",
  f"**{N['unsafe']} URLs pointing at link-local and internal metadata endpoints were stripped**"),
])

# ------------------------------------------------------------------ LABS.md / BOOKS.md
sub("LABS.md", [
 (r"\*\*\d+ vulnerable-app links\*\*", f"**{C['labs-vulnerable-apps']} vulnerable-app links**"),
 (r"\*\*\d+ platform\nlinks\*\*", f"**{C['ctf-platforms-labs']} platform\nlinks**"),
])
sub("BOOKS.md", [
 (r"\*\*\d+ book / course / certification links\*\*", f"**{C['books-courses']} book / course / certification links**"),
 (r"in the\nAntigravity rule `21-books-courses-part\{1,2\}\.md`", "in the\nAntigravity rule `21-books-courses-part{1,2}.md`"),
])
print("\nsync complete")
