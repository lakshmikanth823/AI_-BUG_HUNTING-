#!/usr/bin/env python3
"""
Phase 1: Harvest security-research URLs from high-density curated sources.

Sources are of three kinds:
  md   -> raw markdown file; extract [text](url) + bare URLs
  tree -> GitHub git-trees API; enumerate repo files and build URLs
  json -> special JSON datasets (e.g. bounty program scrapes)

Output: work/harvest.jsonl  (one record per raw hit, pre-dedupe)
"""
import json, re, os, ssl, sys, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

OUT = os.path.join(os.path.dirname(__file__), "harvest.jsonl")
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept": "*/*"}
CTX = ssl.create_default_context()

# ---------------------------------------------------------------- seed sources
# (category, kind, url, note)
MD_SEEDS = [
    # ---- bug bounty writeups / reports / methodology
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/devanshbatham/Awesome-Bugbounty-Writeups/master/README.md", "Awesome-Bugbounty-Writeups"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/devanshbatham/Awesome-Bugbounty-Writeups/main/README.md",   "Awesome-Bugbounty-Writeups(main)"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/djadmin/awesome-bug-bounty/master/README.md",                "awesome-bug-bounty"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/djadmin/awesome-bug-bounty/main/README.md",                  "awesome-bug-bounty(main)"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/readme.md",               "hackerone-reports top disclosed"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/reddelexc/hackerone-reports/main/readme.md",                 "hackerone-reports(main)"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/master/README.md",           "bugbounty-cheatsheet"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/main/README.md",             "bugbounty-cheatsheet(main)"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/codebygk/hackerone-bug-bounty-reports/main/README.md",       "hackerone-bug-bounty-reports"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/nahamsec/Resources-For-Beginner-Bug-Bounty-Hunters/master/README.md", "Nahamsec beginner resources"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/nahamsec/Resources-For-Beginner-Bug-Bounty-Hunters/main/README.md",   "Nahamsec beginner resources(main)"),
    ("writeups-bug-bounty",   "md", "https://raw.githubusercontent.com/bughunters/google-vrp-writeups/main/README.md",             "Google VRP writeups"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/KathanP19/HowToHunt/master/README.md",                       "HowToHunt methodology"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/KathanP19/HowToHunt/main/README.md",                         "HowToHunt(main)"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/bugcrowd/bugcrowd-university/main/README.md",                "Bugcrowd University"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/InsiderPhD/PhD-Security/master/README.md",                   "InsiderPhD resources"),

    # ---- web application security reference
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/qazbnm456/awesome-web-security/master/README.md",           "awesome-web-security"),
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/qazbnm456/awesome-web-security/main/README.md",             "awesome-web-security(main)"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/Owasp/cheatsheets/main/README.md",                           "OWASP Cheat Sheets repo"),
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/0xInfection/Awesome-WAF/master/README.md",                  "Awesome-WAF"),
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/0xInfection/Awesome-WAF/main/README.md",                    "Awesome-WAF(main)"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/coreb1t/awesome-pentest-cheat-sheets/master/README.md",      "awesome-pentest-cheat-sheets"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/riramar/hsec-cheatsheets/master/README.md",                 "hsec-cheatsheets"),
    ("methodology-cheatsheets","md","https://raw.githubusercontent.com/riramar/hsec-cheatsheets/main/README.md",                   "hsec-cheatsheets(main)"),

    # ---- general hacking / pentest mega-lists
    ("github-security-repos", "md", "https://raw.githubusercontent.com/enaqx/awesome-pentest/master/README.md",                    "awesome-pentest"),
    ("github-security-repos", "md", "https://raw.githubusercontent.com/enaqx/awesome-pentest/main/README.md",                      "awesome-pentest(main)"),
    ("github-security-repos", "md", "https://raw.githubusercontent.com/carpedm20/awesome-hacking/master/README.md",                "awesome-hacking"),
    ("github-security-repos", "md", "https://raw.githubusercontent.com/carpedm20/awesome-hacking/main/README.md",                  "awesome-hacking(main)"),
    ("github-security-repos", "md", "https://raw.githubusercontent.com/Hack-with-Github/Awesome-Hacking/master/README.md",         "Hack-with-Github Awesome-Hacking"),
    ("github-security-repos", "md", "https://raw.githubusercontent.com/sbilly/awesome-security/master/README.md",                  "awesome-security"),
    ("github-security-repos", "md", "https://raw.githubusercontent.com/sbilly/awesome-security/main/README.md",                    "awesome-security(main)"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/m4ll0k/Awesome-Hacking/master/README.md",                   "m4ll0k Awesome-Hacking"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/m4ll0k/Awesome-BugBounty-Tools/master/README.md",           "Awesome-BugBounty-Tools"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/m4ll0k/Awesome-BugBounty-Tools/main/README.md",             "Awesome-BugBounty-Tools(main)"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/demonsec666/awesome-hacking-tools/master/README.md",        "awesome-hacking-tools"),

    # ---- CTF
    ("ctf-platforms-labs",    "md", "https://raw.githubusercontent.com/apsdehal/awesome-ctf/master/README.md",                     "awesome-ctf"),
    ("ctf-platforms-labs",    "md", "https://raw.githubusercontent.com/apsdehal/awesome-ctf/main/README.md",                       "awesome-ctf(main)"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/zardus/ctf-tools/master/README.md",                         "ctf-tools"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/zardus/ctf-tools/main/README.md",                           "ctf-tools(main)"),
    ("writeups-ctf",          "md", "https://raw.githubusercontent.com/w181496/Web-CTF-Cheatsheet/master/README.md",               "Web-CTF-Cheatsheet"),
    ("writeups-ctf",          "md", "https://raw.githubusercontent.com/w181496/Web-CTF-Cheatsheet/main/README.md",                 "Web-CTF-Cheatsheet(main)"),
    ("writeups-ctf",          "md", "https://raw.githubusercontent.com/D13David/CTF-writeups/master/README.md",                    "D13David CTF-writeups"),
    ("writeups-ctf",          "md", "https://raw.githubusercontent.com/team-bitsctf/... /placeholder",                             "placeholder-skip"),
    ("ctf-platforms-labs",    "md", "https://raw.githubusercontent.com/zer0pts/awesome-ctf/master/README.md",                      "zer0pts awesome-ctf"),
    ("ctf-platforms-labs",    "md", "https://raw.githubusercontent.com/itaymigdal/awesome-ctfs/main/README.md",                    "awesome-ctfs"),

    # ---- mobile / API / cloud / IoT
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/ashishb/android-security-awesome/master/README.md",         "android-security-awesome"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/ashishb/android-security-awesome/main/README.md",           "android-security-awesome(main)"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/vaib25vicky/awesome-mobile-security/master/README.md",      "awesome-mobile-security"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/vaib25vicky/awesome-mobile-security/main/README.md",        "awesome-mobile-security(main)"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/tanprathan/MobileApp-Pentest-Cheatsheet/master/README.md",  "MobileApp-Pentest-Cheatsheet"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/mgeeky/Pentest-Resources-Cheat-Sheets/master/README.md",    "Pentest-Resources-Cheat-Sheets"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/dafthack/CloudPentestCheatsheets/master/README.md",         "CloudPentestCheatsheets"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/OWASP/www-project-api-security/master/descriptions/README.md","OWASP API Security (may 404)"),
    ("mobile-api-cloud-iot",  "md", "https://raw.githubusercontent.com/trendyol/... /placeholder",                                 "placeholder-skip"),

    # ---- reverse engineering / binary / exploit dev
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/wtsxDev/reverse-engineering/master/README.md",              "awesome reverse-engineering"),
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/wtsxDev/reverse-engineering/main/README.md",                "reverse-engineering(main)"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/secfigo/Awesome-Fuzzing/master/README.md",                 "Awesome-Fuzzing"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/cpuu/awesome-fuzzing/master/README.md",                    "awesome-fuzzing"),
    ("tools-exploitation",    "md", "https://raw.githubusercontent.com/n132/Armo-Wiki/main/README.md",                             "Armo-Wiki binary"),
    ("vuln-classes-reference","md", "https://raw.githubusercontent.com/nightninja/... /placeholder",                               "placeholder-skip"),

    # ---- threat intel / IR / OSINT (adjacent, useful for recon)
    ("tools-recon",           "md", "https://raw.githubusercontent.com/jivoi/awesome-osint/master/README.md",                      "awesome-osint"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/jivoi/awesome-osint/main/README.md",                        "awesome-osint(main)"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/hslatman/awesome-threat-intelligence/master/README.md",     "awesome-threat-intelligence"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/hslatman/awesome-threat-intelligence/main/README.md",       "awesome-threat-intelligence(main)"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/meirwah/awesome-incident-response/master/README.md",        "awesome-incident-response"),
    ("tools-recon",           "md", "https://raw.githubusercontent.com/paralax/awesome-honeypots/master/README.md",               "awesome-honeypots"),

    # ---- AI / LLM security (2025-2026 frontier)
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/adamtlangley/awesome-llm-security/main/README.md",         "awesome-llm-security"),
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/dsopas/assessment-mindset/main/README.md",                 "assessment-mindset"),
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/FrancescoDiSale/... /placeholder",                          "placeholder-skip"),
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/myexploit26/... /placeholder",                              "placeholder-skip"),
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/rubberduck/... /placeholder",                               "placeholder-skip"),
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/protectai/awesome-llm-security/main/README.md",            "protectai awesome-llm-security"),
    ("ai-llm-security",       "md", "https://raw.githubusercontent.com/Klarc/awesome-llm-security/main/README.md",                "Klarc awesome-llm-security"),

    # ---- labs / vulnerable apps / home-lab
    ("labs-vulnerable-apps",  "md", "https://raw.githubusercontent.com/juice-shop/juice-shop/master/README.md",                    "OWASP Juice Shop"),
    ("labs-vulnerable-apps",  "md", "https://raw.githubusercontent.com/OWASP/WebGoat/main/README.md",                              "OWASP WebGoat"),
    ("labs-vulnerable-apps",  "md", "https://raw.githubusercontent.com/digininja/DVWA/master/README.md",                          "DVWA"),
    ("labs-vulnerable-apps",  "md", "https://raw.githubusercontent.com/raesene/... /placeholder",                                  "placeholder-skip"),
    ("lab-setup-guides",      "md", "https://raw.githubusercontent.com/gruntwork-io/... /placeholder",                             "placeholder-skip"),
    ("lab-setup-guides",      "md", "https://raw.githubusercontent.com/jonathandion/awesome-home-lab/main/README.md",             "awesome-home-lab"),
    ("lab-setup-guides",      "md", "https://raw.githubusercontent.com/jonathandion/awesome-home-lab/master/README.md",           "awesome-home-lab(master)"),
    ("lab-setup-guides",      "md", "https://raw.githubusercontent.com/notdls/... /placeholder",                                   "placeholder-skip"),
    ("lab-setup-guides",      "md", "https://raw.githubusercontent.com/xbgoose/... /placeholder",                                  "placeholder-skip"),

    # ---- talks / media / newsletters
    ("youtube-media",         "md", "https://raw.githubusercontent.com/PaulSec/awesome-sec-talks/master/README.md",               "awesome-sec-talks"),
    ("youtube-media",         "md", "https://raw.githubusercontent.com/PaulSec/awesome-sec-talks/main/README.md",                 "awesome-sec-talks(main)"),
    ("books-courses",         "md", "https://raw.githubusercontent.com/Hack-with-Github/... /placeholder",                         "placeholder-skip"),
    ("books-courses",         "md", "https://raw.githubusercontent.com/tyler/... /placeholder",                                    "placeholder-skip"),
]

# GitHub repos enumerated via git-trees API -> build URLs from paths
TREE_SEEDS = [
    # (category, repo, branch, path_filter_regex, url_builder, cap)
    ("writeups-ctf",        "sajjadium/ctf-writeups",            "master", None, "github_blob", 1200),
    ("writeups-ctf",        "perfectblue/ctf-writeups",          "master", None, "github_blob", 400),
    ("vuln-classes-reference","HackTricks-wiki/hacktricks",      "master", r"\.md$", "hacktricks", 1500),
    ("vuln-classes-reference","Swisskyrepo/PayloadsAllTheThings","master", r"\.md$", "github_blob", 600),
    ("tools-exploitation",  "projectdiscovery/nuclei-templates", "main",   r"\.yaml$", "github_blob", 900),
]

# ---------------------------------------------------------------- helpers
def fetch(url, timeout=25, tries=2):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and i == 0:
                time.sleep(2 + i * 3); continue
            return e.code, b""
        except Exception:
            if i == 0:
                time.sleep(1); continue
            return 0, b""
    return 0, b""

LINK_RE  = re.compile(r"\[([^\]]*)\]\(\s*(<?https?://[^)\s>]+>?)")
BARE_RE  = re.compile(r"(?<![\(\[])((?:https?://)[^\s<>\)\"\']+)")

def extract_md(text):
    out = []
    for m in LINK_RE.finditer(text):
        title, u = m.group(1).strip(), m.group(2).strip().strip("<>")
        out.append((u, title))
    linked = {u for u, _ in out}
    for m in BARE_RE.finditer(text):
        u = m.group(1)
        if u not in linked:
            out.append((u, ""))
    return out

records = []
def add(cat, url, title, source):
    records.append({"category": cat, "url": url.strip(), "title": title.strip(), "source": source})

# ---------------------------------------------------------------- phase A: markdown
def do_md(seed):
    cat, kind, url, note = seed
    if "placeholder" in url:
        return note, 0
    st, body = fetch(url)
    if st != 200 or not body:
        return note, 0
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        return note, 0
    hits = extract_md(text)
    for u, t in hits:
        add(cat, u, t, note)
    return note, len(hits)

print("=== Phase A: markdown seeds ===")
md_seeds = [s for s in MD_SEEDS if s[1] == "md" and "placeholder" not in s[2]]
with ThreadPoolExecutor(max_workers=12) as ex:
    futs = {ex.submit(do_md, s): s for s in md_seeds}
    for f in as_completed(futs):
        note, n = f.result()
        print(f"  {n:5d}  {note}")
print(f"  md records: {len(records)}")

# ---------------------------------------------------------------- phase B: github trees
def gh_tree(repo, branch):
    for b in (branch, "main", "master"):
        url = f"https://api.github.com/repos/{repo}/git/trees/{b}?recursive=1"
        st, body = fetch(url, timeout=60)
        if st == 200 and body:
            try:
                return json.loads(body.decode("utf-8", "replace"))
            except Exception:
                pass
    return None

def do_tree(seed):
    cat, repo, branch, filt, builder, cap = seed
    data = gh_tree(repo, branch)
    if not data:
        print(f"  FAIL tree {repo}"); return
    paths = []
    for e in data.get("tree", []):
        if e.get("type") != "blob":
            continue
        p = e.get("path", "")
        if filt and not re.search(filt, p, re.I):
            continue
        paths.append(p)
    if data.get("truncated"):
        print(f"  NOTE {repo} tree truncated")
    paths = paths[:cap]
    default_branch = data.get("tree") and branch or "main"
    n = 0
    for p in paths:
        enc = urllib.parse.quote(p)
        if builder == "github_blob":
            u = f"https://github.com/{repo}/blob/{branch}/{enc}"
            t = p.split("/")[-1]
        elif builder == "hacktricks":
            # file path -> book.hacktricks.wiki page path
            rel = p[:-3] if p.lower().endswith(".md") else p
            if rel.lower() in ("readme", "summary", "index"):
                continue
            u = "https://book.hacktricks.wiki/en/" + enc[:-3]
            t = p.split("/")[-1][:-3]
        else:
            continue
        add(cat, u, t, f"{repo} (tree)")
        n += 1
    print(f"  {n:5d}  tree {repo}")

print("=== Phase B: github trees ===")
for seed in TREE_SEEDS:
    try:
        do_tree(seed)
    except Exception as e:
        print(f"  ERR {seed[1]}: {e}")

# ---------------------------------------------------------------- phase C: bounty program dataset
print("=== Phase C: bounty program datasets ===")
def do_bounties():
    base = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
    n = 0
    for fn, cat in [("hackerone_data.json", "platforms-bounty-programs"),
                    ("bugcrowd_data.json", "platforms-bounty-programs"),
                    ("intigriti_data.json", "platforms-bounty-programs"),
                    ("yeswehack_data.json", "platforms-bounty-programs"),
                    ("synack_data.json", "platforms-bounty-programs"),
                    ("hackerone_data.json", None)]:
        if cat is None:
            break
        st, body = fetch(f"{base}/{fn}", timeout=60)
        if st != 200 or not body:
            print(f"  FAIL {fn} ({st})"); continue
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except Exception as e:
            print(f"  PARSE FAIL {fn}: {e}"); continue
        for prog in data:
            handle = prog.get("handle") or prog.get("code") or prog.get("id") or ""
            name   = prog.get("name") or handle
            url    = prog.get("url") or ""
            if not url and handle and fn.startswith("hackerone"):
                url = f"https://hackerone.com/{handle}"
            if not url and handle and fn.startswith("bugcrowd"):
                url = f"https://bugcrowd.com/{handle}"
            if url:
                records.append({"category": cat, "url": url, "title": name,
                                "source": fn, "program": name, "handle": handle,
                                "bounty": prog.get("offers_bounties", False),
                                "raw": {k: prog.get(k) for k in
                                        ("max_bounty", "offers_bounties", "targets",
                                         "managed", "state", "bookmarked")}})
                n += 1
        print(f"  {len(data):5d} programs in {fn}")
    print(f"  bounty records: {n}")

try:
    do_bounties()
except Exception as e:
    print("  ERR bounties:", e)

# ---------------------------------------------------------------- write
with open(OUT, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"\nTOTAL raw records: {len(records)} -> {OUT}")
