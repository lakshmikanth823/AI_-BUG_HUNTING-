#!/usr/bin/env python3
"""Phase 1b: fix failed seeds (HEAD ref + filename variants) and add more."""
import json, re, os, ssl, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "harvest.jsonl")
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
CTX = ssl.create_default_context()

def fetch(url, timeout=25, tries=2):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout, context=CTX) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            if i == 0: time.sleep(1); continue
            return 0, b""
    return 0, b""

LINK_RE = re.compile(r"\[([^\]]*)\]\(\s*(<?https?://[^)\s>]+>?)")
BARE_RE = re.compile(r"(?<![\(\[])((?:https?://)[^\s<>\)\"\']+)")

def extract_md(text):
    out = []
    for m in LINK_RE.finditer(text):
        out.append((m.group(2).strip().strip("<>"), m.group(1).strip()))
    seen = {u for u, _ in out}
    for m in BARE_RE.finditer(text):
        if m.group(1) not in seen: out.append((m.group(1), ""))
    return out

NAMES = ["README.md", "readme.md", "Readme.md", "README.MD", "README", "index.md", "ReadMe.md"]

def get_readme(repo):
    """Try HEAD ref across common readme filenames (no API rate limit)."""
    for n in NAMES:
        st, body = fetch(f"https://raw.githubusercontent.com/{repo}/HEAD/{n}", timeout=20)
        if st == 200 and body and len(body) > 200:
            return n, body.decode("utf-8", "replace")
    # fall back to API readme endpoint
    st, body = fetch(f"https://api.github.com/repos/{repo}/readme", timeout=30)
    if st == 200 and body:
        try:
            import base64
            d = json.loads(body.decode("utf-8", "replace"))
            return d.get("name", "?"), base64.b64decode(d["content"]).decode("utf-8", "replace")
        except Exception: pass
    return None, ""

# repos that failed in phase A, plus new high-value additions
RETRY = [
    ("writeups-bug-bounty",     "devanshbatham/Awesome-Bugbounty-Writeups"),
    ("writeups-bug-bounty",     "djadmin/awesome-bug-bounty"),
    ("writeups-bug-bounty",     "reddelexc/hackerone-reports"),
    ("writeups-bug-bounty",     "codebygk/hackerone-bug-bounty-reports"),
    ("writeups-bug-bounty",     "nahamsec/Resources-For-Beginner-Bug-Bounty-Hunters"),
    ("writeups-bug-bounty",     "m4ll0k/Awesome-BugBounty-Writeups"),
    ("writeups-bug-bounty",     "nahoole/bug-bounty-writeups"),
    ("writeups-bug-bounty",     "th3g3nt3l/most-common-passwords"),
    ("methodology-cheatsheets", "EdOverflow/bugbounty-cheatsheet"),
    ("methodology-cheatsheets", "KathanP19/HowToHunt"),
    ("methodology-cheatsheets", "bugcrowd/bugcrowd-university"),
    ("methodology-cheatsheets", "OWASP/CheatSheetSeries"),
    ("methodology-cheatsheets", "coreb1t/awesome-pentest-cheat-sheets"),
    ("methodology-cheatsheets", "riramar/hsec-cheatsheets"),
    ("methodology-cheatsheets", "mgeeky/Pentest-Resources-Cheat-Sheets"),
    ("methodology-cheatsheets", "dafthack/CloudPentestCheatsheets"),
    ("methodology-cheatsheets", "HackTricks-wiki/hacktricks"),
    ("tools-recon",             "m4ll0k/Awesome-BugBounty-Tools"),
    ("tools-recon",             "edoardottt/awesome-hackerone-api"),
    ("tools-exploitation",      "m4ll0k/Awesome-Hacking"),
    ("tools-exploitation",      "demonsec666/awesome-hacking-tools"),
    ("tools-exploitation",      "zricethezav/gitleaks"),
    ("vuln-classes-reference",  "qazbnm456/awesome-web-security"),
    ("vuln-classes-reference",  "0xInfection/Awesome-WAF"),
    ("vuln-classes-reference",  "wtsxDev/reverse-engineering"),
    ("vuln-classes-reference",  "OWASP/wstg"),
    ("vuln-classes-reference",  "OWASP/ASVS"),
    ("ctf-platforms-labs",      "apsdehal/awesome-ctf"),
    ("ctf-platforms-labs",      "itaymigdal/awesome-ctfs"),
    ("ctf-platforms-labs",      "zer0pts/awesome-ctf"),
    ("ctf-platforms-labs",      "TeamSparta/CTF-Learning-Resources"),
    ("writeups-ctf",            "w181496/Web-CTF-Cheatsheet"),
    ("writeups-ctf",            "D13David/CTF-writeups"),
    ("writeups-ctf",            "perfectblue/ctf-writeups"),
    ("writeups-ctf",            "google/google-ctf"),
    ("mobile-api-cloud-iot",    "ashishb/android-security-awesome"),
    ("mobile-api-cloud-iot",    "vaib25vicky/awesome-mobile-security"),
    ("mobile-api-cloud-iot",    "tanprathan/MobileApp-Pentest-Cheatsheet"),
    ("mobile-api-cloud-iot",    "OWASP/www-project-api-security"),
    ("mobile-api-cloud-iot",    "OWASP/owasp-mastg"),
    ("mobile-api-cloud-iot",    "HackTricks-wiki/hacktricks-cloud"),
    ("ai-llm-security",         "dsopas/assessment-mindset"),
    ("ai-llm-security",         "corca-ai/awesome-llm-security"),
    ("ai-llm-security",         "OWASP/www-project-top-10-for-large-language-model-applications"),
    ("ai-llm-security",         "withsecurelabs/... placeholder"),
    ("ai-llm-security",         "mitre-atlas/atlas-data"),
    ("ai-llm-security",         "GossiTheDog/LLM-Security"),
    ("lab-setup-guides",        "jonathandion/awesome-home-lab"),
    ("lab-setup-guides",        "x1a0x/awesome-home-lab"),
    ("lab-setup-guides",        "Awesome-Windows/Awesome"),
    ("lab-setup-guides",        "shhossain/awesome-homelab"),
    ("labs-vulnerable-apps",    "OWASP/WebGoat"),
    ("labs-vulnerable-apps",    "juice-shop/juice-shop"),
    ("labs-vulnerable-apps",    "digininja/DVWA"),
    ("labs-vulnerable-apps",    "snoopysecurity/dvws-node"),
    ("labs-vulnerable-apps",    "payatu/diva-android"),
    ("books-courses",           "Hack-with-Github/Awesome-Hacking"),
    ("books-courses",           "YehudaMeir/awesome-security-books"),
    ("books-courses",           "calve/awesome-security-books"),
    ("books-courses",           "sbilly/awesome-security"),
    ("youtube-media",           "PaulSec/awesome-sec-talks"),
    ("youtube-media",           "troyhunt/... placeholder"),
    ("github-security-repos",   "enaqx/awesome-pentest"),
    ("github-security-repos",   "carpedm20/awesome-hacking"),
    ("github-security-repos",   "jivoi/awesome-osint"),
    ("github-security-repos",   "hslatman/awesome-threat-intelligence"),
    ("github-security-repos",   "paralax/awesome-honeypots"),
    ("github-security-repos",   "secfigo/Awesome-Fuzzing"),
    ("github-security-repos",   "cpuu/awesome-fuzzing"),
    ("platforms-bounty-programs","disclose/disclose.github.io"),
    ("platforms-bounty-programs","bugcrowd/VDP-Disclosure"),
]

records = []
def add(cat, url, title, source):
    records.append({"category": cat, "url": url.strip(), "title": title.strip(), "source": source})

def work(item):
    cat, repo = item
    if "placeholder" in repo: return repo, 0, None
    name, text = get_readme(repo)
    if not text: return repo, 0, None
    hits = extract_md(text)
    for u, t in hits: add(cat, u, t, f"{repo} ({name})")
    return repo, len(hits), name

print("=== Phase 1b: readme resolution ===")
with ThreadPoolExecutor(max_workers=10) as ex:
    for f in as_completed([ex.submit(work, i) for i in RETRY]):
        repo, n, name = f.result()
        flag = "OK " if n else "MISS"
        print(f"  {flag} {n:5d}  {repo}  [{name}]")

# append
with open(OUT, "a", encoding="utf-8") as f:
    for r in records: f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"\nappended {len(records)} records")
tot = sum(1 for _ in open(OUT))
print(f"harvest.jsonl now has {tot} raw records")
