#!/usr/bin/env python3
"""Phase 2: normalize, filter junk, dedupe, re-classify -> work/candidates.json"""
import json, os, re, urllib.parse
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.join(HERE, "harvest.jsonl")
OUT  = os.path.join(HERE, "candidates.json")

# --------------------------------------------------------------- blocklists
BAD_HOSTS = {
 "img.shields.io","shields.io","badge.fury.io","badges.gitter.im","d3sky.com",
 "travis-ci.org","travis-ci.com","app.travis-ci.com","codecov.io","coveralls.io",
 "pepy.tech","circleci.com","api.travis-ci.org","www.codacy.com","deepsource.io",
 "camo.githubusercontent.com","raw.githubusercontent.com","opencollective.com",
 "www.patreon.com","patreon.com","www.buymeacoffee.com","buymeacoffee.com",
 "ko-fi.com","liberapay.com","en.wikipedia.org","simple.wikipedia.org",
 "www.creativecommons.org","creativecommons.org","choosealicense.com",
 "hits.seeyoufarm.com","visitor-badge.glitch.me","visitor-badge.laobi.icu",
 "img.youtube.com","i.ytimg.com","i.imgur.com","imgur.com","pbs.twimg.com",
 "www.paypal.com","paypal.me","discord.com","discord.gg",  # invite links, low value
 "twitter.com","x.com","plus.google.com",
 "www.instagram.com","www.tiktok.com","www.pinterest.com","www.reddit.com",
 "open.vscode.dev","marketplace.visualstudio.com","chrome.google.com",
 "addons.mozilla.org","apps.apple.com","play.google.com",
 "www.gnu.org","opensource.org","spdx.org","unlicense.org","mit-license.org",
 "www.apache.org",  # license links
 "json.schemastore.org","nodei.co","npmjs.org","www.npmjs.com",
 "pypi.org","packagist.org","rubygems.org","crates.io","pkg.go.dev","godoc.org",
 "coveralls.io","sonarcloud.io","codeclimate.com","lgtm.com","snyk.io",
 "github-readme-stats.vercel.app","readme-typing-svg.herokuapp.com",
 "contrib.rocks","capsule-render.vercel.app","komarev.com","ghchart.rshah.org",
 "star-history.com","ossinsight.io","repo-stats.vercel.app",
}
BAD_PATH_RE = re.compile(
 r"(/stargazers|/network/members|/watchers|/graphs|/pulse|/actions|/workflows|"
 r"/commits?/|/commit/|/blame/|/issues$|/pulls$|/milestones|/projects\?|"
 r"/wiki/_history|/search\?|/releases/tag/v?0\.0\.0|/compare/|/blob/.*/\.github/|"
 r"/sponsor|/LICENSE|/license)", re.I)
BAD_EXT = (".png",".jpg",".jpeg",".gif",".svg",".ico",".webp",".bmp",".tiff",
           ".mp4",".webm",".mov",".avi",".mp3",".wav",".eot",".woff",".woff2",
           ".ttf",".otf",".css",".lock",".min.js",".icns")
BAD_QUERY = ("utm_","fbclid","gclid","mc_cid","mc_eid","ref=twsrc","source=share")
# keep only these TLD-ish/known-relevant hosts for the "generic" bucket drop rule
DROP_SCHEME = ("ftp://","mailto:","tel:","javascript:","data:","file://","chrome://","irc://")

SEC_HOST_HINTS = re.compile(
 r"(hack|secur|exploit|vuln|ctf|pentest|bug|cve|cyber|osint|forensic|malware|"
 r"payload|redteam|red-team|blue-?team|reverse|pwn|owasp|nuclei|burp|metasploit|"
 r"threat|intel|crypto|infosec|0x|shell|inject|fuzz|defen|attack|breach)", re.I)

# --------------------------------------------------------------- classifier
def classify(url, src_cat, title, source):
    h = urllib.parse.urlparse(url).netloc.lower()
    p = urllib.parse.urlparse(url).path.lower()
    t = (title or "") + " " + url
    tl = t.lower()

    # ---- media
    if h in ("www.youtube.com","youtube.com","youtu.be","vimeo.com","www.twitch.tv",
             "twitch.tv","open.spotify.com","podcasts.apple.com","soundcloud.com",
             "castbox.fm","www.buzzsprout.com","anchor.fm"):
        return "youtube-media"
    if h.endswith(".blogspot.com") or "/podcast" in p:
        return "youtube-media"

    # ---- communities
    if h in ("www.reddit.com","old.reddit.com","news.ycombinator.com",
             "security.stackexchange.com","reverseengineering.stackexchange.com",
             "stackoverflow.com","forum.hackthebox.com","forum.bugcrowd.com"):
        return "communities-forums"

    # ---- bug bounty platforms & program pages
    if h in ("hackerone.com","www.hackerone.com"):
        if re.search(r"^/(reports|hacktivity)", p): return "writeups-bug-bounty"
        return "platforms-bounty-programs"
    if h in ("bugcrowd.com","www.bugcrowd.com"):
        return "platforms-bounty-programs"
    if h in ("www.intigriti.com","intigriti.com","www.yeswehack.com","yeswehack.com",
             "www.synack.com","cobalt.io","zerocopter.com","hackenproof.com",
             "www.hackenproof.com","immunefi.com","firebounty.com","www.openbugbounty.org",
             "openbugbounty.org","disclose.io","www.disclose.io","www.bugbountyforum.com",
             "bountyfactory.io"):
        return "platforms-bounty-programs"

    # ---- CTF
    if h in ("ctftime.org","www.ctftime.org"):
        return "writeups-ctf" if "writeup" in p else "ctf-platforms-labs"
    if h in ("app.hackthebox.com","www.hackthebox.com","hackthebox.com",
             "tryhackme.com","www.tryhackme.com","www.root-me.org","root-me.org",
             "overthewire.org","www.overthewire.org","picoctf.org","play.picoctf.org",
             "ctflearn.com","www.ctflearn.com","cryptohack.org","pwnable.kr","pwnable.tw",
             "ropemporium.com","ringzer0ctf.com","io.netgarage.org","pwn.college",
             "dojo.pwn.college","exploit.education","www.exploit.education",
             "defendtheweb.net","www.defendtheweb.net","cmdchallenge.com",
             "underthewire.tech","holidayhackchallenge.com","cyberdefenders.org",
             "blueteamlabs.online","letsdefend.io","capturetheflag.withgoogle.com",
             "pentesterlab.com","www.pentesterlab.com","www.vulnhub.com","vulnhub.com"):
        return "ctf-platforms-labs"
    if "ctf" in tl and (h.startswith("github.com") or h == "book.hacktricks.wiki"):
        return "writeups-ctf"

    # ---- vulnerable apps / labs
    if h in ("mas.owasp.org","owasp-juice.shop","pwning.owasp-juice.shop","vulhub.org"):
        return "labs-vulnerable-apps"
    if re.search(r"(vulnerable|vuln-|dvwa|dvna|dvja|dvws|dvfa|diva|webgoat|juice-?shop|"
                 r"metasploitable|bwapp|igoat|andr?ogoat|insecureshop|cloudgoat|kubernetes-goat|"
                 r"terragoat|iam-vulnerable|sadcloud|crapi|vampi|wrongsecrets|security-shepherd|"
                 r"node\.?js-?goat|railsgoat|pygoat|dvsna|damnvulnerable)", tl, re.I):
        return "labs-vulnerable-apps"

    # ---- standards / vuln databases
    if h in ("nvd.nist.gov","cve.mitre.org","www.cve.org","cwe.mitre.org","www.first.org",
             "www.cisa.gov","attack.mitre.org","capec.mitre.org","d3fend.mitre.org",
             "atlas.mitre.org","www.exploit-db.com","exploit-db.com","packetstormsecurity.com",
             "www.zerodayinitiative.com","zerodayinitiative.com","osv.dev","vulners.com",
             "www.rapid7.com","attackerkb.com","security.snyk.io","www.mend.io","vuldb.com",
             "cxsecurity.com","www.cvedetails.com","cvedetails.com","bugs.chromium.org",
             "haveibeenpwned.com","dehashed.com","www.shodan.io","shodan.io",
             "search.censys.io","censys.io","www.zoomeye.org","fofa.info","hunter.how",
             "app.netlas.io","urlscan.io","www.virustotal.com","publicwww.com",
             "crt.sh","www.certificate-transparency.org","otx.alienvault.com",
             "pulsedive.com","www.abuseipdb.com","commoncrawl.org","web.archive.org",
             "viz.greynoise.io","www.binaryedge.io","talosintelligence.com"):
        return "standards-databases"
    if h in ("msrc.microsoft.com","msrc.blog","googleprojectzero.blogspot.com",
             "chromereleases.googleblog.com","securelist.com","threatpost.com",
             "thehackernews.com","www.bleepingcomputer.com","krebsonsecurity.com"):
        return "standards-databases"

    # ---- OWASP standards
    if h == "owasp.org" or h == "www.owasp.org" or h == "genai.owasp.org":
        return "methodology-cheatsheets"
    if h == "cheatsheetseries.owasp.org":
        return "methodology-cheatsheets"

    # ---- reference / methodology
    if h in ("portswigger.net","www.portswigger.net","book.hacktricks.wiki",
             "cloud.hacktricks.wiki","swisskyrepo.github.io","gtfobins.github.io",
             "lolbas-project.github.io","www.hacksplaining.com","hacksplanning.com",
             "html5sec.org","payloads.wiki","ctf-wiki.org","docs.projectdiscovery.io",
             "www.assetnote.io","labs.detectify.com","detectify.com","bughunter.guide",
             "bugbountyguide.com","six2dez.gitbooks.io","guyinatuxedos.github.io",
             "mas.owasp.org","www.zaproxy.org","zaproxy.org","docs.zaproxy.org",
             "saif.google.com","learn.microsoft.com","docs.github.com","docs.aws.amazon.com",
             "cloud.google.com","frida.re","docs.pwntools.com","mobsf.github.io",
             "codeql.github.com","ghidra-sre.org","threatmodelingbook.com","www.seedsecuritylabs.org",
             "seedsecuritylabs.org","cs253.stanford.edu","www.offensiveosint.io",
             "osintframework.com","www.osinttechniques.com","inteltechniques.com",
             "www.bellingcat.com","www.redteam-pentesting.de","www.corelan.be",
             "help.shodan.io","cli.shodan.io","nmap.org","www.nmap.org","llvm.org",
             "docs.metasploit.com","www.metasploit.com","www.offsec.com","offsec.com"):
        return "vuln-classes-reference" if h not in (
            "frida.re","docs.pwntools.com","mobsf.github.io","codeql.github.com",
            "ghidra-sre.org","nmap.org","www.nmap.org","llvm.org","cli.shodan.io",
            "help.shodan.io","docs.metasploit.com","www.metasploit.com",
            "www.offsec.com","offsec.com") else "tools-exploitation"

    # ---- books / courses / certs
    if h in ("nostarch.com","www.wiley.com","wiley.com","www.packtpub.com","packtpub.com",
             "link.springer.com","www.manning.com","manning.com","www.oreilly.com",
             "oreilly.com","www.mheducation.com","mhprofessional.com","www.amazon.com",
             "amazon.com","leanpub.com","www.goodreads.com","goodreads.com",
             "www.sans.org","sans.org","www.comptia.org","comptia.org","www.eccouncil.org",
             "eccouncil.org","www.alteredsecurity.com","certifications.tcm-sec.com",
             "academy.tcm-sec.com","www.cybrary.it","cybrary.it","my.ine.com","www.ine.com",
             "www.pentesteracademy.com","www.stationx.net","www.rangeforce.com",
             "immersivelabs.com","www.hacker101.com","ctf.hacker101.com",
             "www.thehackerplaybook.com","www.hackingexposed.com",
             "www.apress.com","www.informit.com","www.safaribooksonline.com"):
        return "books-courses"
    if re.search(r"(book|ebook|pdf|cheat-?sheet-guide|course|training|certif|tutorial)", tl, re.I) \
       and h in ("github.com","www.gitbook.com","leanpub.com"):
        return "books-courses"

    # ---- conferences
    if h in ("defcon.org","www.defcon.org","media.defcon.org","www.blackhat.com","blackhat.com",
             "owasp.org","bsides.org","www.bsides.org","www.rsaconference.com","cansecwest.com",
             "www.offensivecon.org","powerofcommunity.net","conference.hitb.org",
             "www.troopers.de","44con.com","nullcon.net","recon.cx","www.ekoparty.org",
             "www.first.org","secapparmor.org","www.hack.lu","hack.lu","www.grcon.org",
             "www.deepsec.net","www.botconf.eu","www.sstic.org"):
        return "youtube-media"

    # ---- AI / LLM
    if re.search(r"(llm|gpt|ai-|artificial|prompt-?injection|jailbreak|langchain|"
                 r"agent(ic)?|machine-?learning|ml-?sec|risk|garak|neural|transformer)", tl, re.I):
        return "ai-llm-security"

    # ---- github: tools vs repos vs writeups
    if h == "github.com" or h == "www.github.com":
        owner_repo = "/".join(p.strip("/").split("/")[:2])
        if "nuclei-templates" in owner_repo:
            return "tools-exploitation"
        if re.search(r"(tool|scanner|fuzzer|payload|wordlist|brute|crawl|recon|"
                     r"exploit|proxy|inject|enum|scan|attack|redteam)", owner_repo, re.I):
            return "tools-exploitation"
        if re.search(r"(writeup|write-up|report|hacktivity|disclos)", owner_repo, re.I):
            return "writeups-bug-bounty"
        if re.search(r"(awesome|list|resource|cheat)", owner_repo, re.I):
            return "github-security-repos"
        return "github-security-repos"

    # ---- enterprise vendor security pages
    if re.search(r"(security|vulnerability|bug-bounty|bugbounty|msrc|psirt|cert|trust|"
                 r"responsible-disclosure|whitehat)", tl, re.I):
        return "enterprise-programs-top500"

    if src_cat:
        return src_cat
    return "other"

# --------------------------------------------------------------- normalize
def norm(url):
    url = url.strip().strip("<>").strip()
    if any(c in url for c in "[]{}<>|`^\\ \"'"):
        return None
    url = re.sub(r"[\)\]\}>,;\"'\s]+$", "", url)
    url = url.replace("\\_", "_").replace("\\(", "(").replace("\\)", ")")
    if url.lower().startswith(DROP_SCHEME):
        return None
    m = re.match(r"^(https?)://([^/?#]+)(.*)$", url, re.I)
    if not m:
        return None
    scheme, host, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
    host = re.sub(r"^www\.", "", host) if host.count(".") > 1 else host
    rest = re.sub(r"#.*$", "", rest)                      # drop fragment
    rest = re.sub(r"/+$", "", rest)                        # drop trailing slash
    if "?" in rest:
        base, q = rest.split("?", 1)
        parts = [kv for kv in q.split("&")
                 if kv and not any(b in kv.lower() for b in BAD_QUERY)]
        rest = base + ("?" + "&".join(parts) if parts else "")
    return f"{scheme}://{host}{rest}"

def is_junk(url):
    if any(c in url for c in "[]{}<> \\`|^"):
        return True
    try:
        pr = urllib.parse.urlparse(url)
    except Exception:
        return True
    h = pr.netloc.lower()
    p = pr.path
    if not h or "." not in h: return True
    if any(h == b or h.endswith("." + b) for b in BAD_HOSTS): return True
    if BAD_PATH_RE.search(url): return True
    pl = p.lower()
    if pl.endswith(BAD_EXT): return True
    if h in ("medium.com",): return True          # paywalled duplicates, keep infosecwriteups only
    if "github.com" in h and re.search(r"/(stargazers|network|watchers|pulse)", pl): return True
    return False

# --------------------------------------------------------------- run
seen = {}
cats = Counter()
srcs = Counter()
bounty = {}
n_raw = n_bad = n_dupe = 0

with open(SRC, encoding="utf-8") as f:
    for line in f:
        try: r = json.loads(line)
        except Exception: continue
        n_raw += 1
        raw = r.get("url","")
        u = norm(raw)
        if not u or is_junk(u):
            n_bad += 1
            continue
        cat = classify(u, r.get("category"), r.get("title",""), r.get("source",""))
        key = u.lower()
        if key in seen:
            n_dupe += 1
            # promote: curated beats harvested; richer title wins
            ex = seen[key]
            if r.get("source") == "CURATED" and ex["source"] != "CURATED":
                ex["source"] = "CURATED"; ex["category"] = cat
            if len(r.get("title","")) > len(ex.get("title","")):
                ex["title"] = r["title"]
            ex["categories"] = sorted(set(ex.get("categories", [ex["category"]]) + [cat]))
            continue
        rec = {"url": u, "title": (r.get("title") or "").strip(),
               "category": cat, "source": r.get("source",""),
               "categories": [cat]}
        seen[key] = rec
        if r.get("program"):
            bounty[u] = {"program": r["program"], "handle": r.get("handle"),
                         "bounty": r.get("bounty"), "raw": r.get("raw") or {}}
        cats[cat] += 1
        srcs[r.get("source","?")] += 1

cands = list(seen.values())
json.dump({"candidates": cands, "bounty": bounty}, open(OUT, "w", encoding="utf-8"),
          ensure_ascii=False, indent=0)

print(f"raw={n_raw}  junk_dropped={n_bad}  dupes={n_dupe}  unique={len(cands)}")
print("\n-- by category --")
for c, n in cats.most_common(): print(f"  {n:6d}  {c}")
print("\n-- top sources --")
for s, n in srcs.most_common(25): print(f"  {n:6d}  {s}")
print(f"\nbounty program metadata kept: {len(bounty)}")
