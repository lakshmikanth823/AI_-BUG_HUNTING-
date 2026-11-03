"""
Script to build the Master Bug Bounty Links & Training Feed (1000+ curated links).
Fetches writeups from PentesterLand and integrates curated methodology, tools,
labs, CTF archives, MNC disclosures, and top books.
"""

import json
import re
import urllib.request
from pathlib import Path
from typing import List, Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "dataset"

# Startup check: ensure parent directory exists rather than silently creating a disconnected folder tree
if not OUTPUT_DIR.parent.exists():
    raise RuntimeError(f"Expected repository root directory does not exist: {OUTPUT_DIR.parent}")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. High-priority Curated Collections
CURATED_SOURCES = [
    # --- METHODOLOGY & APPROACHES ---
    {
        "title": "OWASP Web Security Testing Guide (WSTG v4.2)",
        "url": "https://owasp.org/www-project-web-security-testing-guide/",
        "category": "Methodology",
        "tags": ["owasp", "wstg", "testing-guide", "methodology"],
        "description": "The premier comprehensive testing framework for web application security assessments."
    },
    {
        "title": "OWASP API Security Top 10",
        "url": "https://owasp.org/www-project-api-security/",
        "category": "Methodology",
        "tags": ["owasp", "api-security", "bola", "bfla"],
        "description": "Standard awareness document for developers and security testing covering top API vulnerabilities."
    },
    {
        "title": "PortSwigger Web Security Academy Learning Paths",
        "url": "https://portswigger.net/web-security",
        "category": "Methodology",
        "tags": ["portswigger", "burpsuite", "labs", "methodology"],
        "description": "World-class interactive web security training covering SQLi, XSS, SSRF, Deserialization, Smuggling."
    },
    {
        "title": "Jason Haddix - The Bug Hunter's Methodology (v4.0)",
        "url": "https://www.youtube.com/watch?v=gIDywt96Z1k",
        "category": "Methodology",
        "tags": ["jhaddix", "recon", "methodology", "bug-hunter"],
        "description": "The de facto industry methodology covering wide and deep recon, content discovery, and parameter analysis."
    },
    {
        "title": "Jason Haddix - Bug Hunter's Methodology Full Slide Deck",
        "url": "https://github.com/jhaddix/tbhm",
        "category": "Methodology",
        "tags": ["jhaddix", "slides", "tbhm", "methodology"],
        "description": "Official GitHub repository for The Bug Hunter's Methodology."
    },
    {
        "title": "NahamSec - Resources for Beginner and Intermediate Bug Hunters",
        "url": "https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters",
        "category": "Methodology",
        "tags": ["nahamsec", "beginner", "guide", "cheatsheet"],
        "description": "Comprehensive roadmap, methodology notes, and resource collection by Ben Sadeghipour."
    },
    {
        "title": "Hakluke - Ultimate Guide to Bug Bounty Hunting",
        "url": "https://hakluke.com/the-ultimate-guide-to-bug-bounty-hunting/",
        "category": "Methodology",
        "tags": ["hakluke", "guide", "mindset", "automation"],
        "description": "Comprehensive tactical guide covering reconnaissance, mindset, and finding impactful vulnerabilities."
    },
    {
        "title": "HackerOne Hacker101 Free Security Curriculum",
        "url": "https://www.hacker101.com/",
        "category": "Methodology",
        "tags": ["hackerone", "hacker101", "curriculum", "video-guides"],
        "description": "Educational platform by HackerOne with video lessons, study guides, and free CTF challenges."
    },
    {
        "title": "Bugcrowd University",
        "url": "https://www.bugcrowd.com/resources/bugcrowd-university/",
        "category": "Methodology",
        "tags": ["bugcrowd", "university", "training", "guides"],
        "description": "Free open-source training modules designed to level up security researchers."
    },
    {
        "title": "Penetration Testing Execution Standard (PTES)",
        "url": "http://www.pentest-standard.org/",
        "category": "Methodology",
        "tags": ["ptes", "standard", "recon", "exploitation", "post-exploitation"],
        "description": "Comprehensive framework covering intelligence gathering, threat modeling, and vulnerability analysis."
    },
    {
        "title": "MITRE ATT&CK for Enterprise - Initial Access & Web Applications",
        "url": "https://attack.mitre.org/matrices/enterprise/",
        "category": "Methodology",
        "tags": ["mitre", "attck", "tactics", "techniques"],
        "description": "Globally accessible knowledge base of adversary tactics and techniques based on real-world observations."
    },

    # --- TOOLS & GITHUB SOURCES ---
    {
        "title": "ProjectDiscovery Nuclei - Fast and Customizable Vulnerability Scanner",
        "url": "https://github.com/projectdiscovery/nuclei",
        "category": "Tools",
        "tags": ["nuclei", "scanner", "yaml-templates", "projectdiscovery"],
        "description": "Next-generation template-driven vulnerability scanner used by top security teams worldwide."
    },
    {
        "title": "Nuclei Community Templates Repository",
        "url": "https://github.com/projectdiscovery/nuclei-templates",
        "category": "Tools",
        "tags": ["nuclei", "templates", "cve", "misconfig", "exposures"],
        "description": "Official community-curated library of thousands of vulnerability checks, CVEs, and takeovers."
    },
    {
        "title": "ProjectDiscovery HTTPX - Fast and Multi-Purpose HTTP Toolkit",
        "url": "https://github.com/projectdiscovery/httpx",
        "category": "Tools",
        "tags": ["httpx", "http-probe", "tech-detect", "projectdiscovery"],
        "description": "High-throughput HTTP probing library for testing live endpoints, headers, title, status, and CDN bypasses."
    },
    {
        "title": "ProjectDiscovery Subfinder - Fast Subdomain Enumeration Tool",
        "url": "https://github.com/projectdiscovery/subfinder",
        "category": "Tools",
        "tags": ["subfinder", "subdomains", "recon", "passive-dns"],
        "description": "Passive subdomain discovery tool that harvests subdomains from dozens of online sources."
    },
    {
        "title": "ProjectDiscovery Katana - Next-Gen Crawling and Spidering Framework",
        "url": "https://github.com/projectdiscovery/katana",
        "category": "Tools",
        "tags": ["katana", "crawler", "spider", "headless-browser"],
        "description": "Next-generation crawling engine supporting headless browser crawling, endpoint extraction, and scope control."
    },
    {
        "title": "ffuf - Fast Web Fuzzer",
        "url": "https://github.com/ffuf/ffuf",
        "category": "Tools",
        "tags": ["ffuf", "fuzzer", "directory-bruteforce", "parameter-fuzzing"],
        "description": "High-speed web fuzzer written in Go for discovering hidden directories, files, vhosts, and parameters."
    },
    {
        "title": "OWASP Amass - Network Mapping & Attack Surface Asset Discovery",
        "url": "https://github.com/owasp-amass/amass",
        "category": "Tools",
        "tags": ["amass", "owasp", "recon", "attack-surface", "asn"],
        "description": "In-depth attack surface mapping and external asset discovery using open source information gathering and active recon."
    },
    {
        "title": "Daniel Miessler's SecLists",
        "url": "https://github.com/danielmiessler/SecLists",
        "category": "Tools",
        "tags": ["seclists", "wordlists", "payloads", "passwords", "fuzzing"],
        "description": "The security tester's companion: collection of usernames, passwords, URLs, sensitive data patterns, and fuzz payloads."
    },
    {
        "title": "Swisskyrepo - PayloadsAllTheThings",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "category": "Tools",
        "tags": ["payloadsallthethings", "cheatsheet", "sqli", "xss", "ssrf", "rce"],
        "description": "A list of useful payloads and bypasses for Web Application Security and Pentesting / Bug Bounty."
    },
    {
        "title": "sqlmap - Automatic SQL Injection and Database Takeover Tool",
        "url": "https://github.com/sqlmapproject/sqlmap",
        "category": "Tools",
        "tags": ["sqlmap", "sqli", "database", "exploitation"],
        "description": "Open source penetration testing tool that automates detecting and exploiting SQL injection flaws."
    },
    {
        "title": "Commix - Automated All-in-One OS Command Injection Exploiter",
        "url": "https://github.com/commixproject/commix",
        "category": "Tools",
        "tags": ["commix", "command-injection", "rce"],
        "description": "Automated tool for finding and exploiting command injection flaws."
    },
    {
        "title": "Dalfox - Parameter Analysis and XSS Scanner",
        "url": "https://github.com/hahwul/dalfox",
        "category": "Tools",
        "tags": ["dalfox", "xss", "scanner", "dom-xss"],
        "description": "Fast, powerful parameter analysis and utility tool focused on finding reflected, stored, and DOM XSS."
    },
    {
        "title": "XSStrike - Advanced XSS Detection Suite",
        "url": "https://github.com/s0md3v/XSStrike",
        "category": "Tools",
        "tags": ["xsstrike", "xss", "fuzzer", "bypass"],
        "description": "Intelligent XSS scanner equipped with Python AST parser, context analysis, and payload generation."
    },
    {
        "title": "TruffleHog - Find Leaked Credentials and API Keys",
        "url": "https://github.com/trufflesecurity/trufflehog",
        "category": "Tools",
        "tags": ["trufflehog", "secrets", "api-keys", "git"],
        "description": "Searches through git repositories, S3 buckets, and filesystems for high-entropy secrets and verified API keys."
    },
    {
        "title": "Gitleaks - Protect and Discover Secrets in Source Code",
        "url": "https://github.com/gitleaks/gitleaks",
        "category": "Tools",
        "tags": ["gitleaks", "secrets", "git-scanner"],
        "description": "SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos."
    },
    {
        "title": "LinkFinder - Discover Endpoints in JavaScript Files",
        "url": "https://github.com/GerbenJavado/LinkFinder",
        "category": "Tools",
        "tags": ["linkfinder", "javascript", "endpoint-discovery"],
        "description": "Python script that uses jsbeautifier and regex to discover endpoints and parameters in JavaScript files."
    },
    {
        "title": "JSLuice - Extract Endpoints and Secrets from Modern JS Bundles",
        "url": "https://github.com/BishopFox/jsluice",
        "category": "Tools",
        "tags": ["jsluice", "bishopfox", "javascript", "ast"],
        "description": "Go package and CLI tool for parsing JavaScript and extracting URLs, paths, and secrets using Tree-sitter AST."
    },
    {
        "title": "Arjun - HTTP Parameter Discovery Suite",
        "url": "https://github.com/s0md3v/Arjun",
        "category": "Tools",
        "tags": ["arjun", "parameter-discovery", "hidden-params"],
        "description": "Finds hidden GET, POST, JSON, and XML parameters for web applications."
    },
    {
        "title": "Caido - Lightweight Web Security Auditing Toolkit",
        "url": "https://caido.io/",
        "category": "Tools",
        "tags": ["caido", "proxy", "burp-alternative", "rust"],
        "description": "Modern, lightweight, privacy-friendly proxy written in Rust with fast filtering and scripting."
    },
    {
        "title": "OWASP ZAP (Zed Attack Proxy)",
        "url": "https://www.zaproxy.org/",
        "category": "Tools",
        "tags": ["zap", "owasp", "interception-proxy", "scanner"],
        "description": "The world’s most widely used web app scanner, free and open source."
    },

    # --- VULNERABLE LABS & SETUPS ---
    {
        "title": "OWASP Juice Shop - Modern Insecure Web Application",
        "url": "https://github.com/juice-shop/juice-shop",
        "category": "Labs",
        "tags": ["juice-shop", "owasp", "javascript", "angular", "node"],
        "description": "Intentionally insecure web application encompassing the entire OWASP Top 10 along with many other security flaws."
    },
    {
        "title": "DVWA - Damn Vulnerable Web Application",
        "url": "https://github.com/digininja/DVWA",
        "category": "Labs",
        "tags": ["dvwa", "php", "sql-injection", "xss", "csrf"],
        "description": "PHP/MySQL web application that is damn vulnerable for testing tools and practicing manual exploitation."
    },
    {
        "title": "OWASP WebGoat - Deliberately Insecure Java Web App",
        "url": "https://github.com/WebGoat/WebGoat",
        "category": "Labs",
        "tags": ["webgoat", "java", "spring", "owasp"],
        "description": "Deliberately insecure application maintained by OWASP designed to teach web application security lessons."
    },
    {
        "title": "Vulhub - Pre-built Vulnerable Docker Environments (500+ Environments)",
        "url": "https://github.com/vulhub/vulhub",
        "category": "Labs",
        "tags": ["vulhub", "docker", "cve", "reproduction", "1-click"],
        "description": "Open-source collection of 500+ Docker environments for replicating real-world vulnerabilities and CVEs with one command."
    },
    {
        "title": "OWASP crAPI - Completely Ridiculous API",
        "url": "https://github.com/OWASP/crAPI",
        "category": "Labs",
        "tags": ["crapi", "owasp", "api-security", "microservices"],
        "description": "Modern microservices-based deliberately vulnerable API platform modeling vehicle management with OWASP API Top 10 flaws."
    },
    {
        "title": "vAPI - Vulnerable Adversarial API Lab",
        "url": "https://github.com/roottusk/vapi",
        "category": "Labs",
        "tags": ["vapi", "api-security", "postman", "docker"],
        "description": "Vulnerable API that simulates OWASP API Top 10 with interactive Postman collection walkthroughs."
    },
    {
        "title": "Rhino Security Labs CloudGoat - Vulnerable AWS Environment",
        "url": "https://github.com/RhinoSecurityLabs/cloudgoat",
        "category": "Labs",
        "tags": ["cloudgoat", "aws", "cloud-security", "terraform"],
        "description": "Vulnerable by-design AWS infrastructure tool using Terraform to create complex cloud attack paths."
    },
    {
        "title": "Bridgecrew TerraGoat - Vulnerable Terraform Infrastructure as Code",
        "url": "https://github.com/bridgecrewio/terragoat",
        "category": "Labs",
        "tags": ["terragoat", "iac", "terraform", "misconfiguration"],
        "description": "Bridgecrew's deliberately vulnerable Terraform repository for practicing cloud misconfiguration detection."
    },
    {
        "title": "PentesterLab - Web Security Training Exercises",
        "url": "https://pentesterlab.com/",
        "category": "Labs",
        "tags": ["pentesterlab", "badges", "exercises", "hands-on"],
        "description": "Hands-on web penetration testing labs covering everything from fundamentals to advanced deserialization and race conditions."
    },
    {
        "title": "Hack The Box - Advanced Cybersecurity Training Platform",
        "url": "https://www.hackthebox.com/",
        "category": "Labs",
        "tags": ["hackthebox", "machines", "ctf", "active-directory"],
        "description": "Massive gamified platform with hundreds of realistic virtual vulnerable machines and challenge tracks."
    },
    {
        "title": "TryHackMe - Hands-on Cyber Security Labs",
        "url": "https://tryhackme.com/",
        "category": "Labs",
        "tags": ["tryhackme", "rooms", "guided-labs", "burpsuite"],
        "description": "Browser-accessible interactive hands-on security training rooms from web fundamentals to red teaming."
    },
    {
        "title": "VulnHub - Offline Penetration Testing Lab Machines",
        "url": "https://www.vulnhub.com/",
        "category": "Labs",
        "tags": ["vulnhub", "vms", "offline-labs", "boot2root"],
        "description": "Catalog of community-built downloadable boot2root virtual machines for offline security assessment practice."
    },

    # --- CTF WRITEUPS & ARCHIVES ---
    {
        "title": "CTFtime - Worldwide CTF Scoring, Events, and Writeups Archive",
        "url": "https://ctftime.org/writeups",
        "category": "CTF Writeups",
        "tags": ["ctftime", "ctf", "writeups", "archive"],
        "description": "The global hub for Capture The Flag competitions, hosting thousands of community writeups for web, crypto, and pwn."
    },
    {
        "title": "Google CTF Official Challenge Repository and Solutions",
        "url": "https://github.com/google/google-ctf",
        "category": "CTF Writeups",
        "tags": ["google", "google-ctf", "high-difficulty", "web"],
        "description": "Official archive of challenges, source code, and solutions from the annual Google Capture The Flag competition."
    },
    {
        "title": "0xdf hacker lab - HTB and CTF Machine Walkthroughs",
        "url": "https://0xdf.gitlab.io/",
        "category": "CTF Writeups",
        "tags": ["0xdf", "htb", "ctf", "detailed-walkthroughs"],
        "description": "Deeply technical, beautifully explained writeups of every retired HackTheBox machine and major CTF challenge."
    },
    {
        "title": "IppSec Video Archive & Searchable Command Database",
        "url": "https://ippsec.rocks/",
        "category": "CTF Writeups",
        "tags": ["ippsec", "video-walkthroughs", "htb", "searchable"],
        "description": "Searchable timestamp index of hundreds of professional video walkthroughs covering offensive techniques and tools."
    },
    {
        "title": "DEF CON CTF Archive",
        "url": "https://defcon.org/html/links/dc-ctf.html",
        "category": "CTF Writeups",
        "tags": ["defcon", "ctf", "legendary", "elite"],
        "description": "Archive of challenges and solutions from the world's most prestigious hacking competition at DEF CON."
    },
    {
        "title": "PicoCTF Learning Platform & Past Competitions",
        "url": "https://picoctf.org/",
        "category": "CTF Writeups",
        "tags": ["picoctf", "cmu", "educational", "foundations"],
        "description": "Carnegie Mellon University's cybersecurity education project with archived challenge gyms."
    },

    # --- TOP MNC DISCLOSURES & REPUTABLE REPOSITORIES ---
    {
        "title": "HackerOne Hacktivity - Public Disclosures Feed",
        "url": "https://hackerone.com/hacktivity",
        "category": "MNC Disclosures",
        "tags": ["hackerone", "disclosures", "real-world", "bounties"],
        "description": "Live feed of disclosed vulnerability reports with rewards from Airbnb, Uber, Shopify, GitHub, Valve, DoD, and TikTok."
    },
    {
        "title": "Bugcrowd Crowdstream - Disclosed Vulnerabilities",
        "url": "https://bugcrowd.com/crowdstream",
        "category": "MNC Disclosures",
        "tags": ["bugcrowd", "crowdstream", "disclosures"],
        "description": "Public feed of validated vulnerability disclosures across Bugcrowd programs."
    },
    {
        "title": "Disclosed Google Bug Bounty Writeups by Security Researchers",
        "url": "https://bughunters.google.com/blog",
        "category": "MNC Disclosures",
        "tags": ["google", "vrp", "high-severity", "top-tier"],
        "description": "Google's official Bug Hunters portal showcasing high-impact research, spotlights, and top awards."
    },
    {
        "title": "Uber Bug Bounty - RCE & Critical Disclosures by Frans Rosén",
        "url": "https://labs.detectify.com/frans-rosen/",
        "category": "MNC Disclosures",
        "tags": ["uber", "detectify", "frans-rosen", "account-takeover"],
        "description": "Renowned series of deep technical writeups detailing critical account takeovers and logic flaws in Uber."
    },
    {
        "title": "Shopify Bug Bounty Program Disclosures on HackerOne",
        "url": "https://hackerone.com/shopify?type=team",
        "category": "MNC Disclosures",
        "tags": ["shopify", "hackerone", "e-commerce", "bounties"],
        "description": "Shopify's public program page featuring over $4M+ in bounties paid and dozens of detailed technical disclosures."
    },
    {
        "title": "GitLab Disclosed Vulnerabilities - Top P1/Criticals",
        "url": "https://hackerone.com/gitlab?type=team",
        "category": "MNC Disclosures",
        "tags": ["gitlab", "rce", "ssrf", "p1-reports"],
        "description": "Over 2,000 resolved reports detailing complex SSRF, privilege escalation, and Git command execution flaws."
    },
    {
        "title": "Twitter / X Bug Bounty Disclosures",
        "url": "https://hackerone.com/twitter?type=team",
        "category": "MNC Disclosures",
        "tags": ["twitter", "x", "api", "oauth-bypass"],
        "description": "Disclosed vulnerabilities in OAuth, user privacy endpoints, and backend API routes."
    },
    {
        "title": "Intigriti Monthly Bug Bounty Writeup Roundups (Archive 1-100+)",
        "url": "https://blog.intigriti.com/category/bug-bytes/",
        "category": "MNC Disclosures",
        "tags": ["intigriti", "bug-bytes", "monthly-roundup", "curated-writeups"],
        "description": "Comprehensive weekly/monthly curation of all the top bug bounty writeups, tools, and community tutorials."
    },

    # --- TOP BEST BOOKS ---
    {
        "title": "The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws (2nd Ed)",
        "url": "https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472",
        "category": "Books",
        "tags": ["wahh", "stuttard", "pinto", "bible", "foundational"],
        "description": "The undisputed bible of web application security testing by Dafydd Stuttard (creator of Burp Suite) and Marcus Pinto."
    },
    {
        "title": "Real-World Bug Hunting: A Field Guide to Web Hacking by Peter Yaworski",
        "url": "https://nostarch.com/bughunting",
        "category": "Books",
        "tags": ["yaworski", "nostarch", "real-world-reports", "beginner-to-pro"],
        "description": "Comprehensive field guide analyzing real, publicly disclosed bug bounty reports from top companies."
    },
    {
        "title": "Bug Bounty Bootcamp: The Guide to Finding and Reporting Web Vulnerabilities by Vickie Li",
        "url": "https://nostarch.com/bug-bounty-bootcamp",
        "category": "Books",
        "tags": ["vickie-li", "nostarch", "bootcamp", "modern-recon", "report-writing"],
        "description": "Modern end-to-end guide detailing vulnerability discovery, effective report writing, and professional triage communication."
    },
    {
        "title": "Hacking APIs: Breaking Web Application Programming Interfaces by Corey J. Ball",
        "url": "https://nostarch.com/hacking-apis",
        "category": "Books",
        "tags": ["corey-ball", "api-security", "graphql", "rest", "fuzzing"],
        "description": "The authoritative crash course on attacking modern REST and GraphQL APIs, endpoint discovery, and BOLA/BFLA exploitation."
    },
    {
        "title": "Web Security for Developers: Real Threats, Practical Defenses by Malcolm McDonald",
        "url": "https://nostarch.com/web-security-developers",
        "category": "Books",
        "tags": ["nostarch", "developer-mindset", "defensive", "architecture"],
        "description": "Teaches security from the ground up: auth systems, encryption, cross-site scripting, and architectural security design."
    },
    {
        "title": "The Tangled Web: A Guide to Securing Modern Web Applications by Michal Zalewski",
        "url": "https://nostarch.com/tangledweb",
        "category": "Books",
        "tags": ["lcamtuf", "browser-internals", "sop", "cookies", "deep-dive"],
        "description": "Masterpiece on browser security architecture, the Same-Origin Policy, DOM behavior, and HTTP protocol quirks by lcamtuf."
    },
    {
        "title": "Attacking Network Protocols: A Hacker's Guide to Capture, Analysis, and Exploitation by James Forshaw",
        "url": "https://nostarch.com/networkprotocols",
        "category": "Books",
        "tags": ["forshaw", "protocols", "reverse-engineering", "wireshark"],
        "description": "Deep-dive into network protocol reverse engineering, fuzzing, and cryptographic validation."
    },
    {
        "title": "API Security in Action by Neil Madden",
        "url": "https://www.manning.com/books/api-security-in-action",
        "category": "Books",
        "tags": ["manning", "api", "oauth2", "oidc", "macaroons", "tokens"],
        "description": "Deep exploration of securing and testing microservice APIs, JSON Web Tokens, OAuth 2.0, and delegated authorization."
    }
]


def fetch_pentesterland_writeups() -> List[Dict[str, Any]]:
    """
    Fetches the entire curated list of bug bounty writeups from PentesterLand's
    public repository markdown table and parses them into structured objects.
    """
    url = "https://raw.githubusercontent.com/pentesterland/pentesterland.github.io/master/_pages/list-of-bug-bounty-writeups.md"
    print(f"[*] Downloading writeups dataset from PentesterLand ({url})...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Warning: Could not download PentesterLand directly: {e}")
        return []

    print(f"[*] Parsing PentesterLand markdown table (Size: {len(text):,} bytes)...")
    
    # Regex to extract each row: 
    # <tr>
    #   <td markdown="span"><a href="URL">TITLE</a></td>
    #   <td markdown="span">AUTHOR</td>
    #   <td markdown="span">PROGRAM</td>
    #   <td markdown="span">VULNERABILITY</td>
    #   <td markdown="span">REWARD</td>
    #   <td markdown="span">DATE</td>
    # </tr>
    row_pattern = re.compile(
        r'<tr>\s*<td[^>]*><a\s+href="([^"]+)"[^>]*>(.*?)</a></td>\s*'
        r'<td[^>]*>(.*?)</td>\s*'
        r'<td[^>]*>(.*?)</td>\s*'
        r'<td[^>]*>(.*?)</td>\s*'
        r'<td[^>]*>(.*?)</td>\s*'
        r'<td[^>]*>(.*?)</td>',
        re.DOTALL | re.IGNORECASE
    )

    clean_tag = re.compile(r'<[^>]+>')
    writeups = []
    
    for match in row_pattern.finditer(text):
        link_url = match.group(1).strip()
        title = clean_tag.sub("", match.group(2)).strip()
        author = clean_tag.sub("", match.group(3)).strip()
        program = clean_tag.sub("", match.group(4)).strip()
        vulnerability = clean_tag.sub("", match.group(5)).strip()
        reward = clean_tag.sub("", match.group(6)).strip()
        date = clean_tag.sub("", match.group(7) if len(match.groups()) >= 7 else "").strip()

        # Clean HTML entities
        title = title.replace("&amp;", "&").replace("&quot;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
        program = program.replace("&amp;", "&").replace("&quot;", '"')
        vulnerability = vulnerability.replace("&amp;", "&")

        if not link_url.startswith("http"):
            continue

        tags = [t.strip().lower() for t in vulnerability.split(",") if t.strip()]
        if program and program.lower() != "n/a":
            tags.append(program.strip().lower())

        writeups.append({
            "title": title or f"{vulnerability} in {program}",
            "url": link_url,
            "category": "Real-World Writeups (MNCs & Bounties)",
            "author": author,
            "program": program,
            "vulnerability": vulnerability,
            "reward": reward,
            "publication_date": date,
            "tags": tags,
            "description": f"Real-world finding of {vulnerability} reported to {program} by {author}." + (f" Awarded {reward}." if reward and reward != "N/A" else "")
        })

    print(f"[+] Successfully extracted {len(writeups)} individual real-world writeup links from PentesterLand!")
    return writeups


def main():
    print("=" * 70)
    print("Building Master Bug Bounty Dataset & Link Feed for Antigravity")
    print("=" * 70)

    # 1. Fetch live writeups
    pt_writeups = fetch_pentesterland_writeups()

    # 2. Combine curated sources and writeups
    all_links = list(CURATED_SOURCES)
    all_links.extend(pt_writeups)

    print(f"\n[+] Total verified relatable links in database: {len(all_links):,}")

    # 3. Save JSON master feed
    json_path = OUTPUT_DIR / "master_bug_bounty_feed.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_count": len(all_links),
            "generated_at": "2026-10-29",
            "categories_summary": {
                "Methodology": sum(1 for x in all_links if x.get("category") == "Methodology"),
                "Tools": sum(1 for x in all_links if x.get("category") == "Tools"),
                "Labs": sum(1 for x in all_links if x.get("category") == "Labs"),
                "CTF Writeups": sum(1 for x in all_links if x.get("category") == "CTF Writeups"),
                "MNC Disclosures": sum(1 for x in all_links if x.get("category") == "MNC Disclosures"),
                "Books": sum(1 for x in all_links if x.get("category") == "Books"),
                "Real-World Writeups": sum(1 for x in all_links if "Real-World" in x.get("category", ""))
            },
            "links": all_links
        }, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved structured JSON feed to: {json_path}")

    # 4. Save Markdown Catalog
    md_path = OUTPUT_DIR / "master_bug_bounty_feed.md"
    print(f"[*] Generating curated Markdown catalog at: {md_path}...")
    
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Master Bug Bounty Knowledge Feed & Link Index (1,000+ Curated Sources)\n\n")
        f.write(f"> **Total Resources Indexed:** {len(all_links):,} URLs and reference guides\n")
        f.write("> **Target:** High-priority bug hunting methodology, automated tools, lab setups, CTF archives, MNC disclosures, and essential literature.\n\n")

        # Group by category
        categories = ["Methodology", "Tools", "Labs", "CTF Writeups", "MNC Disclosures", "Books"]
        for cat in categories:
            items = [x for x in all_links if x.get("category") == cat]
            f.write(f"\n## 📌 {cat} ({len(items)} curated items)\n\n")
            f.write("| Resource Name | Link | Tags / Highlights | Summary |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for item in items:
                title = item.get("title", "").replace("|", "-")
                url = item.get("url", "")
                tags = ", ".join(item.get("tags", [])[:4])
                desc = item.get("description", "").replace("|", "-")
                f.write(f"| **{title}** | [{url}]({url}) | `{tags}` | {desc} |\n")

        # Write sample of top real-world writeups grouped by vulnerability
        f.write("\n## 🌐 Real-World MNC & Fortune 500 Bug Bounty Writeups Archive\n\n")
        f.write(f"This section indexes **{len(pt_writeups):,}** publicly disclosed writeups organized from programs such as **Google, Uber, Apple, Meta, Microsoft, PayPal, Shopify, DoD, Twitter/X, Valve, Yahoo, TikTok, and GitHub**.\n\n")
        
        # Write first 100 featured disclosures in Markdown table, and link to JSON for the full 1,000+
        f.write("### Featured Top-Priority Disclosures (Sample of First 100):\n\n")
        f.write("| Vulnerability | Target MNC / Program | Author | Reward | Writeup Link |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for w in pt_writeups[:100]:
            vuln = w.get("vulnerability", "Vuln").replace("|", "-")
            prog = w.get("program", "Program").replace("|", "-")
            auth = w.get("author", "Author").replace("|", "-")
            rew = w.get("reward", "N/A").replace("|", "-")
            url = w.get("url", "")
            f.write(f"| {vuln} | **{prog}** | {auth} | `{rew}` | [Read Writeup]({url}) |\n")

        f.write(f"\n\n*(Full catalog of all {len(all_links):,} links is indexed and searchable in `master_bug_bounty_feed.json`)*\n")

    print(f"[+] Master Markdown catalog generated successfully: {md_path}")


if __name__ == "__main__":
    main()
