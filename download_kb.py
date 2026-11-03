"""
Knowledge Base Downloader & Indexer for Antigravity Bug Bounty Agent.
Clones the curated high-signal repositories into knowledge_base/ with --depth 1.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BASE_DIR = ROOT_DIR / "knowledge_base"

# Startup check: ensure parent directory exists rather than silently creating a disconnected folder tree
if not BASE_DIR.parent.exists():
    raise RuntimeError(f"Expected repository root directory does not exist: {BASE_DIR.parent}")

REPOSITORIES = [
    # Category 1: Methodologies & Playbooks
    {
        "category": "methodologies",
        "name": "owasp-wstg",
        "url": "https://github.com/OWASP/wstg.git",
        "description": "OWASP Web Security Testing Guide (100+ testing modules)",
        "license": "CC BY-SA 4.0",
        "notice": "Share-Alike: Adaptation/redistribution must retain CC BY-SA 4.0 and credit OWASP."
    },
    {
        "category": "methodologies",
        "name": "hacktricks",
        "url": "https://github.com/Carlospolop/hacktricks.git",
        "description": "HackTricks pentesting & bounty playbooks",
        "license": "CC BY-NC 4.0",
        "notice": "RESTRICTED: Non-Commercial research only. Not authorized for commercial bug bounty or monetary reward."
    },
    {
        "category": "methodologies",
        "name": "hacktricks-cloud",
        "url": "https://github.com/Carlospolop/hacktricks-cloud.git",
        "description": "HackTricks Cloud security guide (AWS, GCP, Azure, K8s)",
        "license": "No Grant / CC BY-NC 4.0 (Parent)",
        "notice": "RESTRICTED: Non-Commercial research only / All Rights Reserved. Not authorized for commercial use."
    },
    {
        "category": "methodologies",
        "name": "tbhm",
        "url": "https://github.com/jhaddix/tbhm.git",
        "description": "Jason Haddix The Bug Hunter's Methodology",
        "license": "No License (All Rights Reserved)",
        "notice": "RESTRICTED: No open-source grant. Cloned strictly for local personal reading under fair use."
    },
    {
        "category": "methodologies",
        "name": "howtohunt",
        "url": "https://github.com/KathanP19/HowToHunt.git",
        "description": "HowToHunt tutorials and checklists per bug class",
        "license": "GPL-3.0",
        "notice": "Strong Copyleft: Derivative code must be distributed under GPL-3.0."
    },
    {
        "category": "methodologies",
        "name": "bugbounty-cheatsheet",
        "url": "https://github.com/EdOverflow/bugbounty-cheatsheet.git",
        "description": "EdOverflow Bug Bounty Cheatsheet",
        "license": "CC BY-SA 4.0",
        "notice": "Share-Alike: Credit EdOverflow; adaptations require identical CC BY-SA 4.0 terms."
    },
    {
        "category": "methodologies",
        "name": "api-security-checklist",
        "url": "https://github.com/shieldfy/API-Security-Checklist.git",
        "description": "Shieldfy API Security Checklist",
        "license": "MIT",
        "notice": "Permissive: Retain original copyright and permission notice."
    },

    # Category 2: Payloads, Bypasses & Fingerprints
    {
        "category": "payloads",
        "name": "PayloadsAllTheThings",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "description": "PayloadsAllTheThings - 70+ vulnerability categories and bypasses",
        "license": "MIT",
        "notice": "Permissive: Retain original copyright and permission notice."
    },
    {
        "category": "payloads",
        "name": "can-i-take-over-xyz",
        "url": "https://github.com/EdOverflow/can-i-take-over-xyz.git",
        "description": "Subdomain takeover fingerprints for 80+ cloud services",
        "license": "CC BY 4.0",
        "notice": "Permissive Attribution: Retain credit to EdOverflow."
    },

    # Category 3: Disclosed Bug Bounty Writeups
    {
        "category": "writeups",
        "name": "Awesome-Bugbounty-Writeups",
        "url": "https://github.com/devanshbatham/Awesome-Bugbounty-Writeups.git",
        "description": "Categorized writeups by bug class",
        "license": "No License (All Rights Reserved)",
        "notice": "RESTRICTED: No open-source grant. Local personal reading only."
    },
    {
        "category": "writeups",
        "name": "bug-bounty-reference",
        "url": "https://github.com/ngalongc/bug-bounty-reference.git",
        "description": "Categorized public writeups across top tech companies",
        "license": "No License (All Rights Reserved)",
        "notice": "RESTRICTED: No open-source grant. Local personal reading only."
    },
    {
        "category": "writeups",
        "name": "hackerone-reports",
        "url": "https://github.com/reddelexc/hackerone-reports.git",
        "description": "Curated top HackerOne disclosed reports",
        "license": "No License (All Rights Reserved)",
        "notice": "RESTRICTED: Report copyrights belong to individual researchers and HackerOne. Local study only."
    },
    {
        "category": "writeups",
        "name": "awesome-bug-bounty-2026",
        "url": "https://github.com/itsmohitnarayan/awesome-bug-bounty.git",
        "description": "Curated programs, writeups & researcher blogs",
        "license": "CC0 1.0",
        "notice": "Public Domain Dedication: Free unrestricted use."
    },

    # Category 4: Templates & CTF
    {
        "category": "templates",
        "name": "nuclei-templates",
        "url": "https://github.com/projectdiscovery/nuclei-templates.git",
        "description": "ProjectDiscovery Nuclei 9,000+ community detection templates",
        "license": "MIT",
        "notice": "Permissive: Retain original ProjectDiscovery copyright."
    },
    {
        "category": "ctf_archives",
        "name": "ctf-wiki",
        "url": "https://github.com/ctf-wiki/ctf-wiki.git",
        "description": "CTF Wiki technical breakdown of vulnerability classes",
        "license": "CC BY-NC-SA 4.0",
        "notice": "RESTRICTED: Non-Commercial & Share-Alike only. Commercial bounty use is strictly prohibited."
    }
]


def clone_repo(repo: dict):
    target_dir = BASE_DIR / repo["category"] / repo["name"]
    license_tag = repo.get("license", "Unknown")
    notice = repo.get("notice", "")
    print(f"\n[*] [{repo['name']}] License: {license_tag}")
    if "RESTRICTED" in notice:
        print(f"    [!] COMPLIANCE WARNING: {notice}")
    else:
        print(f"    [i] Terms: {notice}")

    if target_dir.exists() and any(target_dir.iterdir()):
        print(f"    [+] Skipping (already present locally at {target_dir})")
        return True

    target_dir.parent.mkdir(parents=True, exist_ok=True)
    print(f"    [*] Cloning -> {target_dir} ...")
    cmd = ["git", "clone", "--depth", "1", repo["url"], str(target_dir)]
    try:
        start_t = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        elapsed = time.time() - start_t
        if res.returncode == 0:
            print(f"[+] Successfully cloned {repo['name']} in {elapsed:.1f}s")
            return True
        else:
            print(f"[!] Failed to clone {repo['name']}: {res.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout cloning {repo['name']} (>180s)")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False


def count_files(base_dir: Path):
    md_count = 0
    yaml_count = 0
    total_bytes = 0
    for root, dirs, files in os.walk(base_dir):
        # Skip git internal files
        if ".git" in dirs:
            dirs.remove(".git")
        for f in files:
            if f.endswith(".md") or f.endswith(".markdown"):
                md_count += 1
                try:
                    total_bytes += (Path(root) / f).stat().st_size
                except Exception:
                    pass
            elif f.endswith(".yaml") or f.endswith(".yml"):
                yaml_count += 1
                try:
                    total_bytes += (Path(root) / f).stat().st_size
                except Exception:
                    pass
    return md_count, yaml_count, total_bytes


def main():
    print("=" * 75)
    print("Populating Antigravity Knowledge Base with High-Signal Repositories")
    print("NOTICE: Review LICENSES.md before using downloaded materials.")
    print("Several repositories (HackTricks, CTF Wiki) are strictly Non-Commercial")
    print("(CC BY-NC 4.0) and must not be used for commercial bug bounty activities.")
    print("=" * 75)

    success_count = 0
    for repo in REPOSITORIES:
        if clone_repo(repo):
            success_count += 1

    md_count, yaml_count, total_bytes = count_files(BASE_DIR)
    print("\n" + "=" * 70)
    print("Knowledge Base Ingestion Complete!")
    print(f"Repositories Cloned: {success_count}/{len(REPOSITORIES)}")
    print(f"Total Markdown Files: {md_count:,}")
    print(f"Total YAML Templates: {yaml_count:,}")
    print(f"Total Content Size:   {total_bytes / (1024*1024):.1f} MB")
    print("=" * 70)


if __name__ == "__main__":
    main()
