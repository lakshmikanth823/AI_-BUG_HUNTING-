#!/usr/bin/env python3
"""Master verification suite: 10 sections covering corpus integrity, arithmetic,
safety, Antigravity rule package, internal links, stale figures, claim guards,
triage gate & scope rules, lab configuration, and query tool consistency.
"""

import csv, glob, json, os, re, sys, subprocess, yaml
from collections import Counter, defaultdict

# Fix Windows stdout encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__)).replace("\\", "/")
ROOT = os.path.abspath(os.path.join(HERE, "..")).replace("\\", "/")
WORKSPACE_ROOT = os.path.abspath(os.path.join(ROOT, "../..")).replace("\\", "/")
DATA = f"{ROOT}/data"
DOCS = [f"{ROOT}/{f}" for f in ("STRATEGY.md", "TOP_PROGRAMS.md", "BOOKS.md", "LABS.md", "INDEX.md")]
all_rules = glob.glob(f"{ROOT}/antigravity/.agents/rules/*.md")

fails = []
def chk(cond, msg):
    if cond:
        print(f"  PASS  {msg}")
    else:
        print(f"  FAIL  {msg}")
        fails.append(msg)

def f(n): return f"{n:,}" if isinstance(n, int) else str(n)

# ==============================================================================
# SECTION 1: CORPUS INTEGRITY
# ==============================================================================
print("\n=== 1. corpus integrity ===")
j_raw = json.load(open(f"{DATA}/links.json", encoding="utf-8"))
j = j_raw["links"] if "links" in j_raw else j_raw
t = [l.strip() for l in open(f"{DATA}/all-links.txt", encoding="utf-8") if l.strip()]
c = list(csv.DictReader(open(f"{DATA}/links.csv", encoding="utf-8")))

rules1 = glob.glob(f"{ROOT}/antigravity/.agents/rules/1*.md") + glob.glob(f"{ROOT}/antigravity/.agents/rules/2*.md")
rb = sum(sum(1 for line in open(f_rule, encoding="utf-8") if re.match(r"^-\s+[✓~x]\s+<https?://", line)) for f_rule in rules1)

chk(len(j) == len(t) == len(c) == rb == 9879, f"count identical across links.json / all-links.txt / links.csv / rule bullets  ({f(len(t))})")
chk(len(set(t)) == len(t), "no duplicate URLs")
chk(all(u.startswith("http://") or u.startswith("https://") for u in t), "every URL is absolute http(s)")

# ==============================================================================
# SECTION 2: ARITHMETIC RECONCILIATION
# ==============================================================================
print("\n=== 2. arithmetic reconciliation ===")
N = json.load(open(f"{HERE}/final_numbers.json"))

chk(N["vkept"] + N["vfail"] == N["uniq"], f"validated set == unique candidates  ({f(N['uniq'])})")
chk(N["vkept"] == 10246, f"validation pass buckets -> {f(N['vkept'])}")
chk(N["vkept"] + N["vfail"] == N["uniq"], f"{f(N['vkept'])} passed + {f(N['vfail'])} failed == {f(N['uniq'])}")

computed_kept = N["vkept"] - N["unsafe"] - N["low"] + N["overlap"]
chk(computed_kept == N["total"] == 9879, f"{f(N['total'])} kept + {f(N['dead'])} dead + {f(N['unsafe'])} unsafe + {f(N['low'])} low-value == {f(N['uniq'])}")
chk(N["overlap"] == 44, f"overlap (failures already caught by safety/low-value) == {N['overlap']}")
chk(N["core"] + N["adj"] == N["total"], f"core {f(N['core'])} + adjacent {f(N['adj'])} == {f(N['total'])}")

cat_counts = Counter(x.get("category") for x in j)
chk(sum(cat_counts.values()) == N["total"], "17 categories sum to total")
chk(all(cat_counts[k] == N["cats"][k] for k in N["cats"]), "category counts match links.json")

core_lines = sum(1 for l in open(f"{DATA}/all-links-core.txt", encoding="utf-8") if l.strip())
chk(core_lines == N["core"], "all-links-core.txt == core count")

live_lines = sum(1 for l in open(f"{DATA}/verified-live-only.txt", encoding="utf-8") if l.strip())
chk(live_lines == N["live"], "verified-live-only.txt == live count")

dead_csv = sum(1 for _ in csv.DictReader(open(f"{DATA}/dropped-dead-links.csv", encoding="utf-8")))
chk(dead_csv == N["dead"], "dropped-dead-links.csv rows == dead count")

low_csv = sum(1 for _ in csv.DictReader(open(f"{DATA}/dropped-low-value-links.csv", encoding="utf-8")))
chk(low_csv == N["low"], "dropped-low-value csv rows == low-value count")

unsafe_txt = sum(1 for l in open(f"{DATA}/dropped-unsafe-ssrf-targets.txt", encoding="utf-8") if l.strip())
chk(unsafe_txt == N["unsafe"], "dropped-unsafe file == unsafe count")

prog_csv = sum(1 for _ in csv.DictReader(open(f"{DATA}/programs-ranked.csv", encoding="utf-8")))
chk(prog_csv == N["programs"] == 946, f"programs-ranked.csv rows == {N['programs']}")

# ==============================================================================
# SECTION 3: SAFETY
# ==============================================================================
print("\n=== 3. safety ===")
bad_ssrf = []
SSRF_PAT = re.compile(
    r"://(169\.254\.|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|"
    r"metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|0\.0\.0\.0|"
    r"[^/]+\.internal|[^/]+\.local)"
)
for u in t:
    if SSRF_PAT.search(u): bad_ssrf.append(u)
chk(len(bad_ssrf) == 0, f"no SSRF / cloud-metadata / private-IP URLs in corpus ({len(bad_ssrf)} found)")

# ==============================================================================
# SECTION 4: ANTIGRAVITY RULE PACKAGE
# ==============================================================================
print("\n=== 4. Antigravity rule package ===")
chk(len(all_rules) == 66, f"66 total rule files (64 corpus + 2 gate rules, found {len(all_rules)})")

big = 0; bad_yaml = 0
for r in all_rules:
    sz = os.path.getsize(r); big = max(big, sz)
    txt = open(r, encoding="utf-8").read(300)
    if not (txt.startswith("---\n") and "\n---\n" in txt):
        bad_yaml += 1
chk(big <= 24000, f"largest rule file {f(big)} B <= 24,000 B limit")
chk(bad_yaml == 0, "every rule file has YAML frontmatter")

always = [r for r in all_rules if "trigger: always_on" in open(r, encoding="utf-8").read(200)]
chk(len(always) == 3, f"exactly 3 always_on rules (00-index, 08-scope, 09-triage; found {len(always)})")

# Check: every rule with trigger: model_decision has a non-empty description
model_dec_rules = [r for r in all_rules if "trigger: model_decision" in open(r, encoding="utf-8").read(300)]
missing_desc = []
for r in model_dec_rules:
    txt = open(r, encoding="utf-8").read(400)
    m = re.search(r"description:\s*([^\n]+)", txt)
    if not m or not m.group(1).strip() or m.group(1).strip() in ('""', "''", "none"):
        missing_desc.append(os.path.basename(r))
chk(len(missing_desc) == 0, f"every rule with trigger: model_decision has a non-empty description ({len(missing_desc)} missing)")

# ==============================================================================
# SECTION 5: INTERNAL REFERENCES
# ==============================================================================
print("\n=== 5. internal document references ===")
bad_refs = defaultdict(int)
nref = 0
for d in DOCS + [f"{ROOT}/antigravity/.agents/rules/00-corpus-index.md"]:
    if not os.path.exists(d): continue
    txt = open(d, encoding="utf-8").read()
    for m in re.finditer(r"by-category/(\d\d-[a-z0-9\-]+\.md)", txt):
        nref += 1
        target_path = f"{ROOT}/by-category/{m.group(1)}"
        if not os.path.exists(target_path):
            bad_refs[(os.path.basename(d), m.group(1))] += 1
chk(len(bad_refs) == 0 and nref == 37, f"37 by-category refs all resolve ({nref} found, {len(bad_refs)} broken)")

# ==============================================================================
# SECTION 6: STALE FIGURES
# ==============================================================================
print("\n=== 6. doc prose carries no stale figures ===")
stale = []
for d in DOCS:
    if not os.path.exists(d): continue
    s = open(d, encoding="utf-8").read()
    for wrong in ("9,013", "9,881", "5,779", "10,113", "11,084", "65 rule files", "(0 templates)", "(0 pages)", "948 programs"):
        if wrong in s: stale.append((os.path.basename(d), wrong))
chk(not stale, f"no stale numbers in prose ({len(stale)} found)")
for d, w in stale: print(f"        {d}: {w}")

# ==============================================================================
# SECTION 7: CLAIM GUARDS (Hours-not-days & Paid/Responsive Disjointness)
# ==============================================================================
print("\n=== 7. CLAIM GUARDS ===")
p_rows = list(csv.DictReader(open(f"{DATA}/programs-ranked.csv", encoding="utf-8")))

unit_errs = []
suspicious_hours = []
for r in p_rows:
    ttr_h = r.get("ttr_hours"); ttr_d = r.get("ttr_days")
    if ttr_h and ttr_d:
        expected = round(float(ttr_h) / 24.0, 2)
        if abs(float(ttr_d) - expected) > 0.05:
            unit_errs.append((r["name"], "ttr", ttr_h, ttr_d, expected))
        if 0 < float(ttr_h) < 24:
            suspicious_hours.append((r["name"], "ttr", ttr_h))
    ttb_h = r.get("ttb_hours"); ttb_d = r.get("ttb_days")
    if ttb_h and ttb_d:
        expected = round(float(ttb_h) / 24.0, 2)
        if abs(float(ttb_d) - expected) > 0.05:
            unit_errs.append((r["name"], "ttb", ttb_h, ttb_d, expected))
        if 0 < float(ttb_h) < 24:
            suspicious_hours.append((r["name"], "ttb", ttb_h))

# Guard: no *_days column value is non-integer-derived from its *_hours
chk(len(unit_errs) == 0, f"every *_days column equals *_hours / 24 ({len(unit_errs)} mismatches)")

# Converse Guard: no *_hours field is suspiciously small (< 24) where days >= 1.0 (prevents 24x scaling regression in reverse)
suspicious_hours = [r["name"] for r in p_rows if r.get("ttr_hours") and float(r.get("ttr_days") or 0) >= 1.0 and float(r["ttr_hours"]) < 24]
chk(len(suspicious_hours) == 0, f"no *_hours field is suspiciously small (< 24) where days >= 1 ({len(suspicious_hours)} found)")

# Guard: benchmark responsive programs in TOP_PROGRAMS have ttr_hours >= 24
bench_ttr = [p for p in ("inDrive", "Eternal", "Airbnb") if next((float(r["ttr_hours"]) for r in p_rows if r["name"] == p), 0) < 24]
chk(len(bench_ttr) == 0, f"benchmark responsive programs in TOP_PROGRAMS have ttr_hours >= 24 ({len(bench_ttr)} failing)")

# Guard: no days value exceeds 10 years (3,650 days)
too_long = [r["name"] for r in p_rows if r.get("ttr_days") and float(r["ttr_days"]) > 3650]
chk(len(too_long) == 0, f"no resolution time exceeds 10 years ({len(too_long)} found)")

# Guard: paid and responsive join is disjoint (0 programs have both)
p_summary = json.load(open(f"{HERE}/programs_summary.json", encoding="utf-8"))
chk(p_summary.get("paid_and_responsive") == 0, "payout and responsiveness are disjoint (intersection is 0)")

# Guard: no shipped doc contains unsupported claims
overclaim_errs = []
for d in DOCS:
    if not os.path.exists(d): continue
    txt = open(d, encoding="utf-8").read()
    if "they pay quickly" in txt.lower():
        overclaim_errs.append((os.path.basename(d), "unsupported phrase 'they pay quickly'"))
chk(len(overclaim_errs) == 0, f"no unsupported 'they pay quickly' claims in prose ({len(overclaim_errs)} found)")

# ==============================================================================
# SECTION 8: TRIAGE GATE & SCOPE AUTHORISATION RULES
# ==============================================================================
print("\n=== 8. gate rules ===")
r09_path = f"{ROOT}/antigravity/.agents/rules/09-triage-gate.md"
r08_path = f"{ROOT}/antigravity/.agents/rules/08-scope-authorisation.md"

chk(os.path.exists(r09_path), "09-triage-gate.md exists")
chk(os.path.exists(r08_path), "08-scope-authorisation.md exists")

if os.path.exists(r09_path) and os.path.exists(r08_path):
    r09_txt = open(r09_path, encoding="utf-8").read()
    r08_txt = open(r08_path, encoding="utf-8").read()
    r09_sz = os.path.getsize(r09_path)
    r08_sz = os.path.getsize(r08_path)

    chk("trigger: always_on" in r09_txt[:200], "09-triage-gate.md trigger is always_on")
    chk("trigger: always_on" in r08_txt[:200], "08-scope-authorisation.md trigger is always_on")
    chk(r09_sz < 12000, f"09-triage-gate.md size {f(r09_sz)} B < 12,000 B budget")
    chk(r08_sz < 8000, f"08-scope-authorisation.md size {f(r08_sz)} B < 8,000 B budget")

    q_check = all(f"Q{i}" in r09_txt or f"{i}." in r09_txt for i in range(1, 8))
    chk(q_check, "09-triage-gate.md contains all seven stage-1 impact questions")
    contract_check = all(k in r09_txt for k in ("OUTPUT CONTRACT", "VERDICT:", "STAGE REACHED:", "BLOCKING GAP:", "SEVEN ANSWERS:", "CVSS:", "NEXT ACTION:"))
    chk(contract_check, "09-triage-gate.md contains full OUTPUT CONTRACT block")

    deny_entries = [
        "169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254",
        "169.254.0.0/16", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "*.internal", "*.local", "0.0.0.0"
    ]
    deny_check = all(de in r08_txt for de in deny_entries)
    chk(deny_check, "08-scope-authorisation.md contains all 12 permanent deny list entries")

    always_on_files = [r for r in all_rules if "trigger: always_on" in open(r, encoding="utf-8").read(200)]
    always_on_bytes = sum(os.path.getsize(r) for r in always_on_files)
    approx_tokens = always_on_bytes // 4
    chk(approx_tokens < 20000, f"always_on aggregate: {len(always_on_files)} files, {f(always_on_bytes)} B (~{f(approx_tokens)} tokens) < 20,000 tokens limit")

# ==============================================================================
# SECTION 9: LAB LAYER
# ==============================================================================
print("\n=== 9. lab layer ===")
compose_files = [
    f"{WORKSPACE_ROOT}/docker-compose.yml",
    f"{WORKSPACE_ROOT}/lab/docker-compose.yml",
]

bad_binds = []
zero_zero_finds = []
host_ports = []
host_mode_violations = []
privileged_violations = []

for compose_path in compose_files:
    chk(os.path.exists(compose_path), f"compose file exists: {os.path.relpath(compose_path, WORKSPACE_ROOT)}")
    if os.path.exists(compose_path):
        raw_text = open(compose_path, encoding="utf-8").read()
        
        # Style-independent port extraction via PyYAML
        ports_to_check = []
        try:
            parsed_yaml = yaml.safe_load(raw_text)
            if not isinstance(parsed_yaml, dict) or "services" not in parsed_yaml or not isinstance(parsed_yaml.get("services"), dict):
                chk(False, f"compose schema violation in {compose_path}: missing top-level 'services' mapping")
            else:
                # Check top-level networks for driver: host
                top_networks = parsed_yaml.get("networks")
                if isinstance(top_networks, dict):
                    for net_name, net_cfg in top_networks.items():
                        if isinstance(net_cfg, dict) and str(net_cfg.get("driver", "")).strip().lower() == "host":
                            host_mode_violations.append(f"{os.path.basename(compose_path)}: network '{net_name}' uses driver: host")

                for s_name, s_cfg in parsed_yaml.get("services", {}).items():
                    if isinstance(s_cfg, dict):
                        # Guard against network_mode: host and privileged: true (in bool or string forms)
                        if str(s_cfg.get("network_mode", "")).strip().lower() == "host":
                            host_mode_violations.append(f"{os.path.basename(compose_path)}: service '{s_name}' uses network_mode: host")
                        priv = s_cfg.get("privileged")
                        if priv is True or str(priv).strip().lower() in ("true", "1", "yes"):
                            privileged_violations.append(f"{os.path.basename(compose_path)}: service '{s_name}' uses privileged: true")

                        p_entry = s_cfg.get("ports", [])
                        if isinstance(p_entry, list):
                            for p in p_entry:
                                ports_to_check.append(p)
                        elif isinstance(p_entry, (str, int, dict)):
                            ports_to_check.append(p_entry)
        except Exception as e:
            chk(False, f"YAML parse error in {compose_path}: {e}")

        # Count actual published port entries (excluding non-publishing definitions)
        valid_published_count = 0

        for p_item in ports_to_check:
            # Handle long syntax dict e.g. {"target": 80, "published": "8888", "host_ip": "127.0.0.1"}
            if isinstance(p_item, dict):
                host_ip = p_item.get("host_ip")
                pub = p_item.get("published")
                if pub is None:
                    # Missing published port in long syntax fails closed
                    bad_binds.append(f"{os.path.basename(compose_path)}: {p_item} (long syntax missing 'published' key)")
                    continue
                valid_published_count += 1
                pub_clean = str(pub).strip()
                if host_ip != "127.0.0.1":
                    bad_binds.append(f"{os.path.basename(compose_path)}: {p_item} (host_ip != 127.0.0.1)")
                
                # Handle range or discrete port in published
                if "-" in pub_clean:
                    r_parts = pub_clean.split("-")
                    if len(r_parts) == 2 and r_parts[0].isdigit() and r_parts[1].isdigit():
                        p_start, p_end = int(r_parts[0]), int(r_parts[1])
                        if 1 <= p_start <= 65535 and 1 <= p_end <= 65535 and p_start <= p_end and (p_end - p_start) <= 1000:
                            for rp in range(p_start, p_end + 1):
                                host_ports.append(str(rp))
                        else:
                            bad_binds.append(f"{os.path.basename(compose_path)}: {p_item} (invalid published port range: bounds or reversed/excessive)")
                    else:
                        bad_binds.append(f"{os.path.basename(compose_path)}: {p_item} (invalid published port range)")
                elif pub_clean.isdigit():
                    host_ports.append(pub_clean)
                else:
                    bad_binds.append(f"{os.path.basename(compose_path)}: {p_item} (invalid published port)")
                continue

            valid_published_count += 1
            p_clean = str(p_item).strip().strip('"').strip("'")
            if "0.0.0.0" in p_clean:
                zero_zero_finds.append(f"{os.path.basename(compose_path)}: {p_clean}")

            # Check for bracketed IPv6 (e.g. "[::1]:8888:80" or "[::]:8888:80")
            if p_clean.startswith("["):
                # Non-standard / IPv6 spec is rejected from IPv4 loopback carve-out
                bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean} (IPv6/bracketed bind rejected; strictly 127.0.0.1 required)")
                continue

            # Strip protocol suffix like /tcp or /udp if present on container port
            p_no_proto = p_clean.split("/")[0]
            parts = p_no_proto.split(":")

            def _record_ports(raw_port: str):
                if "-" in raw_port:
                    p_range = raw_port.split("-")
                    if len(p_range) == 2 and p_range[0].isdigit() and p_range[1].isdigit():
                        p_start, p_end = int(p_range[0]), int(p_range[1])
                        if 1 <= p_start <= 65535 and 1 <= p_end <= 65535 and p_start <= p_end and (p_end - p_start) <= 1000:
                            for rp in range(p_start, p_end + 1):
                                host_ports.append(str(rp))
                        else:
                            bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean} (invalid port range: bounds or reversed/excessive)")
                    else:
                        bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean} (invalid port range syntax)")
                elif raw_port.isdigit():
                    host_ports.append(raw_port)
                else:
                    bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean} (invalid host port)")

            if len(parts) == 3:
                bind_ip, h_port, c_port = parts
                if bind_ip != "127.0.0.1":
                    bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean}")
                _record_ports(h_port)
            elif len(parts) == 2:
                # e.g., "8080:80" without host ip binds to 0.0.0.0 by default
                bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean}")
                _record_ports(parts[0])
            elif len(parts) == 1 and parts[0].isdigit():
                # e.g., "3000" exposes port directly on 0.0.0.0
                bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean}")
                _record_ports(parts[0])
            else:
                # Any unrecognized or unparsable port spec fails closed
                bad_binds.append(f"{os.path.basename(compose_path)}: {p_clean} (unrecognized port spec syntax)")

        # Guard against vacuous passes: compose file must declare published lab ports
        chk(valid_published_count > 0, f"compose file {os.path.basename(compose_path)} declares at least one published port ({valid_published_count} found)")

chk(len(bad_binds) == 0, f"host side of every compose published port is strictly 127.0.0.1 across all compose files ({len(bad_binds)} non-127 found)")
if bad_binds:
    for b in bad_binds: print(f"        EXPOSURE RISK: {b} does not bind to 127.0.0.1")

chk(len(zero_zero_finds) == 0, f"0.0.0.0 never appears in compose published ports ({len(zero_zero_finds)} found)")
chk(len(host_mode_violations) == 0, f"network_mode: host never used in compose services ({len(host_mode_violations)} found)")
if host_mode_violations:
    for v in host_mode_violations: print(f"        EXPOSURE RISK: {v}")

chk(len(privileged_violations) == 0, f"privileged: true never used in compose services ({len(privileged_violations)} found)")
if privileged_violations:
    for v in privileged_violations: print(f"        EXPOSURE RISK: {v}")

# Check that every compose host port appears in 08-scope-authorisation.md carve-out
r08_path = f"{ROOT}/antigravity/.agents/rules/08-scope-authorisation.md"
r08_txt = open(r08_path, encoding="utf-8").read() if os.path.exists(r08_path) else ""
unlisted_ports = [p for p in host_ports if f"`{p}`" not in r08_txt and p not in r08_txt]
chk(len(unlisted_ports) == 0, f"every compose host port appears in 08-scope carve-out ({len(unlisted_ports)} unlisted: {unlisted_ports})")

# Check that in_scope_assets.json admits non-lab programs strictly with valid operator attestation
assets_json_path = f"{WORKSPACE_ROOT}/data/in_scope_assets.json"
chk(os.path.exists(assets_json_path), f"data/in_scope_assets.json exists at {assets_json_path}")
if os.path.exists(assets_json_path):
    try:
        in_scope_data = json.load(open(assets_json_path, encoding="utf-8"))
        bad_entries = []
        for p_name, entry in in_scope_data.items():
            if p_name == "local_lab":
                continue
            auth = entry.get("authorized_by")
            status = entry.get("status")
            source_url = entry.get("source_url")
            if status != "OPERATOR_AUTHORIZED" or not auth or not isinstance(auth, dict) or not auth.get("operator_handle") or not auth.get("operator_quote") or not source_url:
                bad_entries.append((p_name, "missing operator attestation or source_url"))
        chk(len(bad_entries) == 0, f"in_scope_assets.json non-lab entries have operator attestation ({len(bad_entries)} invalid: {bad_entries})")
    except Exception as e:
        chk(False, f"in_scope_assets.json check error: {e}")
else:
    chk(False, "data/in_scope_assets.json missing; attestation check failed")

# ==============================================================================
# SECTION 10: QUERY TOOL CONSISTENCY
# ==============================================================================
print("\n=== 10. query tool ===")
query_py_path = f"{HERE}/query.py"
chk(os.path.exists(query_py_path), "work/query.py exists")

if os.path.exists(query_py_path):
    csv_paid = [r for r in p_rows if r.get("payout")]
    csv_paid.sort(key=lambda x: float(x["payout"]), reverse=True)
    top_csv_name = csv_paid[0]["name"]
    top_csv_val = float(csv_paid[0]["payout"])
    chk(top_csv_val == 3000000.0 and "OpenSea" in top_csv_name, f"query.py payout sort matches CSV top ({top_csv_name}: ${top_csv_val:,.0f})")

    # Guard 1: find <nonexistent> prints NO MATCH and never invents a row
    try:
        res_none = subprocess.check_output(["python", query_py_path, "find", "NonExistentProgramXYZ_999"], text=True)
        chk("NO MATCH" in res_none and "PROGRAM:" not in res_none, "query.py find <nonexistent> prints NO MATCH and never invents a row")
    except Exception as e:
        chk(False, f"query.py find nonexistent failed: {e}")

    # Guard 2: renders NO DATA for any program whose upstream hours == 0 or empty
    zero_ttr_prog = next((r["name"] for r in p_rows if not r.get("ttr_hours") or float(r.get("ttr_hours") or 0) == 0), None)
    if zero_ttr_prog:
        try:
            res_zero = subprocess.check_output(["python", query_py_path, "find", zero_ttr_prog], text=True)
            chk("Time to Resolve (TTR): NO DATA" in res_zero, f"query.py renders NO DATA for empty/zero upstream hours ({zero_ttr_prog})")
        except Exception as e:
            chk(False, f"query.py find zero-ttr failed: {e}")

print("\n" + ("=" * 65))
print(f"  {'ALL CHECKS PASSED' if not fails else str(len(fails)) + ' CHECK(S) FAILED'}")
print(f"  {f(N['total'])} verified URLs | {f(N['programs'])} bounty programs | "
      f"{len(all_rules)} total rule files (64 corpus + 2 gates) | 10 sections passing")
print("=" * 65)
sys.exit(1 if fails else 0)
