"""
Regression tests for the live (non-lab) request-ceiling arithmetic and for cross-tenant
probe session hygiene.

Why these exist: an operator-written 'max_request_budget' in data/in_scope_assets.json can
raise the live ceiling from 10 to as much as 150 requests. That is a blast-radius expansion,
so it must be armed only by an entry that would actually pass admission, and it must never
reach the network without the operator having written the attestation.
"""
import json
import socket
import sys
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from core.scope_guard import admission_failure  # noqa: E402
from engine.autonomous_hunter import AutonomousHunter  # noqa: E402
from engine.authz_probe import AuthzProbe, ProbeRefused  # noqa: E402

ATTESTED = {
    "status": "OPERATOR_AUTHORIZED",
    "source_url": "https://example.com/policy",
    "authorized_by": {"operator_handle": "@qa", "timestamp": "2026-10-31T00:00:00Z",
                      "operator_quote": "I hold an account in good standing"},
}
LIVE_URL = "http://clamp-probe.invalid/"

passed = 0
failed = []


def chk(cond, label):
    global passed
    if cond:
        passed += 1
        print(f"[PASS] {label}")
    else:
        failed.append(label)
        print(f"[FAIL] {label}")


def armed_budget(entry, max_probe_budget=None, program="clamp-program", is_lab=False):
    """Runs the live lifecycle against an unreachable host and reports the armed ceiling."""
    hunter = AutonomousHunter(is_lab=is_lab)
    hunter.evaluator._load_asset_map = lambda: ({program: entry} if entry is not None else {})
    dns, http = _count_network()
    try:
        hunter.hunt(program, LIVE_URL, max_probe_budget=max_probe_budget)
    finally:
        _restore_network()
    return hunter.budget_tracker.max_budget, dns[0], http[0]


_NET = {}


def _count_network():
    dns, http = [0], [0]
    _NET["dns"] = socket.getaddrinfo
    _NET["http"] = urllib.request.urlopen

    def counting_getaddrinfo(*a, **k):
        dns[0] += 1
        raise OSError("QA harness: resolution blocked")

    def counting_urlopen(*a, **k):
        http[0] += 1
        raise OSError("QA harness: egress blocked")

    socket.getaddrinfo = counting_getaddrinfo
    urllib.request.urlopen = counting_urlopen
    return dns, http


def _restore_network():
    socket.getaddrinfo = _NET["dns"]
    urllib.request.urlopen = _NET["http"]


def main():
    # 1. No entry at all: the safety default holds even if a caller asks for 500.
    budget, dns, http = armed_budget(None, 500)
    chk(budget == 10, f"unadmitted program clamps to 10 (got {budget}, asked 500)")
    chk(dns == 0 and http == 0, f"clamping decision emits zero DNS/HTTP (dns={dns}, http={http})")

    # 2. An entry that exists but is NOT admitted must never arm a larger ceiling.
    unattested = dict(ATTESTED)
    unattested.pop("status")
    unattested["status"] = "UNATTESTED"
    unattested["max_request_budget"] = 150
    budget, dns, http = armed_budget(unattested)
    chk(budget == 10, f"status=UNATTESTED cannot raise the ceiling (got {budget})")
    budget, dns, http = armed_budget({"max_request_budget": 150})
    chk(budget == 10, f"max_request_budget without any attestation is ignored (got {budget})")
    no_source = dict(ATTESTED)
    no_source["max_request_budget"] = 150
    no_source.pop("source_url")
    budget, _, _ = armed_budget(no_source)
    chk(budget == 10, f"missing source_url cannot raise the ceiling (got {budget})")

    # 3. A fully admitted entry may raise it, within the hard cap.
    ok = dict(ATTESTED)
    ok["max_request_budget"] = 120
    budget, dns, http = armed_budget(ok)
    chk(budget == 120, f"admitted entry arms operator ceiling (got {budget})")
    chk(dns == 0 and http == 0, f"armed-but-unreachable target still emits zero DNS/HTTP (dns={dns})")
    over = dict(ATTESTED)
    over["max_request_budget"] = 99999
    budget, _, _ = armed_budget(over)
    chk(budget == 150, f"ceiling is hard-capped at 150 (got {budget})")
    asked_low = dict(ATTESTED)
    asked_low["max_request_budget"] = 120
    budget, _, _ = armed_budget(asked_low, 40)
    chk(budget == 40, f"caller may ask for less than the ceiling (got {budget})")

    # 4. Junk values fall back to the default rather than to something large or negative.
    for bad, label in [(True, "bool"), (-5, "negative"), (0, "zero"), ("120", "string"), (None, "null")]:
        entry = dict(ATTESTED)
        entry["max_request_budget"] = bad
        budget, _, _ = armed_budget(entry)
        chk(budget == 10, f"max_request_budget={label} falls back to 10 (got {budget})")

    # 5. admission_failure is the single predicate both scope and budget consult.
    chk(admission_failure(ok, "clamp-program") == "", "fully attested entry passes admission")
    chk("UNATTESTED" in admission_failure(unattested, "clamp-program"), "unattested entry reports its status")
    chk("not admitted" in admission_failure(None, "clamp-program"), "absent entry is refused")

    # 6. Probe session hygiene: a static credential is refused, never silently dropped.
    calls = []

    class StubRecon:
        def fetch_endpoint(self, url, method="GET", headers=None, data=None,
                           budget_tracker=None, is_lab=False, program=None):
            calls.append((method, url, dict(headers or {})))
            return {"url": url, "status": 200, "headers": {},
                    "body": '{"ok":true,"id":"D7","token":"TK"}', "error": None}

    def cfg(**overrides):
        base = {
            "name": "probe", "title": "T", "accounts_owned_by_operator": True, "program": "local_lab",
            "attacker": {"label": "attacker",
                         "login": {"method": "POST", "path": "/login", "body": "{}",
                                   "extract": {"json_path": "token"}},
                         "header": {"Authorization": "Bearer {token}"}, "values": {"attacker_uid": "1"}},
            "victim": {"label": "victim",
                       "login": {"method": "POST", "path": "/login", "body": "{}",
                                 "extract": {"json_path": "token"}},
                       "header": {"Authorization": "Bearer {token}"}, "values": {"victim_uid": "2"}},
            "marker": {"mode": "plant", "as": "doc",
                       "request": {"path": "/docs/new", "method": "POST"}, "extract": {"json_path": "id"}},
            "attacker_control_request": {"path": "/docs/{attacker_uid}"},
            "cross_tenant_request": {"path": "/docs/{victim_uid}"},
        }
        base.update(overrides)
        return base

    static = cfg(attacker={"label": "attacker", "header": {"Authorization": "Bearer STATIC_A"},
                                  "values": {"attacker_uid": "1"}},
                 victim={"label": "victim", "header": {"Authorization": "Bearer STATIC_B"},
                         "values": {"victim_uid": "2"}})
    calls.clear()
    try:
        AuthzProbe(StubRecon()).run("http://127.0.0.1:8888", static, budget_tracker=None, is_lab=True)
        chk(False, "static bearer token must be refused")
    except ProbeRefused as exc:
        chk("no login step" in str(exc), f"static header without login refuses: {str(exc)[:60]}")
        chk(len(calls) == 0, f"refusal happens before any request (issued {len(calls)})")

    anonymous = cfg(attacker={"label": "attacker", "values": {"attacker_uid": "1"}},
                    victim={"label": "victim", "values": {"victim_uid": "2"}})
    try:
        AuthzProbe(StubRecon()).run("http://127.0.0.1:8888", anonymous, budget_tracker=None, is_lab=True)
        chk(False, "anonymous account block must be refused")
    except ProbeRefused as exc:
        chk("run anonymously" in str(exc), "account with no login and no header refuses")

    no_carrier = cfg(attacker={"label": "attacker",
                               "login": {"method": "POST", "path": "/login", "body": "{}",
                                         "extract": {"json_path": "token"}},
                               "values": {"attacker_uid": "1"}},
                     victim=cfg()["victim"])
    try:
        AuthzProbe(StubRecon()).run("http://127.0.0.1:8888", no_carrier, budget_tracker=None, is_lab=True)
        chk(False, "token that is never sent must be refused")
    except ProbeRefused as exc:
        chk("never be sent" in str(exc), "login without a header to carry the token refuses")

    # 7. The honest happy path still runs: login -> token -> header on every request.
    calls.clear()
    findings = AuthzProbe(StubRecon()).run("http://127.0.0.1:8888", cfg(), budget_tracker=None, is_lab=True)
    chk(len(findings) == 1, f"dynamic login probe still produces one candidate ({len(findings)})")
    chk(any(c[1].endswith("/login") and "Authorization" not in c[2] for c in calls),
        "the login request itself is unauthenticated")
    post_login = [c for c in calls if not c[1].endswith("/login")]
    chk(post_login and all(c[2].get("Authorization") == "Bearer TK" for c in post_login),
        f"every post-login request carries the runtime token ({len(post_login)} checked)")

    print("=" * 60)
    if failed:
        print(f"BUDGET CLAMP + PROBE HYGIENE: {passed} passed, {len(failed)} FAILED")
        for f in failed:
            print("  -", f)
        sys.exit(1)
    print(f"BUDGET CLAMP + PROBE HYGIENE: {passed} passed, 0 failed")


if __name__ == "__main__":
    main()
