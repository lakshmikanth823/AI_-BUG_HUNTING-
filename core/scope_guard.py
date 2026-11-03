"""
Scope & Authorisation Guard.
Enforces the strict requirements of 08-scope-authorisation.md:
- Target provenance against data/programs-ranked.csv and data/in_scope_assets.json or authorized local lab.
- Permanent Deny List blocking link-local, cloud metadata, RFC1918, and private networks.
- Strict DNS resolution check preventing hostname-based bypasses (D1).
- Thread-safe Request Budget Tracker enforcing max requests per probe (D2).
"""

import re
import csv
import json
import socket
import threading
import ipaddress
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"

PERMANENT_DENY_PATTERNS = [
    re.compile(r"^169\.254\.169\.254$"),
    re.compile(r"^metadata\.google\.internal$", re.I),
    re.compile(r"^100\.100\.100\.200$"),
    re.compile(r"^fd00:ec2::254$", re.I),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"\.internal$", re.I),
    re.compile(r"\.local$", re.I),
]

PERMANENT_DENY_CIDRS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

LAB_HOSTS = {"localhost", "127.0.0.1", "::1", "bounty-juiceshop", "bounty-dvwa", "bounty-webgoat", "bounty-crapi-web"}
LAB_PORTS = {3000, 8081, 8082, 9099, 8888}

_PIN_LOCK = threading.Lock()


class RequestBudgetTracker:
    """Thread-safe cumulative request budget tracker enforcing strict blast-radius controls."""
    def __init__(self, max_budget: int = 10):
        self.max_budget = max_budget
        self.current_count = 0
        self._lock = threading.Lock()

    def acquire(self, count: int = 1) -> bool:
        with self._lock:
            if self.current_count + count <= self.max_budget:
                self.current_count += count
                return True
            return False

    def check(self) -> Tuple[bool, str]:
        with self._lock:
            if self.current_count < self.max_budget:
                return True, f"BUDGET_OK ({self.current_count}/{self.max_budget} used)"
            return False, f"BUDGET_EXHAUSTED: Request budget exceeded ({self.current_count}/{self.max_budget}). Strict blast-radius limit enforced."

    def release(self, count: int = 1) -> None:
        """Returns budget for a request that was acquired but never reached the network."""
        if count <= 0:
            return
        with self._lock:
            self.current_count = max(0, self.current_count - count)

    def remaining(self) -> int:
        with self._lock:
            return max(0, self.max_budget - self.current_count)

    def reset(self):
        with self._lock:
            self.current_count = 0


def parse_host_port(destination: str) -> Tuple[str, Optional[int]]:
    """
    Robust destination parser handling IPv4, IPv6 (bare and bracketed), and hostnames with optional port.
    Examples:
      'localhost:5432' -> ('localhost', 5432)
      '127.0.0.1:3000' -> ('127.0.0.1', 3000)
      '[::1]:3000' -> ('::1', 3000)
      '[::1]' -> ('::1', None)
      '::1' -> ('::1', None)
      '169.254.169.254' -> ('169.254.169.254', None)
      'http://localhost:5432/test' -> ('localhost', 5432)
    """
    dest = destination.strip()
    if "://" in dest:
        parsed = urllib.parse.urlparse(dest)
        dest = parsed.netloc or parsed.path

    if dest.startswith("["):
        m = re.match(r"^\[([a-fA-F0-9:]+)\](?::(\d+))?", dest)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else None
            return host, port

    if dest.count(":") > 1:
        try:
            ipaddress.IPv6Address(dest)
            return dest, None
        except ValueError:
            pass

    if ":" in dest:
        parts = dest.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0].strip(), int(parts[1])
        return dest, None

    return dest, None


def resolve_destination(host: str) -> Tuple[List[str], Optional[str]]:
    """Resolves a hostname once. Returns (addresses, error); the caller pins the addresses it validates."""
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return [], f"DNS_RESOLUTION_FAILED: '{host}' did not resolve ({exc}); destination denied fail-closed"
    except Exception as exc:
        return [], f"DNS_RESOLUTION_ERROR: '{host}' resolution raised {type(exc).__name__}; destination denied fail-closed"

    ips: List[str] = []
    for sockaddr in (entry[4] for entry in addrs):
        ip = sockaddr[0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return [], f"DNS_RESOLUTION_EMPTY: '{host}' resolved to no addresses; destination denied fail-closed"
    return ips, None


@contextmanager
def pinned_dns(host: str, ips: List[str]):
    """
    Reuses the gate-validated addresses for `host` at connect time, so a second resolver
    answer (short-TTL / round-robin rebinding) cannot swap in a private or metadata IP.
    """
    if not host or not ips:
        yield
        return

    original = socket.getaddrinfo

    def _pinned(req_host, port=None, *args, **kwargs):
        if isinstance(req_host, (bytes, bytearray)):
            req_host = req_host.decode("utf-8", errors="replace")
        if isinstance(req_host, str) and req_host.lower() == host.lower():
            pinned = []
            for ip in ips:
                family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                pinned.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0)))
            return pinned
        return original(req_host, port, *args, **kwargs)

    with _PIN_LOCK:
        socket.getaddrinfo = _pinned
        try:
            yield
        finally:
            socket.getaddrinfo = original


def _deny_loopback_port(port: Optional[int]) -> Tuple[bool, str]:
    return True, (
        f"PERMANENT_DENY_VIOLATION: Loopback port {port} is not in authorized lab carve-out "
        f"({', '.join(str(p) for p in sorted(LAB_PORTS))})"
    )


def _validate_ips(host: str, port: Optional[int], ips: List[str], is_lab: bool) -> Tuple[bool, str]:
    """Denies if ANY validated address is loopback/metadata/RFC1918."""
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if ip.is_loopback:
            if is_lab:
                if port in LAB_PORTS:
                    continue
                return _deny_loopback_port(port)
            return True, f"PERMANENT_DENY_VIOLATION: Hostname '{host}' resolves to loopback IP {ip} outside authorized lab"

        for cidr in PERMANENT_DENY_CIDRS:
            if ip in cidr:
                return True, (
                    f"PERMANENT_DENY_VIOLATION: Hostname '{host}' resolves to reserved/private IP {ip} in {cidr}"
                    if ip_str != host
                    else f"PERMANENT_DENY_VIOLATION: Destination IP '{host}' falls within reserved/private network {cidr}"
                )
    return False, "CLEAN"


def _static_deny_check(destination: str, host: str, port: Optional[int], is_lab: bool) -> Optional[Dict[str, Any]]:
    """
    Deny-list matching that requires no name resolution: prohibited patterns, IP literals, and
    IPs embedded in a hostname. Returns a gate result when it can decide outright, else None.
    """
    result = {"denied": True, "reason": "", "host": host, "port": port, "ips": []}
    host_lower = host.lower()

    for pat in PERMANENT_DENY_PATTERNS:
        if pat.search(host_lower):
            result["reason"] = (
                f"PERMANENT_DENY_VIOLATION: Destination '{destination}' matches prohibited cloud metadata "
                f"or internal pattern: {pat.pattern}"
            )
            return result

    # 'localhost' is loopback by definition (RFC 6761); no resolution needed to deny it.
    if host_lower == "localhost":
        denied, reason = _validate_ips(host, port, ["127.0.0.1"], is_lab)
        result["denied"], result["reason"] = denied, reason
        if not denied and is_lab:
            result["reason"] = "CLEAN (AUTHORIZED_LAB_CARVE_OUT)"
        return result

    # IP literal
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        denied, reason = _validate_ips(host, port, [str(ip)], is_lab)
        result["denied"], result["reason"], result["ips"] = denied, reason, [str(ip)]
        if not denied and is_lab and ip.is_loopback:
            result["reason"] = "CLEAN (AUTHORIZED_LAB_CARVE_OUT)"
        return result

    # Embedded IP inside a hostname (e.g. 169.254.169.254.nip.io, 127.0.0.1.sslip.io)
    m_ip = re.search(r"(?:^|\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.|$)", host_lower)
    if m_ip:
        try:
            emb_ip = ipaddress.ip_address(m_ip.group(1))
        except ValueError:
            emb_ip = None
        if emb_ip is not None:
            if emb_ip.is_loopback:
                if not is_lab:
                    result["reason"] = (
                        f"PERMANENT_DENY_VIOLATION: Destination '{destination}' embeds loopback IP {emb_ip} "
                        "outside authorized lab"
                    )
                    return result
                if port not in LAB_PORTS:
                    result["reason"] = _deny_loopback_port(port)[1]
                    return result
            else:
                for cidr in PERMANENT_DENY_CIDRS:
                    if emb_ip in cidr:
                        result["reason"] = (
                            f"PERMANENT_DENY_VIOLATION: Destination '{destination}' embeds reserved/private IP "
                            f"{emb_ip} in {cidr}"
                        )
                        return result
    return None


def gate_destination(destination: str, is_lab: bool = False) -> Dict[str, Any]:
    """
    Single-resolution scope gate. Returns the deny verdict plus the exact addresses that were
    validated, so callers can pin them at connect time instead of resolving again.
    """
    host, port = parse_host_port(destination)
    result = {"denied": True, "reason": "", "host": host, "port": port, "ips": []}

    if not host:
        result["reason"] = "PERMANENT_DENY_VIOLATION: Empty or invalid destination host."
        return result

    static = _static_deny_check(destination, host, port, is_lab)
    if static is not None:
        return static

    # Resolve once and validate every returned address (fail closed on resolution errors)
    ips, resolve_error = resolve_destination(host)
    if resolve_error:
        if is_lab and host.lower() in LAB_HOSTS:
            if port in LAB_PORTS:
                result.update({"denied": False, "reason": "CLEAN (AUTHORIZED_LAB_CARVE_OUT)", "ips": []})
                return result
            result["reason"] = _deny_loopback_port(port)[1]
            return result
        result["reason"] = f"PERMANENT_DENY_VIOLATION: {resolve_error}"
        return result

    denied, reason = _validate_ips(host, port, ips, is_lab)
    result.update({"denied": denied, "reason": reason, "ips": ips})
    return result


def check_destination_deny_list(destination: str, is_lab: bool = False) -> Tuple[bool, str]:
    """
    Authoritative permanent deny-list check enforcing 08-scope-authorisation.md §2.
    Resolves hostnames once, inspects embedded IP patterns, validates the loopback port
    carve-out, and denies destinations that cannot be resolved.
    """
    gated = gate_destination(destination, is_lab=is_lab)
    return gated["denied"], gated["reason"]


def check_deny_list_static(destination: str, is_lab: bool = False) -> Tuple[bool, str]:
    """
    Deny-list check for triage-time evaluation of already-captured evidence. Performs no name
    resolution, so judging a finding never emits a query for the host it describes.
    """
    host, port = parse_host_port(destination)
    if not host:
        return True, "PERMANENT_DENY_VIOLATION: Empty or invalid destination host."
    static = _static_deny_check(destination, host, port, is_lab)
    if static is not None:
        return static["denied"], static["reason"]
    return False, "CLEAN (RESOLUTION DEFERRED TO EGRESS GATE)"


def admission_failure(prog_entry: Optional[Dict[str, Any]], label: str = "") -> str:
    """
    Single source of truth for operator admission. Returns '' when the asset-map entry is
    properly attested, else the reason. A missing or malformed entry never admits anything.
    """
    if not prog_entry or not isinstance(prog_entry, dict):
        return f"program '{label}' is not admitted to data/in_scope_assets.json."
    status = prog_entry.get("status", "")
    if status != "OPERATOR_AUTHORIZED":
        return (f"program '{label}' has status '{status or 'UNATTESTED'}'. "
                "Only 'OPERATOR_AUTHORIZED' targets are permitted. Step 7 remains locked.")
    auth_by = prog_entry.get("authorized_by")
    if (not auth_by or not isinstance(auth_by, dict) or not auth_by.get("operator_handle")
            or not auth_by.get("timestamp") or not auth_by.get("operator_quote")
            or not prog_entry.get("source_url")):
        return (f"program '{label}' lacks valid operator attestation block "
                "('operator_handle', 'timestamp', 'operator_quote') or 'source_url'. Step 7 remains locked.")
    return ""


class ScopeGuard:
    def __init__(self, programs_csv: Optional[Path] = None, assets_json: Optional[Path] = None):
        self.programs_csv = programs_csv or (DATA_DIR / "programs-ranked.csv")
        self.assets_json = assets_json or (DATA_DIR / "in_scope_assets.json")
        self.programs = self._load_programs()
        self.asset_map = self._load_asset_map()
        self.budget_tracker = RequestBudgetTracker(max_budget=10)

    def _load_programs(self) -> List[Dict[str, Any]]:
        if not self.programs_csv.exists():
            return []
        try:
            with open(self.programs_csv, "r", encoding="utf-8") as f:
                return list(csv.DictReader(f))
        except Exception:
            return []

    def _load_asset_map(self) -> Dict[str, Any]:
        if not self.assets_json.exists():
            return {}
        try:
            with open(self.assets_json, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def verify_target(self, target_url: str, program_name: str, is_lab: bool = False) -> Tuple[bool, str]:
        """Validates target provenance and bounds adhering to 08-scope-authorisation.md §1 & §6."""
        host, port = parse_host_port(target_url)
        if not host:
            return False, "OUT OF SCOPE — unknown is not a listed in-scope asset for unspecified program. Confirm authorisation or pick a target from data/programs-ranked.csv."

        host_lower = host.lower()

        # Lab validation
        if is_lab or host_lower in LAB_HOSTS:
            if host_lower in LAB_HOSTS:
                # Also check port carve-out
                if port and port not in LAB_PORTS:
                    return False, f"PERMANENT_DENY_VIOLATION: Loopback port {port} is not in authorized lab carve-out (3000, 8081, 8082, 9099, 8888)"
                return True, f"IN_SCOPE: Target '{host}' verified as authorized local lab asset."
            return False, f"OUT OF SCOPE — {host} is not a valid local lab host. Must be localhost/127.0.0.1."

        # Production Bug Bounty Provenance Verification FIRST (pure string matching, zero DNS)
        if not program_name:
            return False, f"OUT OF SCOPE — {host} is not a listed in-scope asset for unspecified program. Confirm authorisation or pick a target from data/programs-ranked.csv."

        prog_lower = program_name.strip().lower()
        matched = None
        for p in self.programs:
            if p.get("name", "").strip().lower() == prog_lower:
                matched = p
                break

        if not matched:
            return False, f"OUT OF SCOPE — {host} is not a listed in-scope asset for {program_name}. Confirm authorisation or pick a target from data/programs-ranked.csv."

        canonical_name = matched.get("name", "")
        prog_entry = self.asset_map.get(canonical_name)
        if not prog_entry:
            # Case-insensitive fallback across asset_map keys
            for k, v in self.asset_map.items():
                if k.strip().lower() == canonical_name.strip().lower() or k.strip().lower() == prog_lower:
                    prog_entry = v
                    break

        if not prog_entry:
            return False, f"OUT OF SCOPE — program '{program_name}' is not admitted to data/in_scope_assets.json. Confirm authorisation or pick a target from data/programs-ranked.csv."

        # Load-bearing status check
        failure = admission_failure(prog_entry, canonical_name)
        if failure:
            return False, f"OUT OF SCOPE — {failure} Confirm authorisation or pick a target from data/programs-ranked.csv."

        prog_assets = prog_entry.get("in_scope_assets", [])

        is_asset_in_scope = False
        for pattern in prog_assets:
            p_pat = pattern.lower().strip()
            if p_pat.startswith("*."):
                suffix = p_pat[1:]
                if host_lower.endswith(suffix) or host_lower == p_pat[2:]:
                    is_asset_in_scope = True
                    break
            elif host_lower == p_pat:
                is_asset_in_scope = True
                break

        if not is_asset_in_scope:
            return False, f"OUT OF SCOPE — {host} is not a listed in-scope asset for {program_name}. Confirm authorisation or pick a target from data/programs-ranked.csv."

        # Once provenance is strictly verified, check Permanent Deny List (DNS resolution)
        is_denied, deny_reason = self.check_deny_list(target_url, is_lab=is_lab)
        if is_denied:
            return False, deny_reason

        return True, f"IN_SCOPE: Host '{host}' verified against authorized program '{canonical_name}' ({matched.get('platform')})."

    def check_deny_list(self, destination: str, is_lab: bool = False) -> Tuple[bool, str]:
        return check_destination_deny_list(destination, is_lab=is_lab)

    def get_program_info(self, query: str) -> Optional[Dict[str, Any]]:
        q = query.lower().strip()
        for p in self.programs:
            if q == p.get("name", "").lower().strip() or q in p.get("name", "").lower():
                return p
        return None
