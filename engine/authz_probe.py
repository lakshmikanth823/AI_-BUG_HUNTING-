"""
Cross-tenant (BOLA / IDOR) authorization probe.

The Triage Gate only accepts a cross-tenant read as proven when it can diff two captured
transactions: the attacker's response must contain a value the attacker's own control response
does not. Asserting `second_account_tested=True` proves nothing. This module performs those
captures for real and hands the bytes to the gate.

Safety model:
  * Sessions and identifiers come from an operator-authored config. Nothing here registers
    accounts, guesses credentials, or touches identities the operator has not declared as theirs.
  * Every request goes through ReconEngine.fetch_endpoint, so it is scope-gated, deny-listed,
    DNS-pinned and charged to the request budget like any other probe.
  * `accounts_owned_by_operator` must be true in the config or the probe refuses to run.
"""

import json
import random
import re
import string
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from engine.triage_evaluator import CandidateFinding


class ProbeRefused(Exception):
    pass


def _sub(template: str, values: Dict[str, str]) -> str:
    out = template
    for key, val in values.items():
        out = out.replace("{" + key + "}", str(val))
    if "{" in out and re.search(r"\{[a-z_]+\}", out):
        raise ProbeRefused(f"unresolved placeholder in template: {out}")
    return out


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


class AuthzProbe:
    def __init__(self, recon):
        self.recon = recon

    def _extract(self, res: Dict[str, Any], spec: Dict[str, Any], values: Dict[str, str]) -> Optional[str]:
        body = res.get("body") or ""
        if "regex" in spec:
            m = re.search(_sub(spec["regex"], values), body)
            if not m:
                return None
            return m.group("value") if "value" in m.groupdict() else (m.group(1) if m.groups() else None)
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return None
        return _dig(parsed, spec["json_path"])

    def _request(
        self,
        base_url: str,
        spec: Dict[str, Any],
        headers: Dict[str, str],
        values: Dict[str, str],
        budget_tracker,
        is_lab: bool,
        program: Optional[str] = None
    ) -> Dict[str, Any]:
        url = urllib.parse.urljoin(base_url + "/", _sub(spec["path"], values))
        body = _sub(spec["body"], values) if spec.get("body") else ""
        return self.recon.fetch_endpoint(
            url,
            method=spec.get("method", "GET").upper(),
            headers=headers,
            data=body or None,
            budget_tracker=budget_tracker,
            is_lab=is_lab,
            program=program
        )

    def authenticate(self, base_url: str, account: Dict[str, Any], budget_tracker, is_lab: bool, program: Optional[str] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Returns (request headers, extracted values) for one operator-declared account."""
        values: Dict[str, str] = dict(account.get("values", {}))
        headers: Dict[str, str] = {}
        login = account.get("login")
        if not login:
            if account.get("header"):
                raise ProbeRefused(
                    f"{account.get('label', '?')} declares a header template but no login step: "
                    "static credentials in a probe config are not accepted. Declare login + extract "
                    "so the session is obtained at runtime."
                )
            raise ProbeRefused(
                f"{account.get('label', '?')} has no login step; the probe would run anonymously and "
                "could not distinguish two tenant sessions"
            )
        res = self._request(base_url, login, {}, values, budget_tracker, is_lab, program)
        token = self._extract(res, login.get("extract", {}), values)
        if not token:
            raise ProbeRefused(
                f"login for {account.get('label', '?')} returned HTTP {res.get('status')} "
                f"and no token via the configured extractor; cannot continue without a session. "
                f"Transport/scope note: {res.get('error')}"
            )
        values["token"] = token
        headers = {k: _sub(v, values) for k, v in account.get("header", {}).items()}
        if not headers:
            raise ProbeRefused(
                f"{account.get('label', '?')} obtained a token but declares no header to carry it; "
                "the session would never be sent"
            )
        for step in account.get("derive", []):
            res = self._request(base_url, step["request"], headers, values, budget_tracker, is_lab, program)
            got = self._extract(res, step.get("extract", {}), values)
            if got is None:
                raise ProbeRefused(f"could not derive value '{step['as']}' from HTTP {res.get('status')}")
            values[step["as"]] = got
        return headers, values

    def run(self, base_url: str, config: Dict[str, Any], budget_tracker=None, is_lab: bool = False) -> List[CandidateFinding]:
        if not config.get("accounts_owned_by_operator"):
            raise ProbeRefused(
                "probe config lacks accounts_owned_by_operator: true; refusing to exercise another "
                "identity's resources"
            )
        attacker_cfg = config.get("attacker") or {}
        victim_cfg = config.get("victim") or {}
        if not attacker_cfg or not victim_cfg:
            raise ProbeRefused("probe config needs both attacker and victim account blocks")

        program_name = config.get("program")
        atk_headers, atk_vals = self.authenticate(base_url, attacker_cfg, budget_tracker, is_lab, program_name)
        vic_headers, vic_vals = self.authenticate(base_url, victim_cfg, budget_tracker, is_lab, program_name)

        marker = config.get("marker") or {}
        if marker.get("mode") == "plant":
            token = "QA" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
            plant = dict(vic_vals)
            plant["marker"] = token
            res = self._request(base_url, marker["request"], vic_headers, plant, budget_tracker, is_lab, program_name)
            if res.get("status") not in (200, 201, 204):
                raise ProbeRefused(f"could not plant the marker value (HTTP {res.get('status')})")
            if marker.get("as") and marker.get("extract"):
                got = self._extract(res, marker["extract"], plant)
                if got is None:
                    raise ProbeRefused(f"planted but could not extract '{marker['as']}' from HTTP {res.get('status')}")
                vic_vals[marker["as"]] = got
            victim_marker = token
        elif marker.get("value"):
            victim_marker = str(marker["value"])
        else:
            raise ProbeRefused("probe config needs marker.mode=plant or a literal marker.value")

        shared = dict(atk_vals)
        shared.update(vic_vals)
        shared["marker"] = victim_marker

        control = self._request(base_url, config["attacker_control_request"], atk_headers, shared, budget_tracker, is_lab, program_name)
        attack = self._request(base_url, config["cross_tenant_request"], atk_headers, shared, budget_tracker, is_lab, program_name)
        if control.get("status") is None or attack.get("status") is None:
            raise ProbeRefused("control or attack request failed to complete; no evidence captured")

        attack_url = urllib.parse.urljoin(base_url + "/", _sub(config["cross_tenant_request"]["path"], shared))
        control_url = urllib.parse.urljoin(base_url + "/", _sub(config["attacker_control_request"]["path"], shared))
        method = config["cross_tenant_request"].get("method", "GET").upper()

        diff_observed = victim_marker in (attack.get("body") or "") and victim_marker not in (control.get("body") or "")
        proof = (
            f"Marker {victim_marker!r} planted by the victim account appears in the attacker's "
            f"{method} {attack_url} response (HTTP {attack.get('status')}) and is absent from the "
            f"attacker's own control {control_url} response (HTTP {control.get('status')})."
        ) if diff_observed else (
            f"No cross-tenant diff observed: marker {victim_marker!r} "
            f"{'present' if victim_marker in (attack.get('body') or '') else 'absent'} in the attacker's "
            f"response and "
            f"{'present' if victim_marker in (control.get('body') or '') else 'absent'} in the control response."
        )

        base = config.get("program", "local_lab")
        host = urllib.parse.urlparse(attack_url).netloc.split(":")[0]
        return [CandidateFinding(
            title=config.get("title", f"Cross-tenant object read on {attack_url}"),
            program=base,
            target_host=host,
            request_method=method,
            request_url=attack_url,
            request_body=_sub(config["cross_tenant_request"].get("body", ""), shared) or "",
            response_status=attack.get("status"),
            response_headers=attack.get("headers", {}),
            response_body=attack.get("body", ""),
            second_account_tested=True,
            attacker_controlled_proof=proof,
            is_lab=is_lab,
            victim_marker=victim_marker,
            baseline_body=control.get("body", ""),
            notes=f"AuthzProbe '{config.get('name')}' captured control HTTP {control.get('status')} / attack HTTP {attack.get('status')}"
        )]
