"""
Scope-Guarded Recon & Attack Surface Mapper.
Discovers endpoints, forms, parameters, and technologies while adhering strictly
to scope limits and avoiding mass scanning or intrusive probing.
"""

import re
import json
import random
import string
import urllib.request
import urllib.parse
from html.parser import HTMLParser
from typing import Dict, Any, List, Set, Optional

from core.scope_guard import gate_destination, pinned_dns, ScopeGuard


class FormParser(HTMLParser):
    # Attributes that carry a same-origin URL. SPAs ship almost all of their surface
    # through script/link src, never through <a href>.
    URL_ATTRS = {
        "a": ("href",),
        "link": ("href",),
        "script": ("src",),
        "form": ("action",),
        "iframe": ("src",),
        "frame": ("src",),
        "img": ("src",),
        "source": ("src",),
        "area": ("href",),
        "base": ("href",),
        "object": ("data",),
        "video": ("src", "poster"),
        "audio": ("src",),
    }

    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": []
            }
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", "")
            })
        for attr in self.URL_ATTRS.get(tag, ()):
            val = (attrs_dict.get(attr) or "").strip()
            if val and not val.startswith(("#", "javascript:", "mailto:", "data:")):
                self.links.add(val)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class ReconEngine:
    # Static bundles / assets are not routable application surface.
    NON_ROUTE_EXT = (
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".pdf", ".zip", ".txt", ".xml"
    )

    def __init__(self, user_agent: str = "AntigravityBugHunter/1.0", scope_guard: Optional[Any] = None):
        self.user_agent = user_agent
        self.scope_guard = scope_guard or ScopeGuard()

    def fetch_endpoint(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        budget_tracker: Optional[Any] = None,
        is_lab: bool = False,
        program: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetches a single endpoint cleanly and extracts headers, body, and status with budget enforcement."""
        if budget_tracker is not None:
            if not budget_tracker.acquire(1):
                return {
                    "url": url,
                    "status": None,
                    "headers": {},
                    "body": "",
                    "error": "BUDGET_EXHAUSTED: Request budget exceeded. Strict blast-radius limit enforced."
                }

        # Provenance before resolution: a live destination must be admitted by the operator's
        # attestation, and this check is a pure string lookup that emits zero DNS.
        if not is_lab:
            if not program:
                return {
                    "url": url,
                    "status": None,
                    "headers": {},
                    "body": "",
                    "error": "PROVENANCE_REQUIRED: live (non-lab) fetch needs an attested program name; refusing before resolution"
                }
            admitted, why = self.scope_guard.verify_target(url, program, is_lab=False)
            if not admitted:
                return {
                    "url": url,
                    "status": None,
                    "headers": {},
                    "body": "",
                    "error": f"PROVENANCE_BLOCKED: {why}"
                }

        # Egress gate: validate the destination and pin the addresses that were validated,
        # so the transport cannot resolve to a different IP after the check.
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        gated = gate_destination(parsed.netloc, is_lab=is_lab)
        if gated["denied"]:
            return {
                "url": url,
                "status": None,
                "headers": {},
                "body": "",
                "error": f"EGRESS_BLOCKED: {gated['reason']}"
            }

        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        payload_bytes = data.encode("utf-8") if data else None
        req = urllib.request.Request(url, data=payload_bytes, headers=req_headers, method=method.upper())
        try:
            with pinned_dns(gated["host"], gated["ips"]):
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.getcode()
                    h = dict(resp.headers)
                    body = resp.read().decode("utf-8", errors="replace")
            return {
                "url": url,
                "status": status,
                "headers": h,
                "body": body,
                "error": None
            }
        except urllib.error.HTTPError as e:
            return {
                "url": url,
                "status": e.code,
                "headers": dict(e.headers),
                "body": e.read().decode("utf-8", errors="replace"),
                "error": str(e)
            }
        except Exception as e:
            return {
                "url": url,
                "status": None,
                "headers": {},
                "body": "",
                "error": str(e)
            }

    def extract_path_candidates(self, text: str) -> Set[str]:
        """Pulls quoted / template-literal path strings out of HTML, inline script and JS bundles."""
        found: Set[str] = set()
        for m in re.findall(
            r"""['"`]/?([A-Za-z0-9_\-{}.:%$]{2,}(?:/[A-Za-z0-9_\-{}.:%$\[\]]+){1,8})['"`]""",
            text
        ):
            if m.lower().endswith(self.NON_ROUTE_EXT):
                continue
            found.add("/" + m.lstrip("/"))
        for m in re.findall(r"""['"`](/[A-Za-z0-9_\-./{}:%$]{2,})['"`]""", text):
            if not m.lower().endswith(self.NON_ROUTE_EXT):
                found.add(m)
        return found

    def detect_catch_all(self, base_url: str, budget_tracker: Optional[Any] = None, is_lab: bool = False, program: Optional[str] = None) -> Optional[int]:
        """Requests a path that cannot exist to learn the SPA's fallback body length, if any."""
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        parsed = urllib.parse.urlparse(base_url)
        probe = f"{parsed.scheme}://{parsed.netloc}/_qa_catchall_{token}"
        res = self.fetch_endpoint(probe, budget_tracker=budget_tracker, is_lab=is_lab, program=program)
        if res["status"] == 200:
            return len(res["body"])
        return None

    def validate_candidates(
        self,
        candidates: List[str],
        catch_all_length: Optional[int],
        max_validations: int,
        budget_tracker: Optional[Any] = None,
        is_lab: bool = False,
        program: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Confirms a candidate by requesting it once. Unconfirmed strings stay leads, not surface."""
        confirmed: List[Dict[str, Any]] = []
        for url in candidates[:max_validations]:
            res = self.fetch_endpoint(url, budget_tracker=budget_tracker, is_lab=is_lab, program=program)
            status = res.get("status")
            if status is None or status == 404:
                continue
            body_len = len(res.get("body") or "")
            if catch_all_length and body_len == catch_all_length:
                continue
            confirmed.append({"url": url, "status": status, "length": body_len})
        return confirmed

    def map_surface(self, base_url: str, depth: int = 1, budget_tracker: Optional[Any] = None, is_lab: bool = False, program: Optional[str] = None) -> Dict[str, Any]:
        """Maps attack surface of the target endpoint without unconstrained crawling."""
        parsed_base = urllib.parse.urlparse(base_url)
        target_host = parsed_base.netloc

        res = self.fetch_endpoint(base_url, budget_tracker=budget_tracker, is_lab=is_lab, program=program)
        if res["status"] is None:
            return {"error": f"Failed to connect to {base_url}: {res['error']}"}

        # Parse forms and links
        parser = FormParser()
        parser.feed(res["body"][:100000])

        discovered_endpoints: Set[str] = set()
        static_assets: Set[str] = set()
        for link in parser.links:
            resolved = urllib.parse.urljoin(base_url, link)
            p = urllib.parse.urlparse(resolved)
            if p.netloc != target_host:
                continue
            bare = resolved.lower().split("?")[0]
            if bare.endswith((".js", ".css", ".map")):
                static_assets.add(resolved)
            elif not bare.endswith(self.NON_ROUTE_EXT):
                discovered_endpoints.add(resolved)

        # Reserve most of the budget for fuzzing and templated scanning; recon only gets a slice.
        if budget_tracker is not None:
            recon_ceiling = max(3, int(budget_tracker.max_budget * 0.35))
        else:
            recon_ceiling = None

        def recon_spend_left() -> int:
            if recon_ceiling is None or budget_tracker is None:
                return 999
            return max(0, recon_ceiling - budget_tracker.current_count)

        candidates: Set[str] = {
            urllib.parse.urljoin(base_url, c)
            for c in self.extract_path_candidates(res["body"])
        }

        # Second pass: pull route strings out of same-origin JS bundles, the only place
        # an SPA declares its API surface.
        js_analyzed: List[str] = []
        for asset in sorted(static_assets):
            if recon_spend_left() < 2:
                break
            js_res = self.fetch_endpoint(asset, budget_tracker=budget_tracker, is_lab=is_lab, program=program)
            if js_res["status"] == 200 and js_res["body"]:
                js_analyzed.append(asset)
                candidates |= {
                    urllib.parse.urljoin(base_url, c)
                    for c in self.extract_path_candidates(js_res["body"][:400000])
                }

        candidates = {
            c for c in candidates
            if urllib.parse.urlparse(c).netloc == target_host
            and not c.lower().split("?")[0].endswith(self.NON_ROUTE_EXT)
            and urllib.parse.urlparse(c).path not in ("", "/")
        }

        catch_all_length = None
        if recon_spend_left() >= 2:
            catch_all_length = self.detect_catch_all(
                base_url, budget_tracker=budget_tracker, is_lab=is_lab, program=program
            )

        to_validate = sorted(candidates - discovered_endpoints - static_assets)
        validated = self.validate_candidates(
            to_validate,
            catch_all_length,
            max(0, min(len(to_validate), recon_spend_left() - 1)),
            budget_tracker=budget_tracker,
            is_lab=is_lab,
            program=program
        )
        for v in validated:
            discovered_endpoints.add(v["url"])

        api_routes = sorted(
            c for c in candidates | discovered_endpoints
            if re.match(r"^/(api|rest|v[0-9]+|graphql|actuator|swagger|api-docs)(/|$)",
                        urllib.parse.urlparse(c).path)
        )

        # Technology fingerprinting from headers
        headers = res["headers"]
        tech = []
        if "server" in headers:
            tech.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            tech.append(f"X-Powered-By: {headers['x-powered-by']}")
        if "set-cookie" in headers:
            cookies = headers["set-cookie"]
            if "PHPSESSID" in cookies:
                tech.append("PHP Session Management")
            elif "JSESSIONID" in cookies:
                tech.append("Java/Servlet Session Management")
            elif "connect.sid" in cookies or "jwt" in cookies.lower():
                tech.append("Node.js / Express Session")

        # Security Headers check
        security_headers = {
            "Content-Security-Policy": "content-security-policy" in headers,
            "Strict-Transport-Security": "strict-transport-security" in headers,
            "X-Frame-Options": "x-frame-options" in headers,
            "X-Content-Type-Options": "x-content-type-options" in headers
        }

        validated_urls = [v["url"] for v in validated]
        validated_set = set(validated_urls)
        # Confirmed-responsive routes first: downstream probes get a bounded target slice.
        ordered_endpoints = validated_urls + sorted(discovered_endpoints - validated_set)

        return {
            "target": base_url,
            "host": target_host,
            "status": res["status"],
            "headers": headers,
            "body": res["body"][:4000],
            "technologies": tech,
            "security_headers": security_headers,
            "forms": parser.forms,
            "endpoints": ordered_endpoints[:40],
            "api_routes": api_routes[:20],
            "discovery_metrics": {
                "html_links": len(discovered_endpoints) - len(validated_urls),
                "static_assets_seen": len(static_assets),
                "js_bundles_analyzed": len(js_analyzed),
                "path_candidates": len(candidates | discovered_endpoints),
                "candidates_validated": len(to_validate),
                "validated_responsive": len(validated_urls),
                "catch_all_length": catch_all_length,
                "requests_used_by_recon": budget_tracker.current_count if budget_tracker is not None else None
            }
        }
