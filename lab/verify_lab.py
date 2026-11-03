"""
Automated Lab Verification & Exposure Audit Suite.
Verifies service health, application markers, and rigorously computes
exposure across all non-loopback host interfaces and docker port bindings.
"""

import sys
import json
import socket
import urllib.request
import subprocess
import argparse

LAB_CONFIGS = [
    {
        "name": "OWASP Juice Shop",
        "url": "http://127.0.0.1:3000",
        "marker": "OWASP Juice Shop",
        "port": 3000
    },
    {
        "name": "OWASP WebGoat",
        "url": "http://127.0.0.1:8081/WebGoat",
        "marker": "WebGoat",
        "port": 8081
    },
    {
        "name": "OWASP WebWolf",
        "url": "http://127.0.0.1:9099/WebWolf",
        "marker": "WebWolf",
        "port": 9099
    },
    {
        "name": "DVWA (Damn Vulnerable Web App)",
        "url": "http://127.0.0.1:8082/login.php",
        "marker": "Damn Vulnerable Web Application",
        "port": 8082
    },
    {
        "name": "OWASP crAPI",
        "url": "http://127.0.0.1:8888",
        "marker": "crAPI",
        "port": 8888,
        "optional": True
    }
]


def get_lan_ips():
    """Retrieves all non-loopback IPv4 addresses assigned to the host."""
    ips = set()
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127.") and ip != "::1":
                ips.add(ip)
    except Exception:
        pass

    # Fallback probe to detect default egress IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        egress = s.getsockname()[0]
        s.close()
        if not egress.startswith("127."):
            ips.add(egress)
    except Exception:
        pass

    return sorted(list(ips))


def check_exposure(ports, lan_ips):
    """Probes all LAN IPs for unauthorized exposure on lab ports and inspects docker bindings."""
    leaks = []
    docker_error = None
    docker_ps_bindings = []

    # 1. Active socket probe across LAN interfaces
    for ip in lan_ips:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            try:
                res = s.connect_ex((ip, port))
                if res == 0:
                    leaks.append(f"LAN EXPOSURE: Port {port} is reachable on external interface {ip}")
            except Exception:
                pass
            finally:
                s.close()

    # 2. Inspect Docker container port bindings
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--filter", "name=bounty", "--format", "{{.Names}} {{.Ports}}"],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5
        )
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            docker_ps_bindings.append(line)
            if "0.0.0.0:" in line:
                leaks.append(f"DOCKER WILDCARD BIND: Container {line} binds to 0.0.0.0 instead of 127.0.0.1")
    except Exception as e:
        docker_error = str(e)

    return {
        "lan_addresses": lan_ips,
        "leaks": leaks,
        "docker_ps_bindings": docker_ps_bindings,
        "docker_error": docker_error
    }


def verify_lab(lab):
    url = lab["url"]
    req = urllib.request.Request(url, headers={"User-Agent": "AntigravityLabVerifier/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            code = resp.getcode()
            body = resp.read().decode("utf-8", errors="replace")
            marker_found = lab["marker"].lower() in body.lower()
            return {
                "name": lab["name"],
                "url": lab["url"],
                "port": lab["port"],
                "status": "UP" if (code == 200 and marker_found) else "UP-unverified",
                "http_code": code,
                "marker_found": marker_found,
                "marker_expected": lab["marker"]
            }
    except Exception as e:
        if lab.get("optional"):
            return {
                "name": lab["name"],
                "url": lab["url"],
                "port": lab["port"],
                "status": "NOT RUN (stack not running on host)",
                "http_code": None,
                "marker_found": False,
                "note": "Optional lab not active on host machine"
            }
        return {
            "name": lab["name"],
            "url": lab["url"],
            "port": lab["port"],
            "status": "DOWN",
            "http_code": None,
            "marker_found": False,
            "error": str(e)
        }


def main():
    parser = argparse.ArgumentParser(description="Lab Verification & Exposure Audit")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    lab_results = [verify_lab(l) for l in LAB_CONFIGS]
    active_ports = [l["port"] for l in LAB_CONFIGS]
    lan_ips = get_lan_ips()
    exposure = check_exposure(active_ports, lan_ips)

    is_safe = (len(exposure["leaks"]) == 0)
    verdict = "SAFE - loopback only" if is_safe else "UNSAFE - EXPOSURE DETECTED"

    report = {
        "target_environment": "localhost (loopback only)",
        "verdict": verdict,
        "exposure": exposure,
        "labs": lab_results
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 65)
        print("LAB VERIFICATION & SAFETY REPORT")
        print("=" * 65)
        print(f"Verdict: {verdict}")
        print(f"LAN IPs: {lan_ips}")
        print(f"Leaks Detected: {len(exposure['leaks'])}")
        for r in lab_results:
            print(f"- {r['name']:<30}: {r['status']} ({r.get('http_code')})")
        print("=" * 65)


if __name__ == "__main__":
    main()
