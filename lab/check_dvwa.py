import urllib.request

for p in ['/', '/index.php', '/login.php', '/dvwa/login.php', '/setup.php']:
    url = f"http://localhost:8080{p}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            body = r.read().decode("utf-8", errors="replace")[:120]
            print(f"{p}: HTTP {r.getcode()} | Body: {repr(body)}")
    except Exception as e:
        print(f"{p}: {e}")
