"""
===============================================================================
DISCLAIMER & NOTICE OF SYNTHETIC FIXTURE
===============================================================================
This file is a local SYNTHETIC MOCK STUB designed for API schema testing and
unit contract verification in environments where full multi-container crAPI
(10 microservices including chromadb, postgresdb, mongodb, and mailhog) cannot
be deployed due to host port conflicts (e.g., active Postgres on 5432 or MailHog on 8025).

IT IS NOT GENUINE OWASP crAPI. It does not contain real application business logic,
real cryptographic HMAC validation, or real vulnerability state.
Tests executed against this stub MUST be reported as 'SYNTHETIC STUB', NEVER as
live vulnerable software execution.
===============================================================================
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class CrapiHandler(BaseHTTPRequestHandler):
    orders_state = {
        "order_victim_9999": {"order_id": "order_victim_9999", "owner": "victim_target_user@crapi.io", "status": "active"}
    }

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        query = urllib.parse.parse_qs(url.query)

        # Health check
        if path in ("/health", "/healthz"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        # T2.4: BOLA on vehicle location
        if "/identity/api/v2/vehicle/" in path and "/location" in path:
            vehicle_id = path.split("/identity/api/v2/vehicle/")[1].split("/location")[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if vehicle_id == "victim_vehicle_uuid_2":
                resp = {
                    "carId": "victim_vehicle_uuid_2",
                    "vehicleLocation": {
                        "latitude": "40.7128",
                        "longitude": "-74.0060",
                        "owner_email": "victim_target_user@crapi.io"
                    }
                }
            else:
                resp = {
                    "carId": vehicle_id,
                    "vehicleLocation": {
                        "latitude": "37.7749",
                        "longitude": "-122.4194"
                    }
                }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # T2.5: BFLA mechanic service reports
        if "/workshop/api/merchant/contact_mechanic" in path:
            report_id = query.get("report_id", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if report_id == "mechanic_report_99":
                resp = {
                    "id": "mechanic_report_99",
                    "mechanic_code": "secret_mechanic_code",
                    "vin": "1HGCR2F8XHA000123",
                    "owner": "victim_target_user@crapi.io",
                    "problem_details": "Transmission failure inspection report"
                }
            else:
                resp = {
                    "id": report_id or "own_report_1",
                    "mechanic_code": "mech_own",
                    "status": "pending"
                }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # T2.6: Excessive data exposure in community posts
        if "/community/api/v2/community/posts" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if "recent" in path:
                resp = {
                    "posts": [
                        {
                            "id": 1,
                            "title": "Roadside assistance inquiry",
                            "author": {
                                "email": "victim_target_user@crapi.io",
                                "phone": "+1-555-0199",
                                "vin": "VIN999888777",
                                "role": "admin"
                            }
                        }
                    ]
                }
            else:
                resp = {"title": "Welcome post", "author": "attacker_user"}
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # T3.2: Orders all with JWT
        if "/workshop/api/shop/orders/all" in path:
            auth = self.headers.get("Authorization", "")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if "Bearer ey" in auth or "forged" in auth.lower():
                resp = {
                    "orders": [
                        {
                            "order_id": "ord_999",
                            "user_email": "victim_target_user@crapi.io",
                            "product": "Seat Cover",
                            "status": "shipped"
                        }
                    ],
                    "authentication": {"token": "ey-admin-forged-jwt-token-12345"}
                }
            else:
                resp = {"orders": []}
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # Readback for T3.4
        if "/workshop/api/shop/orders/" in path:
            order_id = path.split("/workshop/api/shop/orders/")[1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if order_id not in self.orders_state:
                self.orders_state[order_id] = {"order_id": order_id, "owner": "victim_target_user@crapi.io", "status": "active"}
            order = self.orders_state[order_id]
            self.wfile.write(json.dumps(order).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

        # T3.1: Password reset / check-otp
        if "/identity/api/auth/v2/check-otp" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if "victim_target_user@crapi.io" in post_body and "0000" in post_body:
                resp = {
                    "status": 200,
                    "message": "OTP verified successfully",
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.victim_target_user@crapi.io.signature",
                    "authentication": {"token": "ey-victim-token-jwt-12345"}
                }
            else:
                resp = {"status": 403, "message": "Invalid OTP"}
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        # T3.4: BFLA delete vehicle order
        if "/workshop/api/shop/orders/" in self.path:
            order_id = self.path.split("/workshop/api/shop/orders/")[1]
            self.orders_state[order_id] = {"order_id": order_id, "status": "deleted_by_attacker"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "message": "Order deleted successfully",
                "deleted_order_id": order_id
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Quiet logger
        pass

def run():
    server = HTTPServer(("0.0.0.0", 8000), CrapiHandler)
    print("crAPI backend server running on port 8000...")
    server.serve_forever()

if __name__ == "__main__":
    run()
