"""
Loopback fixture app for verifying the cross-tenant authorization probe.

This is test apparatus, not a finding: it deliberately serves tenant A's object to tenant B
so that AuthzProbe has a real, observable BOLA to capture on 127.0.0.1:8888 (an authorized
lab port). Nothing here reaches the network beyond loopback.

Run:  python lab/authz_fixture_server.py  [port]
"""

import json
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8888


class ExclusiveServer(ThreadingHTTPServer):
    """
    Refuses a shared bind. On Windows SO_REUSEADDR lets two processes claim 127.0.0.1:8888,
    and a negative-control run can then be answered by a stale server with ownership checks
    switched off -- which silently turns a KILL into a VALID-PAYABLE.
    """
    allow_reuse_address = False

    def server_bind(self):
        if sys.platform == "win32":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

USERS = {
    "alice": {"id": 1, "password": "alicepass"},
    "bob": {"id": 2, "password": "bobpass"},
}
TOKENS = {}
# owner_id -> document
DOCUMENTS = {}
# When True the fixture enforces ownership, so a correct probe must find nothing to report.
ENFORCE_OWNERSHIP = False


def _token_for(username: str) -> str:
    tok = f"sess-{username}-{len(TOKENS) + 1}"
    TOKENS[tok] = USERS[username]["id"]
    return tok


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AuthzFixture/1.0"

    def log_message(self, *args):
        pass

    def _send(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _caller_id(self):
        tok = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        return TOKENS.get(tok)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        data = self._body()
        if path == "/login":
            user = USERS.get(str(data.get("username")))
            if not user or user["password"] != data.get("password"):
                return self._send(401, {"error": "invalid credentials"})
            return self._send(200, {"session": {"token": _token_for(data["username"])}})
        if path == "/documents":
            cid = self._caller_id()
            if cid is None:
                return self._send(401, {"error": "no session"})
            doc_id = len(DOCUMENTS) + 1
            DOCUMENTS[doc_id] = {"id": doc_id, "owner_id": cid, "contents": data.get("contents", "")}
            return self._send(201, {"document": {"id": doc_id}})
        return self._send(404, {"error": "unknown route"})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/documents/"):
            # The vulnerability under test: ownership is never checked.
            try:
                doc_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            doc = DOCUMENTS.get(doc_id)
            if not doc:
                return self._send(404, {"error": "not found"})
            cid = self._caller_id()
            if cid is None:
                return self._send(401, {"error": "no session"})
            if ENFORCE_OWNERSHIP and doc["owner_id"] != cid:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"document": doc})
        if path == "/whoami":
            cid = self._caller_id()
            if cid is None:
                return self._send(401, {"error": "no session"})
            return self._send(200, {"user": {"id": cid}})
        return self._send(404, {"error": "unknown route"})


def serve(port: int = PORT):
    httpd = ExclusiveServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print(f"[+] Authz fixture app listening on http://127.0.0.1:{port} (loopback only)")
    ExclusiveServer(("127.0.0.1", port), Handler).serve_forever()
