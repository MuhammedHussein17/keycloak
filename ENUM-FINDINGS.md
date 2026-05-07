# Keycloak 26.0.8 — ECP Client/Realm Enumeration

Tested: 2026-05-07 against `keycloak-dev` (Keycloak 26.0.8)  
Script: `ecp_enum.py`  
Technique: SAML ECP `faultstring` oracle documented in `ORACLE-FINDINGS.md`

---

## Task 1 — Built-in client enumeration map

Endpoint: `POST /realms/master/protocol/saml`  
All probes are unauthenticated.

| Client ID | faultstring | Classification | What it reveals |
|---|---|---|---|
| `http://localhost:8080/realms/master` | `invalidRequestMessage` | NOT_FOUND | Not a registered client issuer |
| `account` | `Wrong client protocol.` | FOUND_OIDC | OIDC client, standard+implicit flows |
| `account-console` | `Wrong client protocol.` | FOUND_OIDC | OIDC client, standard flow only |
| `security-admin-console` | `Wrong client protocol.` | FOUND_OIDC | OIDC client, standard flow only |
| `broker` | `bearerOnlyMessage` | FOUND_BEARER_ONLY | OIDC bearer-only (API resource, not a login client) |
| `admin-cli` | `standardFlowDisabledMessage` | FOUND_STANDARD_FLOW_OFF | OIDC direct-grant client; no standard/browser flow |
| `master-realm` | `bearerOnlyMessage` | FOUND_BEARER_ONLY | Master realm's admin resource server (bearer-only) |
| `realm-management` | `invalidRequestMessage` | NOT_FOUND | Per-realm mgmt client; absent in master (named `master-realm` there) |

### Notes on ambiguous classifications

**`FOUND_BEARER_ONLY`** — SAML clients cannot be bearer-only in the Keycloak data model; all bearer-only results are OIDC clients.

**`FOUND_STANDARD_FLOW_OFF`** — applies to both OIDC and SAML clients with standard flow disabled. Requires a follow-up probe to distinguish: send a `SAMLResponse` instead of an `AuthnRequest` to the same issuer; the resulting `faultstring` differs for OIDC vs SAML clients.

**`FOUND_SAML_SIG_REQUIRED`** (`invalidRequesterMessage`) — always a SAML client. The client's `Require Client Signature` setting is `true`; our unsigned probe triggers this path in `handleSamlRequest()`.

**`FOUND_SAML_ECP_DISABLED`** — SAML client exists but `Allow ECP Flow` is off. The detail element of the SOAP fault contains the literal string `"Client is not allowed to use ECP profile."` (`SamlEcpProfileService.loginRequest:99`).

**`FOUND_AUTH_STARTED`** — SAML client fully configured with ECP enabled. The ECP authentication flow was started and Keycloak returned a non-500 response (redirect or auth challenge).

### `checkClientValidity` evaluation order

The order of checks in `SamlService.BindingProtocol.checkClientValidity()` determines which faultstring wins when a client has multiple flags set:

```
1. client == null           → invalidRequestMessage       (NOT_FOUND)
2. !client.isEnabled()      → loginRequesterNotEnabled    (FOUND_DISABLED)
3. client.isBearerOnly()    → bearerOnlyMessage           (FOUND_BEARER_ONLY)
4. !standardFlowEnabled()   → standardFlowDisabled        (FOUND_STANDARD_FLOW_OFF)
5. wrong protocol (≠ saml)  → Wrong client protocol.      (FOUND_OIDC)
```

A disabled bearer-only client returns `loginRequesterNotEnabledMessage`, not
`bearerOnlyMessage`. An enumeration script must account for this ordering when
drawing conclusions about client type.

---

## Task 2 — Enumeration script: `ecp_enum.py`

### Usage

```bash
# Built-in wordlist against master realm (default)
py ecp_enum.py

# Different realm
py ecp_enum.py --realm myrealm

# External host with custom wordlist, 20 threads, show all results
py ecp_enum.py --host https://kc.example.com --realm prod \
               --wordlist clients.txt --workers 20 --all
```

### Live run — built-in wordlist (15 entries) against `keycloak-dev`

```
========================================================================
  Keycloak SAML ECP Client Enumerator
  Endpoint : http://localhost:8080/realms/master/protocol/saml
  Wordlist : 15 entries   Workers: 10
========================================================================
[+] Realm 'master' exists.

  [OIDC]      account                              (  15ms)
  [OIDC]      account-console                      (  16ms)
  [OIDC]      security-admin-console               (  17ms)
  [BEARER]    broker                               (  28ms)
  [STD-OFF]   admin-cli                            (  28ms)
  [BEARER]    master-realm                         (  35ms)

========================================================================
  FOUND: 6 of 15 probed

  Client ID                            Classification              What it reveals
  -----------------------------------  --------------------------  ----------------------------------------
  account                              FOUND_OIDC                  OIDC client registered with this ID
  account-console                      FOUND_OIDC                  OIDC client registered with this ID
  security-admin-console               FOUND_OIDC                  OIDC client registered with this ID
  broker                               FOUND_BEARER_ONLY           OIDC bearer-only client (API resource server)
  admin-cli                            FOUND_STANDARD_FLOW_OFF     client registered, standard flow disabled
  master-realm                         FOUND_BEARER_ONLY           OIDC bearer-only client (API resource server)
```

All 6 are default Keycloak built-in clients, confirmed without any authentication.

### Performance characteristics

- Baseline per-probe: 8–50 ms on localhost
- Threading: `ThreadPoolExecutor` with configurable workers; 10 concurrent probes
  finish a 1000-entry wordlist in ~5–10 seconds on LAN
- No authentication, sessions, or state required

---

## Task 3 — Realm enumeration

### ECP endpoint behaviour

| Realm path | HTTP | Content-Type | Body |
|---|---|---|---|
| `/realms/master/protocol/saml` | 500 | `text/xml` | SOAP fault — realm resolved, SAML processing ran |
| `/realms/nonexistent/protocol/saml` | 404 | `application/json` | `{"error":"Realm does not exist"}` |
| `/realms/MASTER/protocol/saml` | 404 | `application/json` | `{"error":"Realm does not exist"}` |

**Realm names are case-sensitive.** `master` and `MASTER` are treated as different
realm identifiers. The JAX-RS path resolver returns 404 for the wrong case before
the SAML service is reached.

### Simpler realm-existence probe (no SAML required)

The standard OIDC discovery endpoint leaks realm existence with no parsing needed:

```
GET /realms/{realm}
```

| Realm | HTTP | Body excerpt |
|---|---|---|
| `master` | 200 | `{"realm":"master","public_key":"MIIBIjANBgkqhkiG9w0BA..."}` |
| `nonexistent` | 404 | `{"error":"Realm does not exist"}` |
| `MASTER` | 404 | `{"error":"Realm does not exist"}` |

The `GET /realms/{realm}` response for an existing realm returns:
- The realm's RSA public key
- The realm's token service URL, JWKS URI, OIDC endpoint
- Zero authentication required

This is a documented Keycloak behaviour (OIDC discovery), not a finding — but it
means realm enumeration is always available independently of SAML being configured.

### Two-phase enumeration workflow

Given an unknown Keycloak installation:

1. **Enumerate realms** — `GET /realms/{realm}` with a realm wordlist. 200 = realm
   exists. Low cost: ~5ms per probe, no body required.
2. **Enumerate clients per realm** — `ecp_enum.py --realm {realm}`. Requires SAML
   protocol to be enabled on the realm (if SAML is disabled, the endpoint returns
   404/405 rather than a SOAP fault).

### Can the ECP oracle fingerprint Keycloak version?

Yes, with high confidence. Three properties together are unique to Keycloak:

1. **`<faultcode>error</faultcode>`** — standard SOAP faults use
   `SOAP-ENV:Client` or `SOAP-ENV:Server`; Keycloak hardcodes the literal
   string `"error"` via `Soap.createFault().code("error")` (Soap.java:360).

2. **`<faultstring>` = message bundle key** — other SAML IdPs (Shibboleth,
   SimpleSAMLphp, AD FS) return localized human-readable strings or SAML
   status URIs. Keycloak returns internal Java constant values
   (`"invalidRequestMessage"`, `"bearerOnlyMessage"`, etc.) because the ECP
   `error()` override passes the key directly to `setFaultString()` without
   locale resolution.

3. **JSON `{"error":"unknown_error","error_description":"For more on this error
   consult the server log."}` for parse failures** — this is
   `KeycloakErrorHandler`'s `OAuth2ErrorRepresentation` format, specific to
   Keycloak's Quarkus-based error handling.

The `faultstring` key strings have been stable since Keycloak 4.x (pre-Quarkus).
A single unauthenticated probe returning `invalidRequestMessage` or
`bearerOnlyMessage` identifies the software as Keycloak without any version
disambiguation. Distinguishing between 21.x and 26.x would require version-specific
endpoint or response-body differences.

---

## Impact assessment

| Finding | Impact | Auth required | Notes |
|---|---|---|---|
| Realm enumeration | Low | None | Also trivially available via `GET /realms/{name}` |
| Client-ID enumeration | Medium | None | Reveals internal architecture, OIDC vs SAML split, disabled clients |
| `Wrong client protocol.` oracle | Medium | None | Confirms OIDC client IDs — aids targeting of OIDC-specific attacks |
| `FOUND_SAML_ECP_DISABLED` | Low | None | Confirms SAML clients that aren't ECP-enabled |
| `FOUND_SAML_SIG_REQUIRED` | Low-Medium | None | Confirms SAML client exists; also reveals signature is required (narrows forging surface) |
| `standardFlowDisabledMessage` | Low | None | Confirms service-account or direct-grant clients; narrows auth-flow attack surface |
| Software fingerprint | Low | None | Confirms Keycloak, version range inference only |

None of these represent authentication bypass or privilege escalation. The primary
value to an attacker is reconnaissance: confirming which client IDs exist before
attempting OAuth/OIDC redirect_uri attacks, SAML signature forging, or client-
credential stuffing.

---

*Findings documented 2026-05-07 against Keycloak 26.0.8.*
