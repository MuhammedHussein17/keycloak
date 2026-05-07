# Keycloak 26.0.8 — SAML ECP Response Oracle

Endpoint: `POST /realms/{realm}/protocol/saml`  
Handler chain: `SamlService.soapBinding()` → `SamlEcpProfileService.authenticate()`  
Tested: 2026-05-07 against `keycloak-dev` (Keycloak 26.0.8, OpenJDK 21.0.6, saaj-impl 2.0.1)

---

## Finding A — Response format oracle

An unauthenticated attacker can determine whether an arbitrary POST body was
**accepted at SOAP parse level** or rejected, purely from the HTTP
`Content-Type` response header.

### Source: exception boundary in `authenticate(InputStream)` (SamlEcpProfileService.java:66–67)

```
SamlService.soapBinding(InputStream)
  └─ SamlEcpProfileService.authenticate(InputStream)           ← NO try/catch here
       └─ Soap.extractSoapMessage(InputStream)                  ← Soap.java:99–107
            ├─ MessageFactory.createMessage(null, inputStream)  ← SAAJ parse
            └─ extractSoapMessage(SOAPMessage)                  ← body extraction
                  Any exception → RuntimeException("Error creating fault message.", e)
                  propagates UNCAUGHT → KeycloakErrorHandler → JSON

  └─ SamlEcpProfileService.authenticate(Document)              ← line 70
       try {
         PostBindingProtocol.execute(...)
           │ Any SAML-logic error calls error() override:
           │   Soap.createFault().code("error").reason(message).build() → SOAP fault
           │
           │ Unexpected exception rethrown to outer catch at line 108
           └─ "Some error occurred while processing the AuthnRequest." → SOAP fault
       } catch (Exception e) → SOAP fault
```

The `authenticate(InputStream)` method has **no `try/catch`**. Any exception from
`Soap.extractSoapMessage()` propagates directly to Quarkus/RESTEasy's
`KeycloakErrorHandler`, which inspects the `Accept` header of the request.
Because SOAP clients do not send `Accept: text/html`, `isHtmlRequest()` returns
false and the handler always produces JSON (`application/json`).

### Observable states

| # | Input | HTTP | Content-Type | Body | Elapsed |
|---|---|---|---|---|---|
| 1 | Empty body | 500 | `application/json` | `{"error":"unknown_error",...}` | ~11 ms |
| 2 | Valid XML, not SOAP | 500 | `application/json` | `{"error":"unknown_error",...}` | ~8 ms |
| 3 | Valid SOAP, empty `<Body>` | 500 | `application/json` | `{"error":"unknown_error",...}` | ~9 ms |
| 4 | XML with DOCTYPE (any) | 500 | `application/json` | `{"error":"unknown_error",...}` | ~10 ms |
| 5 | Valid SOAP, non-SAML body | 500 | `text/xml` | `faultstring>invalidRequestMessage` | ~11 ms |
| 6 | Valid SOAP + SAML, unregistered issuer | 500 | `text/xml` | `faultstring>invalidRequestMessage` | ~13 ms |
| 7 | Valid SOAP + SAML, OIDC client issuer | 500 | `text/xml` | `faultstring>Wrong client protocol.` | ~13 ms |
| 8 | Valid SOAP + SAML, known SAML client | depends | `text/xml` | SOAP fault or 200 SOAP response | ~16 ms+ |

> Items 3, 6, 7 **runtime-confirmed** against Keycloak 26.0.8 (tests run 2026-05-07):
> - `account` → `Wrong client protocol.` ✓
> - `security-admin-console` → `Wrong client protocol.` ✓
> - `http://ghost/sp` (unregistered) → `invalidRequestMessage` ✓
> - Empty SOAP body → JSON `unknown_error` ✓

**Why case 3 (empty SOAP body) produces JSON:**  
`extractSoapMessage(SOAPMessage)` calls `getFirstChild(soapBody)` which returns
`null` when the body has no child elements. `document.importNode(null, true)` then
throws a `NullPointerException` which is wrapped in `RuntimeException` inside
`extractSoapMessage(SOAPMessage)`, re-wrapped by `extractSoapMessage(InputStream)`,
and propagates uncaught to `KeycloakErrorHandler` — same path as a parse failure.

**Binary classifier:**
- `Content-Type: application/json` → SAAJ parse failed (not valid SOAP)
- `Content-Type: text/xml` → SAAJ produced a valid SOAP envelope

The classifier requires only one response header — no body parsing needed.

---

## Finding B — SAML SOAP fault faultstring as internal state oracle

When the parser succeeds (SOAP fault path), the `<faultstring>` value leaks
**internal Keycloak message key strings** rather than localized human-readable
text.

### Root cause

`SamlEcpProfileService`'s `error()` override (line 75–77):
```java
protected Response error(KeycloakSession session, AuthenticationSessionModel authSession,
                         Response.Status status, String message, Object... parameters) {
    return Soap.createFault().code("error").reason(message).build();
}
```

`message` is passed as a `Messages.*` Java constant whose value is the message
bundle key string (e.g. `Messages.INVALID_REQUEST = "invalidRequestMessage"`).
The override passes this key string directly to `reason()` — it is never
resolved through the theme's `messages.properties`. This is in contrast to the
regular POST binding `error()`, which calls `ErrorPage.error(session, ...)` and
renders the localised text.

### Full faultstring inventory

| Trigger condition | faultstring value | Source |
|---|---|---|
| Client ID not registered in realm | `invalidRequestMessage` | `checkClientValidity()` → `Messages.INVALID_REQUEST` |
| No SAMLRequest/SAMLResponse/artifact | `invalidRequestMessage` | `basicChecks()` → `Messages.INVALID_REQUEST` |
| SAML parse returns null | `invalidRequestMessage` | `handleSamlRequest()` → `Messages.INVALID_REQUEST` |
| SAML doc type not AuthnRequest/LogoutRequest | `invalidRequestMessage` | `handleSamlRequest()` line 314 |
| Signature verification fails | `invalidRequesterMessage` | `handleSamlRequest()` → `Messages.INVALID_REQUESTER` |
| Client is disabled | `loginRequesterNotEnabledMessage` | `checkClientValidity()` → `Messages.LOGIN_REQUESTER_NOT_ENABLED` |
| Client is bearer-only | `bearerOnlyMessage` | `checkClientValidity()` → `Messages.BEARER_ONLY` |
| Standard flow disabled on client | `standardFlowDisabledMessage` | `checkClientValidity()` → `Messages.STANDARD_FLOW_DISABLED` |
| Client protocol ≠ SAML | `Wrong client protocol.` | `checkClientValidity()` — hardcoded literal |
| Realm disabled | `realmNotEnabledMessage` | `basicChecks()` → `Messages.REALM_NOT_ENABLED` |
| HTTPS required (realm config) | `httpsRequiredMessage` | `basicChecks()` → `Messages.HTTPS_REQUIRED` |
| ECP flow disabled on client | `Some error occurred while processing the AuthnRequest.` | outer `catch(Exception e)`, from `RuntimeException("Client is not allowed to use ECP profile.")` |
| Unexpected exception | `Some error occurred while processing the AuthnRequest.` | outer `catch(Exception e)` |

The first argument to `Soap.createFault().code(...)` is always `"error"`.
Standard SOAP uses `SOAP-ENV:Client` / `SOAP-ENV:Server`; this literal `error`
value is Keycloak-specific.

---

## What the oracle can distinguish (combined)

### 1. SOAP validity probe
Send any non-SOAP body → JSON response confirms the SAML SOAP endpoint is active
on this realm. Compare against a realm that has SAML disabled — the SAML service
would not be bound and JAX-RS would return 404, not 500+JSON.

### 2. Client enumeration via faultstring
Given a `<saml:Issuer>` value:

```
                         SAAJ parse error?
                              │
          ┌──── yes ──────────┘─────── no ────────────┐
          ▼                                             ▼
   JSON unknown_error                          SOAP fault
   (not valid SOAP)                                 │
                                      ┌─────────────┴──────────────┐
                              faultstring =                 faultstring ≠
                         "invalidRequestMessage"       "invalidRequestMessage"
                                  │                          │
                    ┌─────────────┴──────────┐     Client exists; reveals its
               client not found        other parse   specific state:
                or unregistered         failures      - disabled
                                                      - bearer-only
                                                      - standard flow off
                                                      - wrong protocol (OIDC!)
                                                      - ECP not enabled
```

The `Wrong client protocol.` faultstring leaks that a **registered OIDC client**
exists with the given issuer/client-id. This is qualitatively different from
`invalidRequestMessage` (no client found).

### 3. Signature-state oracle
If an issuer IS registered with `requiresClientSignature=true`, sending an
unsigned request produces `invalidRequesterMessage` rather than
`invalidRequestMessage`. This confirms (a) the client exists, (b) it requires
signatures, without needing valid credentials.

### 4. ECP-enablement oracle
An existing SAML client with ECP flow disabled produces
`"Some error occurred while processing the AuthnRequest."` at the SOAP level —
distinguishable from the `invalidRequestMessage` produced when the client does
not exist at all.

---

## Finding C — Version fingerprinting via SOAP fault structure

The SOAP fault body across all SAML-logic errors has this exact structure:

```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
    <SOAP-ENV:Fault>
      <faultcode>error</faultcode>
      <faultstring>invalidRequestMessage</faultstring>
    </SOAP-ENV:Fault>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

Fingerprinting indicators:

| Indicator | Value | Significance |
|---|---|---|
| SOAP prefix | `SOAP-ENV` | saaj-impl default; differs from other SAAJ providers |
| `<faultcode>` | literal `error` (not `SOAP-ENV:Client`) | Keycloak-specific; not a standard SOAP fault code |
| `<faultstring>` | message bundle key (e.g. `invalidRequestMessage`) | Keycloak-specific; other IdPs produce localized strings or SAML status URIs |
| Header element | `<SOAP-ENV:Header/>` | always present and empty — saaj-impl behaviour |
| No `<detail>` element | absent on `error()` path | only present when `SamlEcpProfileService`'s outer catch fires with a detail string |

The `faultstring = message-bundle-key` pattern is unique to this code path in
Keycloak. No standard SOAP or SAML IdP specification calls for raw bundle keys
in SOAP faults. An attacker seeing `invalidRequestMessage` or
`loginRequesterNotEnabledMessage` can identify the software as Keycloak without
any version-specific probing. The key strings themselves have been stable across
Keycloak 4.x–26.x (the `Messages` constants predate Quarkus migration).

The JSON error body `{"error":"unknown_error","error_description":"For more on this error consult the server log."}` is the `OAuth2ErrorRepresentation` format from `KeycloakErrorHandler`. The field names (`error`, `error_description`) and the generic server-error description string are consistent across Keycloak versions.

---

## Recommended mitigations (informational)

| Issue | Fix |
|---|---|
| Format oracle (JSON vs SOAP) | Wrap `Soap.extractSoapMessage(InputStream)` in a try/catch inside `authenticate(InputStream)` and return a SOAP fault rather than letting the exception reach `KeycloakErrorHandler` |
| faultstring leaks key strings | Resolve the message key via the session's theme/locale before calling `Soap.createFault().reason(...)`, or use a generic static string |
| Client-state enumeration | Collapse `loginRequesterNotEnabled`, `bearerOnly`, `standardFlowDisabled`, `Wrong client protocol.`, and `invalidRequest` into a single generic faultstring |

None of these are exploitable for authentication bypass or data exfiltration; the
impact is reconnaissance assistance. The client-enumeration and protocol-oracle
findings require an attacker to already know or guess valid client IDs.
