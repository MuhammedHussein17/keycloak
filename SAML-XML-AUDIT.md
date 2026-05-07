# Keycloak 26.0.8 — SAML XML processing audit

Source: `keycloak/` at commit `a9d523b`. Scope: `saml-core/src/main/java`,
`services/src/main/java/org/keycloak/protocol/saml`,
`services/src/main/java/org/keycloak/broker/saml`.

## Q1 — XML parser inventory and XXE configuration

| # | Parser | File:line | Verdict |
|---|---|---|---|
| 1 | `DocumentBuilderFactory.newInstance()` | `saml-core/src/main/java/org/keycloak/saml/common/util/DocumentUtil.java:408` | ✅ Hardened |
| 2 | `XMLInputFactory.newInstance()` (primary StAX) | `saml-core/src/main/java/org/keycloak/saml/common/util/StaxParserUtil.java:936` | ✅ Hardened |
| 3 | `XMLInputFactory.newInstance()` (filter only) | `saml-core/src/main/java/org/keycloak/saml/common/parsers/AbstractParser.java:73` | ⚠️ Unhardened, but used only to wrap an already-parsed XMLEventReader (no fresh parse) |
| 4 | `TransformerFactory.newInstance()` | `saml-core/src/main/java/org/keycloak/saml/common/util/TransformerUtil.java:116` | ⚠️ Hardened with best-effort try/catch |
| 5 | `SchemaFactory.newInstance()` (StaxParserUtil.validate(InputStream, InputStream)) | `saml-core/src/main/java/org/keycloak/saml/common/util/StaxParserUtil.java:78` | ❌ Unhardened — but only called from tests |
| 6 | `SchemaFactory.newInstance()` (JAXB schemas) | `saml-core/src/main/java/org/keycloak/saml/processing/core/util/JAXBUtil.java:201` | ⚠️ Unhardened, but only loads classpath schemas |
| 7 | `SchemaFactory` + `Validator` (PicketLink validate) | `saml-core/src/main/java/org/keycloak/saml/processing/core/util/JAXPValidationUtil.java:99–113, 144` | ⚠️ Best-effort; opt-in via `picketlink.schema.validate=true` |
| 8 | `XPathFactory.newInstance()` | `services/src/main/java/org/keycloak/broker/saml/mappers/XPathAttributeMapper.java:68` | ✅ Hardened (resolvers throw); document parse uses #1 |
| 9 | `MessageFactory.newInstance()` (SAAJ SOAP) | `services/src/main/java/org/keycloak/protocol/saml/profile/util/Soap.java:101, 149, 313` | ⚠️ No explicit hardening — but `saaj-impl 2.0.1` `RejectDoctypeSaxFilter` blocks DOCTYPE at runtime (see Q4) |

### Hardening details

**(1) DocumentBuilderFactory** — `DocumentUtil.java:408`
- ✅ `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- ✅ `setFeature("http://xml.org/sax/features/external-general-entities", false)`
- ✅ `setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
- ✅ `setXIncludeAware(false)`, `setNamespaceAware(true)`
- `setExpandEntityReferences(false)` not explicit — moot when DOCTYPE is disallowed.

**(2) XMLInputFactory (primary)** — `StaxParserUtil.java:936`
- ✅ `SUPPORT_DTD = false`
- ✅ `IS_SUPPORTING_EXTERNAL_ENTITIES = false`
- ✅ `IS_NAMESPACE_AWARE = true`, `IS_COALESCING = true`

**(4) TransformerFactory** — `TransformerUtil.java:116–130`
Sets `FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD=""`, `ACCESS_EXTERNAL_STYLESHEET=""`, **but each in a `try { ... } catch { logger.warn(...) }`**. On a JDK / XML stack that doesn't recognise the features, the factory is still used. Modern Xerces / JDK supports them; documented caveat is for "Xalan 2.7.1 in our testsuite".

**(7) JAXPValidationUtil Validator** — `JAXPValidationUtil.java:99–113`
All five XXE-relevant settings (`ACCESS_EXTERNAL_DTD`, `ACCESS_EXTERNAL_SCHEMA`, `disallow-doctype-decl`, `external-general-entities`, `external-parameter-entities`) attempted, each best-effort. Only triggered when `-Dpicketlink.schema.validate=true` (default off).

**(9) MessageFactory (SAAJ)** — `Soap.java:101`
```java
MessageFactory messageFactory = MessageFactory.newInstance();
SOAPMessage soapMessage = messageFactory.createMessage(null, inputStream);
```
No `setFeature`, no system properties, no DocumentBuilderFactory pre-config. SAAJ providers in modern JDKs typically default-secure XXE, but Keycloak makes no explicit guarantee. After parsing, `Soap.extractSoapMessage(SOAPMessage)` (line 116–126) imports the body's first child into a fresh hardened Document — but **entity resolution already happened during the initial SAAJ parse**, so `importNode` does not undo XXE side effects.

### Reachability

`Soap.extractSoapMessage(InputStream)` is called from:
- `SamlEcpProfileService.java:67` — `/realms/{realm}/protocol/saml/ecp` (anonymous)
- `SamlService.java:1117` — `/realms/{realm}/protocol/saml/resolve` (anonymous, artifact resolution)
- `SamlService.java:1463` — server-side parse of artifact resolve response (Keycloak as client)
- `SAMLIdentityProvider.java:582` — broker-side parse of artifact response from upstream IdP
- `SamlProtocol.java:841` — SOAP-bound logout response handling

## Q2 — XSW (XML Signature Wrapping) trace

### Flow for `/realms/{realm}/broker/{alias}/endpoint` (SAML POST Response)

1. **Parse** (`SAMLEndpoint.java:770`) → `SAMLRequestParser.parseResponseDocument(samlBytes)` via hardened StAX. Returns `SAMLDocumentHolder { Document, ResponseType }`.
2. **`verifySignature(SAML_RESPONSE_KEY, holder)`** (line 794) — for `PostBinding`:
   ```java
   // SAMLEndpoint.java:857
   if ((!containsUnencryptedSignature(documentHolder)) && (samlObject instanceof ResponseType)) {
       if (!responseType.getAssertions().isEmpty()) return; // skip doc-level verify
   }
   SamlProtocolUtils.verifyDocumentSignature(documentHolder.getSamlDocument(), getIDPKeyLocator());
   ```
   Document-level verification is skipped when there are no Signature elements in the doc, on the premise that per-assertion verification will run downstream.
3. **Document-level verify** (`XMLSignatureUtil.java:467`) when run:
   - `getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")` — find every Signature
   - For each Signature: validate; collect referenced first-node into `signedNodes`
   - If `signedNodes.contains(rootElement)` → pass
   - Else find every `<saml:Assertion>` and require **all** of them in `signedNodes` (rejects classic XSW with extra unsigned assertion)
4. **Branch** to `handleLoginResponse(samlResponse, holder, responseType, relayState, clientId)` (line 803).
5. **Extract assertion DOM element** (line 581) via `AssertionUtil.getAssertionElement(holder)`:
   ```java
   // saml-core/.../AssertionUtil.java:575
   Element response = doc.getDocumentElement();   // must be samlp:Response
   for (Node child : response.getChildNodes()) {
       if (child is samlp:Assertion) return (Element) child;
   }
   ```
   First **direct-child** Assertion of the Response root.
6. **Per-assertion check** (lines 604–609):
   ```java
   boolean signed = AssertionUtil.isSignedElement(assertionElement);
   boolean signatureNotValid = signed && cfg.isValidateSignature() && !AssertionUtil.isSignatureValid(assertionElement, getIDPKeyLocator());
   boolean hasNoSignatureWhenRequired = !signed && cfg.isValidateSignature() && !isMessageFullySigned(holder);
   ```
7. **Use the JAXB-parsed assertion** (line 626):
   ```java
   AssertionType assertion = responseType.getAssertions().get(0).getAssertion();
   ```

### Is the JAXB-parsed assertion the one that was verified?

The DOM extractor (`getAssertionElement`) and the JAXB extractor (`responseType.getAssertions().get(0)`) **should** resolve to the same logical Assertion: both produce the first Assertion that is a direct child of Response in document order, given hardened StAX + namespace-aware DOM.

The remaining XSW exposure surface, in priority order:

1. **`propagateIDAttributeSetup` correctness** (`XMLSignatureUtil.java:356, 472`). `signedNodes` membership is established by URI dereference using `xs:ID` resolution. JDK XML-DSig requires explicit `setIdAttributeNS(...)` on every ID-typed attribute; any namespace/attribute the helper misses is a potential ID-confusion XSW.
2. **Encrypted-assertion path** (`AssertionUtil.decryptAssertion`, AssertionUtil.java:622–649). Decrypted plaintext is **re-parsed via `SAMLParser.parse(...)`** and reinserted into `responseType.replaceAssertion(...)`. Two parses (DOM XMLDecrypter output vs StAX re-parse) produce two object trees; any divergence is an encrypted-XSW analogue.
3. **`PostBinding.verifySignature` early-return** (`SAMLEndpoint.java:858`). Document-level verify is skipped when the doc has no Signature elements at all. The fall-through relies on `hasNoSignatureWhenRequired = !signed && !isMessageFullySigned(holder)` — and `isMessageFullySigned` (line 852) checks only for a direct-child Signature of the root.
4. **Mismatch between StAX/JAXB parse and DOM walk** when namespace prefixes are unusual or when the doc carries content in default namespaces with redirected scopes.

## Q3 — ECP endpoint XML parsing

`/realms/{realm}/protocol/saml/ecp` → `SamlEcpProfileService.authenticate(InputStream)` (line 66):
```java
public Response authenticate(InputStream inputStream) {
    return authenticate(Soap.extractSoapMessage(inputStream));
}
```
→ `Soap.extractSoapMessage(InputStream)` (Soap.java:99) → `MessageFactory.newInstance().createMessage(null, inputStream)`.

**Different from the rest of the SAML stack.** The standard SAML XML path uses `DocumentUtil`'s hardened `DocumentBuilderFactory` and `StaxParserUtil`'s hardened `XMLInputFactory`. The ECP endpoint instead routes through SAAJ `MessageFactory`, which Keycloak **does not** XXE-harden.

After SAAJ has parsed the envelope, `extractSoapMessage(SOAPMessage)` imports the body's first child into a fresh hardened-factory Document — but entity resolution already happened during the initial parse, so this re-rooting does not undo XXE side effects.

The same code path is reused for `/realms/{realm}/protocol/saml/resolve` and inbound SOAP from external IdPs. **ECP is the most attacker-accessible**: anonymous POST with a SOAP envelope.

Residual safety depends on the deployed SAAJ provider's default DOCTYPE handling. Worth runtime confirmation:
- Send a SOAP envelope with `<!DOCTYPE foo [ <!ENTITY x SYSTEM "http://attacker/"> ]>` and watch for outbound DNS / HTTP.
- Try parameter-entity expansion (Billion Laughs / quadratic blowup).
- Test on a stack where `com.sun.xml.messaging.saaj.parsing.disallowDoctypeDecl` is unset.

## Q4 — Runtime XXE confirmation (Phase 4)

Script: `xxe_confirm.py` — POST to `http://localhost:8080/realms/master/protocol/saml`
with `Content-Type: application/soap+xml`. Run 2026-05-07 against `keycloak-dev`
(Keycloak 26.0.8, OpenJDK 21.0.6, saaj-impl 2.0.1).

**Correction from static analysis:** `SamlEcpProfileService` is not at a `/ecp`
sub-path. It is dispatched from the main `/realms/{realm}/protocol/saml` endpoint
inside `SamlService.soapBinding()` (line 1163–1170) via JAX-RS `@Consumes`
on `application/soap+xml` / `text/xml`.

### Test results

| # | Test | HTTP | Elapsed | Result |
|---|---|---|---|---|
| 4 | Baseline (clean AuthnRequest) | 500 | 219 ms | SOAP fault `invalidRequestMessage` — endpoint alive, SOAP parsed |
| 1 | OOB callback `http://host.docker.internal:9001/xxe-oob` | 500 | 14 ms | No callback; JSON `unknown_error` — parsing failed |
| 2 | In-band file read `file:///etc/hostname` | 500 | 21 ms | JSON `unknown_error` — parsing failed |
| 3 | Billion Laughs (9-level entity chain) | 500 | 8 ms | JSON `unknown_error` — parsing failed |

### Root cause from container logs

```
Caused by: org.xml.sax.SAXException: Document Type Declaration is not allowed
    at com.sun.xml.messaging.saaj.util.RejectDoctypeSaxFilter.startDTD(RejectDoctypeSaxFilter.java:101)
    at com.sun.org.apache.xerces.internal.parsers.AbstractSAXParser.doctypeDecl(...)
    at com.sun.org.apache.xerces.internal.impl.dtd.XMLDTDValidator.doctypeDecl(...)
```

`saaj-impl-2.0.1` (`/opt/keycloak/lib/lib/main/com.sun.xml.messaging.saaj.saaj-impl-2.0.1.jar`)
installs `RejectDoctypeSaxFilter` as the `LexicalHandler` on every SAX parse inside
`EnvelopeFactory.parseEnvelopeSax()`. The filter's `startDTD()` unconditionally
throws before the DTD body is evaluated — blocking OOB callbacks, file reads,
and Billion Laughs with equal effect.

### Verdict

**XXE via DOCTYPE: NOT exploitable** against `saaj-impl 2.0.1` as shipped.

The protection is **implicit** (library behaviour, not Keycloak code).
The static finding (item #9 in Q1 table) stands as a code-quality risk because:

1. No explicit Keycloak hardening means no guarantee if `saaj-impl` is swapped
   or downgraded to a version that predates `RejectDoctypeSaxFilter`.
2. The JSON `unknown_error` response (not a SOAP fault) leaks that an unhandled
   exception occurred, even though no data exfiltration happened — the error path
   differs from legitimate SAML failures and is observable by an attacker.
3. The fast-fail timing differential (8–21 ms vs 219 ms baseline) confirms the
   failure is at parse time, before any Keycloak SAML logic runs.

### Non-DOCTYPE attack vectors (not tested)

These remain theoretical until tested:

- **SSRF without DOCTYPE** — crafting a SOAP envelope that causes the SAAJ parser
  (or any downstream processing) to make outbound network calls via schema hints
  or namespace URIs (unlikely with the current SAAJ code path but worth testing).
- **Quadratic/cubic blowup without entity references** — extremely deep element
  nesting; not blocked by `RejectDoctypeSaxFilter` but capped by server-side
  timeout / thread budget.
- **`SamlService.soapBinding` path confusion** — the `@Consumes` dispatch means
  any XML-content POST to the SAML endpoint routes through unhardened SAAJ; if
  a future SAAJ provider omits the filter, the attack surface is already wired.

---

*Audit performed 2026-05-07 against snapshot at commit a9d523b.*
