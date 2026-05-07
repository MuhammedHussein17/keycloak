# Keycloak 26.0.8 — Attack Surface Map

Source: `keycloak/` at commit `a9d523b0cdc1e8b75decd2113b851408f3dfde70`.
Running instance: `quay.io/keycloak/keycloak:26.0` container `keycloak-dev`,
listening on `localhost:8080` (HTTP) and `localhost:9000` (management).

This document is the consolidated output of four parallel source-tree audits:
JAX-RS resources under `services/src/main/java/**`, Quarkus/Vert.x routes
under `quarkus/`, admin REST API, and the account console. All file paths are
relative to `keycloak/`. Line numbers were verified against the snapshot at
the commit above; treat them as approximate when reading large methods.

> Convention: every endpoint pattern is the **mounted** path. JAX-RS resources
> sitting under `RealmsResource` are mounted at `/realms/{realm}/...`; admin
> resources at `/admin/realms/{realm}/...`. The management interface (port
> 9000) is denoted `[mgmt:9000]`.

---

## 1. Quarkus / Vert.x routes (non-JAX-RS layer)

These run before — or alongside — the JAX-RS dispatcher. The management port
(9000) carries everything in the second block; nothing on it requires auth by
default.

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `[http:8080] /` | GET | None | `KeycloakRecorder.getRedirectHandler` (quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/KeycloakRecorder.java:93) | Redirects root to configured `http.relative-path` |
| `[http:8080] *` (filter, all paths) | * | n/a | `RejectNonNormalizedPathFilter.handle` (quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/services/RejectNonNormalizedPathFilter.java:37) | Rejects `..`, `//`, `;` before JAX-RS — proxy-normalisation mismatch could bypass |
| `[http:8080] *.js.map` | GET | None | `RejectSourceMapFilter.handle` (quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/services/RejectSourceMapFilter.java:37) | Blocked outside dev mode |
| `[mgmt:9000] /` | GET | None | `KeycloakRecorder.getManagementHandler` (quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/KeycloakRecorder.java:105) | Lists enabled mgmt endpoints. **RISK: info disclosure** |
| `[mgmt:9000] /health` | GET | None | `KeycloakReadyHealthCheck.call` (quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/services/health/KeycloakReadyHealthCheck.java:72) | Reveals `Failing since` timestamp on outage. **RISK: info disclosure** |
| `[mgmt:9000] /health/ready` | GET | None | `BootstrapReadyHealthCheck.call` (quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/services/health/BootstrapReadyHealthCheck.java:45) | |
| `[mgmt:9000] /health/live` | GET | None | (Quarkus default) | |
| `[mgmt:9000] /health/started` | GET | None | (Quarkus default) | |
| `[mgmt:9000] /metrics` | GET | None | Micrometer / SmallRye | URI tag may include realm/resource names. **RISK: info disclosure** |
| `[mgmt:9000] /openapi` | GET | None | SmallRye OpenAPI | Full schema. **RISK: info disclosure** |
| `[mgmt:9000] /openapi/ui` | GET | None | SmallRye OpenAPI UI | Interactive Swagger. **RISK: info disclosure** |

---

## 2. Public / unauthenticated JAX-RS endpoints (port 8080)

Top-level mounts and non-realm-scoped endpoints. Reachable anonymously unless
otherwise noted.

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/` | GET | None | `WelcomeResource.getWelcomePage` (services/src/main/java/org/keycloak/services/resources/WelcomeResource.java:87) | Welcome page redirect |
| `/` | POST | None — admin bootstrap | `WelcomeResource.createUser` (services/src/main/java/org/keycloak/services/resources/WelcomeResource.java:100) | Creates initial master-realm admin if not yet present. CSRF-protected; intended localhost-only |
| `/welcome-content/{path}` | GET | None | `WelcomeResource.getResource` (services/src/main/java/org/keycloak/services/resources/WelcomeResource.java:175) | **RISK: path traversal candidate** via `{path}` |
| `/lb-check` | GET | None | `LoadBalancerResource.getStatusForLoadBalancer` (services/src/main/java/org/keycloak/services/resources/LoadBalancerResource.java:66) | UP/DOWN |
| `/.well-known/{provider}/realms/{realm}` | GET, OPTIONS | None | `ServerMetadataResource.getWellKnown` (services/src/main/java/org/keycloak/services/resources/ServerMetadataResource.java:61) | OIDC discovery, SAML metadata, etc. |
| `/resources/{version}/{themeType}/{themeName}/{path}` | GET | None | `ThemeResource.getResource` (services/src/main/java/org/keycloak/services/resources/ThemeResource.java:91) | **RISK: path traversal candidate** in `{path}` |
| `/resources/{realm}/{themeType}/{locale}` | GET, OPTIONS | None | `ThemeResource.getLocalizationTexts` (services/src/main/java/org/keycloak/services/resources/ThemeResource.java:199) | **RISK: URL param `theme`** |
| `/realms/{realm}` | GET, OPTIONS | None | `PublicRealmResource.getRealm` (services/src/main/java/org/keycloak/services/resources/PublicRealmResource.java:83) | Returns public key, token URL, etc. |
| `/realms/{realm}/.well-known/{provider}` | GET, OPTIONS | None | `RealmsResource.getWellKnown` (services/src/main/java/org/keycloak/services/resources/RealmsResource.java:231) | Dynamic provider dispatch |
| `/realms/{realm}/clients/{client_id}/redirect` | GET | None | `RealmsResource.getRedirect` (services/src/main/java/org/keycloak/services/resources/RealmsResource.java:138) | Redirects to client root URL |

---

## 3. Protocol layer — OIDC / SAML / CIBA / PAR / Device / Brokering

This is the highest-value surface for protocol-level vulns. Most endpoints
are unauthenticated at the network layer; auth is enforced inside the
protocol flow (state, code, action token, signature, etc.).

### 3a. OIDC core

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/protocol/openid-connect/auth` | GET, POST | None | `AuthorizationEndpoint.buildGet/buildPost` (services/src/main/java/org/keycloak/protocol/oidc/endpoints/AuthorizationEndpoint.java) | **RISK: URL params `redirect_uri`, `request_uri`, `state`, `nonce`, `response_type`, `response_mode`, `code_challenge`, `prompt`, `scope`**; `request_uri` triggers external fetch (**RISK: SSRF candidate**) |
| `/realms/{realm}/protocol/openid-connect/token` | POST | Client creds (form / Basic) | `TokenEndpoint.processGrantRequest` (services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenEndpoint.java:76) | **RISK: form params `grant_type`, `code`, `refresh_token`, `password`, `client_assertion`** — JWT validation in client_assertion fetches keys from `jwks_uri` (**RISK: SSRF candidate**) |
| `/realms/{realm}/protocol/openid-connect/userinfo` | GET, POST | Bearer (token) | `UserInfoEndpoint.issueUserInfoGet/issueUserInfoPost` (services/src/main/java/org/keycloak/protocol/oidc/endpoints/UserInfoEndpoint.java:86) | |
| `/realms/{realm}/protocol/openid-connect/logout` | GET, POST | Cookie session or `id_token_hint` | `LogoutEndpoint.logout` (services/src/main/java/org/keycloak/protocol/oidc/endpoints/LogoutEndpoint.java) | **RISK: URL params `post_logout_redirect_uri`, `id_token_hint`, `client_id`, `state`, `ui_locales`** |
| `/realms/{realm}/protocol/openid-connect/logout-confirm` | GET, POST | Cookie session | `LogoutEndpoint.logoutConfirmGet/logoutConfirmAction` | Browser confirm page |
| `/realms/{realm}/protocol/openid-connect/backchannel-logout` | POST | logout token (JWT, signed) | `LogoutEndpoint.backchannelLogout` | **RISK: form param `logout_token`** — JWT signed by client; key lookup may fetch JWKS (**RISK: SSRF candidate**) |
| `/realms/{realm}/protocol/openid-connect/certs` | GET, OPTIONS | None | `OIDCLoginProtocolService.certs` (services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolService.java:199) | Realm signing JWKS |
| `/realms/{realm}/protocol/openid-connect/token/introspect` | POST | Client creds | `TokenIntrospectionEndpoint.introspect` (services/src/main/java/org/keycloak/protocol/oidc/endpoints/TokenIntrospectionEndpoint.java) | |
| `/realms/{realm}/protocol/openid-connect/revoke` | POST | Client creds | `TokenRevocationEndpoint.revoke` | |
| `/realms/{realm}/protocol/openid-connect/login-status-iframe.html` | GET | None | `LoginStatusIframeEndpoint.getLoginStatusIframe` | |
| `/realms/{realm}/protocol/openid-connect/login-status-iframe.html/init` | GET | None | `LoginStatusIframeEndpoint.preCheck` | **RISK: URL param `origin`, `client_id`** — postMessage origin check |
| `/realms/{realm}/protocol/openid-connect/3p-cookies/step1.html` | GET | None | `ThirdPartyCookiesIframeEndpoint.step1` | |
| `/realms/{realm}/protocol/openid-connect/3p-cookies/step2.html` | GET | None | `ThirdPartyCookiesIframeEndpoint.step2` | |
| `/realms/{realm}/protocol/openid-connect/oauth/oob` | GET | None | `OIDCLoginProtocolService.installedAppUrnCallback` (OIDCLoginProtocolService.java:235) | OOB redirect target |
| `/realms/{realm}/protocol/openid-connect/forgot-credentials` | GET | None | `AuthorizationEndpoint.forgotCredentials` | |
| `/realms/{realm}/protocol/openid-connect/registrations` | GET | None / initial-access-token | `AuthorizationEndpoint.register` | |

### 3b. OIDC extensions (CIBA / PAR / Device)

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/protocol/openid-connect/ext/par/request` | POST | Client creds | `ParEndpoint.request` (services/src/main/java/org/keycloak/protocol/oidc/par/endpoints/ParEndpoint.java) | **RISK: form param `request` (JWT) and `request_uri`** — request_uri can fetch external content (**RISK: SSRF candidate**); JWT can be signed (**RISK: XML/JSON key resolution → SSRF via `jwks_uri`**) |
| `/realms/{realm}/protocol/openid-connect/ext/ciba/auth` | POST | Client creds | `BackchannelAuthenticationEndpoint.processCibaAuthenticationRequest` (services/src/main/java/org/keycloak/protocol/oidc/grants/ciba/endpoints/BackchannelAuthenticationEndpoint.java) | **RISK: signed `request` JWT → JWKS fetch (SSRF candidate)** |
| `/realms/{realm}/protocol/openid-connect/ext/ciba/auth/callback` | POST | None (auth_req_id) | `BackchannelAuthenticationCallbackEndpoint.authenticateCallback` | **RISK: form param `auth_req_id`** |
| `/realms/{realm}/protocol/openid-connect/ext/device` | POST | Client creds | `DeviceEndpoint.handleDeviceRequest` (services/src/main/java/org/keycloak/protocol/oidc/grants/device/endpoints/DeviceEndpoint.java) | Device code grant |

### 3c. SAML

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/protocol/saml` | GET, POST | None | `SamlService.redirectBinding/postBinding` (services/src/main/java/org/keycloak/protocol/saml/SamlService.java:929) | **RISK: XML processing — XXE / XSW candidate** on `SAMLRequest`/`SAMLResponse` (Redirect + POST bindings) |
| `/realms/{realm}/protocol/saml/descriptor` | GET | None | `SamlService.getDescriptor` (SamlService.java:952) | XML metadata |
| `/realms/{realm}/protocol/saml/clients/{client}` | GET | None | `SamlService.idpInitiatedSSO` (SamlService.java:1009) | IdP-initiated SSO; **RISK: URL param `RelayState`** |
| `/realms/{realm}/protocol/saml/resolve` | POST | None | `SamlService.artifactResolution` (SamlService.java:1112) | **RISK: XML processing** (SOAP+SAML), artifact dereferencing |
| `/realms/{realm}/protocol/saml/ecp` | POST | None | `SamlEcpProfileService.handleEcpRequest` (services/src/main/java/org/keycloak/protocol/saml/profile/ecp/SamlEcpProfileService.java) | **RISK: XML processing** (SOAP envelope) |

### 3d. Login actions (browser flows)

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/login-actions/authenticate` | GET, POST | Auth-session cookie | `LoginActionsService.authenticate / authenticateForm` (services/src/main/java/org/keycloak/services/resources/LoginActionsService.java:323) | **RISK: URL params `session_code`, `auth_session_id`, `client_id`, `tab_id`, `execution`** |
| `/realms/{realm}/login-actions/reset-credentials` | GET, POST | None / action-token | `LoginActionsService.resetCredentialsGET/POST` (LoginActionsService.java:413) | **RISK: URL params `key`, `code`, `redirect_uri`, `client_id`, `execution`** — entry point for token-driven reset |
| `/realms/{realm}/login-actions/action-token` | GET, HEAD | Action token (signed) | `LoginActionsService.executeActionToken / executeActionTokenHead` (LoginActionsService.java:544) | **RISK: URL param `key`** — token signature is the only auth |
| `/realms/{realm}/login-actions/registration` | GET, POST | None / initial-access-token | `LoginActionsService.processRegisterGET/POST` (LoginActionsService.java:782) | |
| `/realms/{realm}/login-actions/first-broker-login` | GET, POST | Auth-session cookie | `LoginActionsService.firstBrokerLoginGet/Post` (LoginActionsService.java:850) | Continues IdP flow |
| `/realms/{realm}/login-actions/post-broker-login` | GET, POST | Auth-session cookie | `LoginActionsService.postBrokerLoginGet/Post` (LoginActionsService.java:872) | |
| `/realms/{realm}/login-actions/consent` | POST | Auth-session cookie | `LoginActionsService.consentAction` (LoginActionsService.java:1026) | |
| `/realms/{realm}/login-actions/required-action` | GET, POST | Auth-session cookie | `LoginActionsService.requiredActionGET/POST` (LoginActionsService.java:1137) | |
| `/realms/{realm}/login-actions/restart` | GET | None | `LoginActionsService.restartSession` (LoginActionsService.java:229) | **RISK: URL param `auth_session_id`** |
| `/realms/{realm}/login-actions/detached-info` | GET | None | `LoginActionsService.detachedInfo` (LoginActionsService.java:278) | **RISK: URL param `state_checker`** |

### 3e. Identity brokering (IdP callbacks)

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/broker/{provider_alias}/login` | GET, POST | None | `IdentityBrokerService.performLogin/performPostLogin` (services/src/main/java/org/keycloak/services/resources/IdentityBrokerService.java:393) | **RISK: URL params `client_id`, `session_code`, `login_hint`** |
| `/realms/{realm}/broker/{provider_alias}/link` | GET | Cookie session | `IdentityBrokerService.clientInitiatedAccountLinking` (IdentityBrokerService.java:221) | **DEPRECATED**. **RISK: URL params `redirect_uri`, `client_id`, `nonce`, `hash`** |
| `/realms/{realm}/broker/{provider_alias}/endpoint/...` | * (provider-defined) | Provider-defined | `IdentityBrokerService.getEndpoint` (IdentityBrokerService.java:463) | Dispatches into provider-specific callback (e.g. `SAMLEndpoint`, `OIDCEndpoint`). **RISK: XML processing** for SAML provider; **RISK: SSRF candidate** for OIDC token-exchange |
| `/realms/{realm}/broker/{provider_alias}/token` | GET, POST, OPTIONS | Bearer (token) | `IdentityBrokerService.retrieveTokenV1/V2` (IdentityBrokerService.java:483) | Federated-token retrieval |

### 3f. Client registration & UMA

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/clients-registrations/{provider}` | GET, POST, PUT, DELETE | varies (anonymous / initial-access / registration-access) | `ClientRegistrationService.provider → <provider>` (services/src/main/java/org/keycloak/services/clientregistration/ClientRegistrationService.java:43) | Dynamic provider dispatch |
| `/realms/{realm}/clients-registrations/default` | GET, POST, PUT, DELETE | initial-access-token / registration-access-token | `DefaultClientRegistrationProvider` | Keycloak-native client registration |
| `/realms/{realm}/clients-registrations/openid-connect` | GET, POST, PUT, DELETE | initial-access-token / registration-access-token | `OIDCClientRegistrationProvider` (services/src/main/java/org/keycloak/services/clientregistration/oidc/OIDCClientRegistrationProvider.java) | OIDC dynamic client registration; metadata may include `jwks_uri`, `request_uris` (**RISK: SSRF candidate** when those URIs are later fetched) |
| `/realms/{realm}/clients-registrations/saml2-entity-descriptor` | POST | initial-access-token | `EntityDescriptorClientRegistrationProvider` (services/src/main/java/org/keycloak/protocol/saml/clientregistration/EntityDescriptorClientRegistrationProvider.java) | **RISK: XML processing — XXE candidate** |
| `/realms/{realm}/authz/protection/resource_set` | GET, POST, PUT, DELETE | Bearer (token w/ uma_protection) | `ResourceService` (services/src/main/java/org/keycloak/authorization/protection/resource/ResourceService.java) | UMA resource registration |
| `/realms/{realm}/authz/protection/permission` | POST | Bearer (token) | `PermissionService` | UMA permission ticket creation |
| `/realms/{realm}/authz/protection/permission/ticket` | GET, POST, PUT, DELETE | Bearer (token) | `PermissionTicketService` | UMA ticket management |
| `/realms/{realm}/authz/protection/uma-policy` | GET, POST, PUT, DELETE | Bearer (token) | `UserManagedPermissionService` | User-managed policy |

---

## 4. Account console

`AccountLoader` dispatches `/realms/{realm}/account/...` to either
`AccountConsole` (HTML) or `AccountRestService` (JSON, versioned at `/v{N}`).
All REST endpoints below require an account-bearer token (the user's own).

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/realms/{realm}/account/` | GET | None (then content-negotiated) | `AccountLoader.getAccountService` (services/src/main/java/org/keycloak/services/resources/account/AccountLoader.java:75) | Returns SPA shell; JSON branch requires bearer |
| `/realms/{realm}/account/{path:.*}` | GET | None | `AccountConsole.getMainPage / renderAccountConsole` (services/src/main/java/org/keycloak/services/resources/account/AccountConsole.java:108) | **RISK: URL params `referrer`, `referrer_uri`** → `RedirectUtils.verifyRedirectUri` |
| `/realms/{realm}/account/index.html` | GET | None | `AccountConsole.getIndexHtmlRedirect` (AccountConsole.java:280) | Redirect |
| `/realms/{realm}/account` (OPTIONS) | OPTIONS | None | `CorsPreflightService.preflight` (services/src/main/java/org/keycloak/services/resources/account/CorsPreflightService.java:21) | CORS preflight |
| `/realms/{realm}/account/v{N}/` | GET | Bearer (account) | `AccountRestService.account` (services/src/main/java/org/keycloak/services/resources/account/AccountRestService.java:131) | |
| `/realms/{realm}/account/v{N}/` | POST | Bearer (account) | `AccountRestService.updateAccount` (AccountRestService.java:150) | |
| `/realms/{realm}/account/v{N}/supportedLocales` | GET | Bearer (account) | `AccountRestService.supportedLocales` (AccountRestService.java:230) | |
| `/realms/{realm}/account/v{N}/applications` | GET | Bearer (account) | `AccountRestService.applications` (AccountRestService.java:453) | **RISK: URL param `name`** |
| `/realms/{realm}/account/v{N}/applications/{clientId}/consent` | GET, POST, PUT, DELETE | Bearer (account) | `AccountRestService.getConsent / grantConsent / updateConsent / revokeConsent` (AccountRestService.java:289–360) | |
| `/realms/{realm}/account/v{N}/groups` | GET | Bearer (account) | `AccountRestService.groupMemberships` (AccountRestService.java:447) | |
| `/realms/{realm}/account/v{N}/credentials` | GET | Bearer (account) | `AccountCredentialResource.credentialTypes` (services/src/main/java/org/keycloak/services/resources/account/AccountCredentialResource.java:177) | **RISK: URL params `type`, `user-credentials`** |
| `/realms/{realm}/account/v{N}/credentials/{credentialId}` | DELETE | Bearer (account) | `AccountCredentialResource.removeCredential` (AccountCredentialResource.java:307) | DEPRECATED — use kc_action |
| `/realms/{realm}/account/v{N}/credentials/{credentialId}/label` | PUT | Bearer (account) | `AccountCredentialResource.setLabel` (AccountCredentialResource.java:337) | |
| `/realms/{realm}/account/v{N}/sessions` | GET | Bearer (account) | `SessionResource.toRepresentation` (services/src/main/java/org/keycloak/services/resources/account/SessionResource.java:82) | |
| `/realms/{realm}/account/v{N}/sessions/devices` | GET | Bearer (account) | `SessionResource.devices` (SessionResource.java:95) | |
| `/realms/{realm}/account/v{N}/sessions` | DELETE | Bearer (account) | `SessionResource.logout` (SessionResource.java:143) | **RISK: URL param `current`** |
| `/realms/{realm}/account/v{N}/sessions/{id}` | DELETE | Bearer (account) | `SessionResource.logout` (SessionResource.java:171) | |
| `/realms/{realm}/account/v{N}/linked-accounts` | GET | Bearer (account) | `LinkedAccountsResource.linkedAccounts` (services/src/main/java/org/keycloak/services/resources/account/LinkedAccountsResource.java:122) | **RISK: URL params `linked`, `search`, `first`, `max`** |
| `/realms/{realm}/account/v{N}/linked-accounts/{providerAlias}` | GET | Bearer (account) | `LinkedAccountsResource.buildLinkedAccountURI` (LinkedAccountsResource.java:255) | **DEPRECATED**. **RISK: URL param `redirectUri`** |
| `/realms/{realm}/account/v{N}/linked-accounts/{providerAlias}` | DELETE | Bearer (account) | `LinkedAccountsResource.removeLinkedAccount` (LinkedAccountsResource.java:287) | |
| `/realms/{realm}/account/v{N}/organizations` | GET | Bearer (account) | `OrganizationsResource.getOrganizations` (services/src/main/java/org/keycloak/services/resources/account/OrganizationsResource.java:54) | |
| `/realms/{realm}/account/v{N}/resources` | GET | Bearer (account) | `ResourcesService.getResources` (services/src/main/java/org/keycloak/services/resources/account/resources/ResourcesService.java:65) | **RISK: URL params `name`, `first`, `max`** |
| `/realms/{realm}/account/v{N}/resources/shared-with-me` | GET | Bearer (account) | `ResourcesService.getSharedWithMe` (ResourcesService.java:91) | |
| `/realms/{realm}/account/v{N}/resources/{resourceId}` | GET | Bearer (account) | `ResourceService.getResource` (services/src/main/java/org/keycloak/services/resources/account/resources/ResourceService.java:69) | |
| `/realms/{realm}/account/v{N}/resources/{resourceId}/permissions` | GET, PUT | Bearer (account) | `ResourceService.toPermissions / revoke` (ResourceService.java:80, 128) | |
| `/realms/{realm}/account/v{N}/resources/{resourceId}/user` | GET | Bearer (account) | `ResourceService.user` (ResourceService.java:103) | **RISK: URL param `value`** — username lookup, enumeration risk |

---

## 5. Admin REST API (`/admin/realms/...`)

Mounted by `RealmsAdminResource`. All endpoints require an admin bearer token
plus a permission check (`auth.realm()`, `auth.users()`, `auth.clients()`,
`auth.groups()`, `auth.roles()`, `auth.orgs()`); fine-grained checks delegate
to `AdminPermissions` / `AdminPermissionEvaluator`. Sub-resources are
returned via JAX-RS locator methods.

### 5a. Realm-level

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/admin/realms` | GET, POST | Bearer admin (realms scope) | `RealmsAdminResource.getRealms / importRealm` | POST imports realm JSON |
| `/admin/realms/{realm}` | GET, PUT, DELETE | `auth.realm().requireView/Manage` | `RealmAdminResource.getRealm / updateRealm / deleteRealm` | |
| `/admin/realms/{realm}/client-description-converter` | POST | `auth.clients().requireManage()` | `RealmAdminResource.convertClientDescription` (services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java:179) | Consumes JSON / **XML** / TEXT. **RISK: XML processing** via `ClientDescriptionConverter` factories |
| `/admin/realms/{realm}/partialImport` | POST | `auth.realm().requireManageRealm()` | `RealmAdminResource.partialImport` | JSON import via `ExportImportManager` |
| `/admin/realms/{realm}/partial-export` | POST | `auth.realm()` | `RealmAdminResource.partialExport` | Streamed export |
| `/admin/realms/{realm}/testSMTPConnection` | POST | `auth.realm().requireManageRealm()` | `RealmAdminResource.testSMTPConnection` | **RISK: SSRF-adjacent** — opens SMTP connection to admin-supplied host:port |
| `/admin/realms/{realm}/events` | GET, DELETE | `auth.realm()` | `RealmAdminResource.getEvents / clearEvents` | |
| `/admin/realms/{realm}/events/config` | GET, PUT | `auth.realm()` | `RealmAdminResource.getRealmEventsConfig / updateRealmEventsConfig` | |
| `/admin/realms/{realm}/admin-events` | GET, DELETE | `auth.realm()` | `RealmAdminResource.getEvents / clearAdminEvents` | |
| `/admin/realms/{realm}/client-session-stats` | GET | `auth.realm().requireViewRealm()` | `RealmAdminResource.getClientSessionStats` | |
| `/admin/realms/{realm}/push-revocation` | POST | `auth.realm().requireManageRealm()` | `RealmAdminResource.pushRevocation` | Backchannel push to clients (**RISK: SSRF candidate** — outbound HTTP to client URLs) |
| `/admin/realms/{realm}/logout-all` | POST | `auth.users().requireManage()` | `RealmAdminResource.logoutAll` | |
| `/admin/realms/{realm}/sessions/{session}` | DELETE | `auth.users().requireManage()` | `RealmAdminResource.deleteSession` | |
| `/admin/realms/{realm}/credential-registrators` | GET | `auth.realm().requireViewRealm()` | `RealmAdminResource.getCredentialRegistrators` | |
| `/admin/realms/{realm}/keys` | (locator) | auth | `RealmAdminResource.keys` | → `KeyResource` |
| `/admin/realms/{realm}/authentication` | (locator) | auth | `RealmAdminResource.flows` | → `AuthenticationManagementResource` |
| `/admin/realms/{realm}/{extension}` | (locator) | auth | `RealmAdminResource.extension` | Dynamic SPI dispatch |

### 5b. Users

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/admin/realms/{realm}/users` | GET, POST | `auth.users()` | `UsersResource.getUsers / createUser` (services/src/main/java/org/keycloak/services/resources/admin/UsersResource.java) | **RISK: dynamic query** — `searchQuery` param parsed via `SearchQueryUtils.getFields` and passed to `searchForUserStream` |
| `/admin/realms/{realm}/users/count` | GET | `auth.users().requireQuery()` | `UsersResource.getUsersCount` | |
| `/admin/realms/{realm}/users/profile` | (locator) | auth | `UsersResource.userProfile` | → `UserProfileResource` |
| `/admin/realms/{realm}/users/{user-id}` | GET, PUT, DELETE | `auth.users()` | `UserResource.getUser / updateUser / deleteUser` | |
| `/admin/realms/{realm}/users/{user-id}/impersonation` | POST | `auth.users().requireImpersonate()` | `UserResource.impersonate` | Requires IMPERSONATION feature |
| `/admin/realms/{realm}/users/{user-id}/credentials` | GET | `auth.users()` | `UserResource.credentials` | |
| `/admin/realms/{realm}/users/{user-id}/credentials/{credentialId}` | PUT, DELETE | `auth.users()` | `UserResource` | |
| `/admin/realms/{realm}/users/{user-id}/sent-registration-link` | PUT | `auth.users()` | `UserResource.sendVerifyEmail` | **RISK: URL param `redirect_uri`** → `RedirectUtils.verifyRedirectUri` |
| `/admin/realms/{realm}/users/{user-id}/execute-actions-email` | PUT | `auth.users()` | `UserResource.sendExecuteActionsEmail` | **RISK: URL param `redirect_uri`**; also `lifespan` |
| `/admin/realms/{realm}/users/{user-id}/reset-password` | PUT | `auth.users()` | `UserResource.resetPassword` | |
| `/admin/realms/{realm}/users/{user-id}/reset-password-email` | PUT | `auth.users()` | `UserResource.sendResetPasswordEmail` | **RISK: URL param `redirectUri`** |
| `/admin/realms/{realm}/users/{user-id}/federated-identities` | GET | `auth.users()` | `UserResource.getFederatedIdentities` | |
| `/admin/realms/{realm}/users/{user-id}/federated-identities/{idp-alias}` | POST, DELETE | `auth.users()` | `UserResource.addFederatedIdentity / removeFederatedIdentity` | |
| `/admin/realms/{realm}/users/{user-id}/role-mappings` | (locator) | auth | `UserResource.getRoleMappingResource` | → `RoleMapperResource` |
| `/admin/realms/{realm}/users/{user-id}/groups` | GET | `auth.groups()` | `UserResource.getUserGroups` | |
| `/admin/realms/{realm}/users/{user-id}/groups/{groupId}` | PUT, DELETE | `auth.groups()` | `UserResource.addGroup / leaveGroup` | |
| `/admin/realms/{realm}/users/{user-id}/consents` | GET | `auth.users()` | `UserResource.getConsents` | |
| `/admin/realms/{realm}/users/{user-id}/consents/{client}` | DELETE | `auth.users()` | `UserResource.revokeConsent` | |
| `/admin/realms/{realm}/users/{user-id}/sessions` | GET | `auth.users()` | `UserResource.getUserSessions` | |
| `/admin/realms/{realm}/users/{user-id}/logout` | POST | `auth.users()` | `UserResource.logout` | |
| `/admin/realms/{realm}/users/{user-id}/offline-sessions/{clientId}` | DELETE | `auth.users()` | `UserResource.logoutUserSessionsForClient` | |
| `/admin/realms/{realm}/users/{user-id}/disableCredentialTypes` | PUT | `auth.users()` | `UserResource.disableCredentialTypes` | |
| `/admin/realms/{realm}/users/{user-id}/oid4vci/credentials` | GET, POST, DELETE | `auth.users()` | `UserVerifiableCredentialResource` | OID4VC feature gated |
| `/admin/realms/{realm}/users-management-permissions` | GET, PUT | `auth.realm()` | `RealmAdminResource.getUserMgmtPermissions / setUsersManagementPermissionsEnabled` | |

### 5c. Clients

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/admin/realms/{realm}/clients` | GET, POST | `auth.clients()` | `ClientsResource.getClients / createClient` | **RISK: dynamic query** — `searchQuery` → `searchClientByAttributes` |
| `/admin/realms/{realm}/clients/{client-uuid}` | GET, PUT, DELETE | `auth.clients()` | `ClientResource.getClient / update / deleteClient` | |
| `/admin/realms/{realm}/clients/{client-uuid}/installation/providers/{providerId}` | GET | `auth.clients().requireView()` | `ClientResource.getInstallationProvider` (services/src/main/java/org/keycloak/services/resources/admin/ClientResource.java:240) | **RISK: SSRF candidate** — installation providers may fetch remote metadata |
| `/admin/realms/{realm}/clients/{client-uuid}/client-secret` | GET, POST | `auth.clients()` | `ClientResource.getClientSecret / regenerateSecret` | |
| `/admin/realms/{realm}/clients/{client-uuid}/registration-access-token` | POST | `auth.clients().requireManage()` | `ClientResource.regenerateRegistrationAccessToken` | |
| `/admin/realms/{realm}/clients/{client-uuid}/default-client-scopes` | GET, PUT, DELETE | `auth.clients()` | `ClientResource.{get,add,remove}DefaultClientScopes` | |
| `/admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes` | GET, PUT, DELETE | `auth.clients()` | `ClientResource.{get,add,remove}OptionalClientScopes` | |
| `/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers` | (locator) | auth | `ClientResource.getProtocolMappers` | → `ProtocolMappersResource` |
| `/admin/realms/{realm}/clients/{client-uuid}/scope-mappings` | (locator) | auth | `ClientResource.getScopeMappedResource` | → `ScopeMappedResource` |
| `/admin/realms/{realm}/clients/{client-uuid}/roles` | (locator) | auth | `ClientResource.getRoleContainerResource` | → `RoleContainerResource` |
| `/admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}` | (locator) | auth | `ClientResource.getCertificateResource` | → `ClientAttributeCertificateResource` (PEM upload) |
| `/admin/realms/{realm}/client-scopes`, `/client-templates` | (locator) | auth | `RealmAdminResource.getClientScopes / getClientTemplates` | |
| `/admin/realms/{realm}/default-default-client-scopes`, `/default-optional-client-scopes` | GET, PUT, DELETE | `auth.clients().requireView/ManageClientScopes` | `RealmAdminResource` | |
| `/admin/realms/{realm}/clients-initial-access` | (locator) | auth | `RealmAdminResource.getClientInitialAccess` | → `ClientInitialAccessResource` |
| `/admin/realms/{realm}/client-registration-policy` | (locator) | auth | `RealmAdminResource.getClientRegistrationPolicy` | → `ClientRegistrationPolicyResource` |
| `/admin/realms/{realm}/components` | (locator) | auth | `RealmAdminResource.getComponents` | → `ComponentResource` |
| `/admin/realms/{realm}/client-policies/policies`, `/client-policies/profiles`, `/client-types` | (locator) | auth + feature gate | `RealmAdminResource` | |

### 5d. Roles & groups

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/admin/realms/{realm}/roles` | GET, POST | `auth.roles()` | `RoleContainerResource.getRoles / createRole` | |
| `/admin/realms/{realm}/roles/{role-name}` | GET, PUT, DELETE | `auth.roles()` | `RoleContainerResource.getRole / updateRole / deleteRole` | |
| `/admin/realms/{realm}/roles-by-id` | (locator) | auth | `RealmAdminResource.rolesById` | → `RoleByIdResource` |
| `/admin/realms/{realm}/groups` | GET, POST | `auth.groups()` | `GroupsResource.getGroups / createGroup` | **RISK: dynamic query** — `searchQuery` → `searchGroupsByAttributes` |
| `/admin/realms/{realm}/groups/{group-id}` | (locator) | `auth.groups()` | `GroupsResource.getGroupById` | → `GroupResource` |
| `/admin/realms/{realm}/group-by-path/{path}` | GET | `auth.groups()` | `RealmAdminResource.getGroupByPath` | |
| `/admin/realms/{realm}/default-groups` | GET | `auth.realm()` | `RealmAdminResource.getDefaultGroups` | |
| `/admin/realms/{realm}/default-groups/{groupId}` | PUT, DELETE | `auth.realm().requireManageRealm()` | `RealmAdminResource.{add,remove}DefaultGroup` | |

### 5e. Identity providers

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/admin/realms/{realm}/identity-provider/instances` | GET, POST | `auth.realm()` | `IdentityProvidersResource.getIdentityProviders / create` | |
| `/admin/realms/{realm}/identity-provider/instances/{alias}` | (locator) | auth | `IdentityProvidersResource.getIdentityProvider` | → `IdentityProviderResource` |
| `/admin/realms/{realm}/identity-provider/import-config` | POST | `auth.realm().requireManageIdentityProviders()` | `IdentityProvidersResource.importFrom / importFromUrl` | **RISK: SSRF candidate** (`fromUrl` form param fetched server-side); **RISK: XML processing** (SAML metadata) |
| `/admin/realms/{realm}/identity-provider/upload-certificate` | POST | `auth.realm()` | `IdentityProvidersResource.uploadCertificate` | PEM parsing |

### 5f. Organizations / workflows / OID4VC

| Endpoint pattern | HTTP methods | Auth required | Handler class:method | Notes |
|---|---|---|---|---|
| `/admin/realms/{realm}/organizations` | GET, POST | `auth.orgs()` | `OrganizationsResource.search / create` (services/src/main/java/org/keycloak/organization/admin/resource/OrganizationsResource.java:114, 150) | **RISK: URL param** `organization.redirectUrl` → `OrganizationsValidation.validateUrl`; **RISK: dynamic query** via `searchQuery` |
| `/admin/realms/{realm}/organizations/{org-id}` | (locator) | `auth.orgs()` | `OrganizationsResource.get` | → `OrganizationResource` (members, identity providers, groups, invitation) |
| `/admin/realms/{realm}/organizations/count` | GET | `auth.orgs().requireQuery()` | `OrganizationsResource.getOrganizationCount` | |
| `/admin/realms/{realm}/organizations/members/{member-id}/organizations` | GET | `auth.orgs()` | `OrganizationsResource.getOrganizations` | |
| `/admin/realms/{realm}/workflows` | (locator) + GET, POST, PUT, DELETE | auth (check unclear) | `WorkflowsResource`, `WorkflowResource` (services/src/main/java/org/keycloak/workflow/admin/resource/) | **Auth check unclear in source**; verify before reporting |

---

## 6. Consolidated risk callouts

### 6.1 RISK: redirect / URL parameter (open redirect, SSRF-adjacent, phishing)

OIDC / browser flows
- `redirect_uri`, `post_logout_redirect_uri` — `AuthorizationEndpoint`, `LogoutEndpoint`, `LoginActionsService.resetCredentialsGET` (LoginActionsService.java:445)
- `request_uri` — `AuthorizationEndpoint` and `ParEndpoint` (PAR / JAR), fetched server-side
- `referrer`, `referrer_uri` — `AccountConsole.getReferrer` (AccountConsole.java:284) → `RedirectUtils.verifyRedirectUri`
- `redirectUri` — `LinkedAccountsResource.buildLinkedAccountURI` (LinkedAccountsResource.java:255) — **deprecated** but still live
- `redirect_uri`, `nonce`, `hash` — `IdentityBrokerService.clientInitiatedAccountLinking` (IdentityBrokerService.java:221) — **deprecated**

Admin user-driven email/link flows
- `redirect_uri` in `UserResource.sendVerifyEmail`, `sendExecuteActionsEmail`, `sendResetPasswordEmail`

OIDC postMessage iframe
- `origin`, `client_id` — `LoginStatusIframeEndpoint.preCheck`

Theme / account
- `theme` — `ThemeResource.getLocalizationTexts` (ThemeResource.java:199)
- `name` — `AccountRestService.applications`, `ResourcesService.getResources`
- `value` — `ResourceService.user` (lookup)

Organization admin
- `organization.redirectUrl` — `OrganizationsResource.create` (OrganizationsResource.java:114)

### 6.2 RISK: XML processing — XXE / XSW candidate

- `SamlService.redirectBinding` / `postBinding` (SamlService.java:929) — `SAMLRequest`, `SAMLResponse`
- `SamlService.artifactResolution` (SamlService.java:1112) — SOAP envelope + artifact resolve
- `SamlEcpProfileService.handleEcpRequest` — SOAP message
- `SamlService.getDescriptor` (SamlService.java:952) and IdP metadata generators
- `EntityDescriptorClientRegistrationProvider` (`/clients-registrations/saml2-entity-descriptor`)
- `RealmAdminResource.convertClientDescription` (RealmAdminResource.java:179) — accepts `application/xml`
- `IdentityProvidersResource.importFrom / importFromUrl` — SAML metadata XML
- Identity-provider broker callbacks for SAML providers (`broker/{alias}/endpoint/...`)

### 6.3 RISK: SSRF candidate (server-side fetch of attacker-influenced URL)

- `request_uri` (PAR / JAR) — `ParEndpoint`, `AuthzEndpointRequestObjectParser`
- `client_assertion` JWT — `jwks_uri` lookup via `JWKSHttpUtils`
- Backchannel CIBA — `HttpAuthenticationChannelProvider`
- IdP metadata — `SamlMetadataPublicKeyLoader`
- Admin: `IdentityProvidersResource.importFromUrl` (admin-controlled but still SSRF-shaped)
- Admin: `RealmAdminResource.pushRevocation` and `testSMTPConnection`
- Admin: `ClientResource.getInstallationProvider` (provider-dependent)
- Dynamic client registration: client metadata `jwks_uri`, `request_uris` later fetched
- Identity broker callbacks with token-exchange — outbound HTTP to IdP token endpoint

### 6.4 RISK: dynamic query construction

- Admin search endpoints with `searchQuery` (Keycloak's attribute search DSL):
  - `UsersResource.getUsers` — `searchForUserStream`
  - `ClientsResource.getClients` — `searchClientByAttributes`
  - `GroupsResource.getGroups` — `searchGroupsByAttributes`
  - `OrganizationsResource.search` — `provider.getAllStream(attributes)`
- `RealmsResource.resolveRealmExtension` (services/src/main/java/org/keycloak/services/resources/RealmsResource.java:277) — RealmResource SPI dispatch by string
- `RealmsResource.getWellKnown` — provider alias dispatch
- `OIDCLoginProtocolService.resolveExtension` (OIDCLoginProtocolService.java:246) — extension dispatch

### 6.5 RISK: info disclosure (mgmt:9000)

- `/`, `/health`, `/metrics`, `/openapi`, `/openapi/ui` — all unauthenticated by default. Metrics URI tag may leak realm names.

### 6.6 RISK: path traversal candidate

- `WelcomeResource.getResource` — `/welcome-content/{path}` (WelcomeResource.java:175)
- `ThemeResource.getResource` — `/resources/{version}/{themeType}/{themeName}/{path}` (ThemeResource.java:91)

---

## 7. Endpoints reachable without authentication

The complete list of endpoints anonymous network reach can hit. Most enforce
auth *inside* the protocol flow (signature, action token, code-grant code,
etc.) — "no network auth" does not mean "free entry to the underlying
operation" in those cases.

**Bootstrap / static / metadata**
- `GET, POST /` (POST creates initial admin if none exists)
- `GET /welcome-content/{path}`
- `GET /lb-check`
- `GET, OPTIONS /.well-known/{provider}/realms/{realm}`
- `GET /resources/{version}/{themeType}/{themeName}/{path}`
- `GET, OPTIONS /resources/{realm}/{themeType}/{locale}`
- `GET, OPTIONS /realms/{realm}`
- `GET, OPTIONS /realms/{realm}/.well-known/{provider}`
- `GET /realms/{realm}/clients/{client_id}/redirect`
- All `[mgmt:9000]` routes

**OIDC public endpoints**
- `GET, POST /realms/{realm}/protocol/openid-connect/auth`
- `GET, OPTIONS /realms/{realm}/protocol/openid-connect/certs`
- `GET /realms/{realm}/protocol/openid-connect/login-status-iframe.html` and `/init`
- `GET /realms/{realm}/protocol/openid-connect/3p-cookies/step1.html`, `step2.html`
- `GET /realms/{realm}/protocol/openid-connect/oauth/oob`
- `GET /realms/{realm}/protocol/openid-connect/forgot-credentials`
- `POST /realms/{realm}/protocol/openid-connect/ext/ciba/auth/callback` (auth_req_id authenticates)

**SAML public endpoints**
- `GET, POST /realms/{realm}/protocol/saml`
- `GET /realms/{realm}/protocol/saml/descriptor`
- `GET /realms/{realm}/protocol/saml/clients/{client}`
- `POST /realms/{realm}/protocol/saml/resolve`
- `POST /realms/{realm}/protocol/saml/ecp`

**Login actions (entry points)**
- `GET /realms/{realm}/login-actions/restart`
- `GET /realms/{realm}/login-actions/detached-info`
- `GET, HEAD /realms/{realm}/login-actions/action-token` (signed token is the auth)
- `GET, POST /realms/{realm}/login-actions/reset-credentials`
- `GET, POST /realms/{realm}/login-actions/registration`

**Brokering**
- `GET, POST /realms/{realm}/broker/{provider_alias}/login`
- `/realms/{realm}/broker/{provider_alias}/endpoint/...` (provider-defined; SAML POST/Redirect, OIDC code/token)

**Account console (HTML shell)**
- `GET /realms/{realm}/account/`, `/index.html`, `/{path:.*}` (HTML shell — the JSON API beneath requires bearer)

---

## 8. Top-priority targets for vuln research

Ten that are worth opening first, with the angle that makes each interesting:

1. **`/protocol/saml`** (POST + Redirect bindings) — XXE, XSW, signature bypass, audience/destination handling.
2. **`/protocol/saml/resolve`** — artifact dereference, SOAP+SAML XML.
3. **`/protocol/openid-connect/ext/par/request`** — `request_uri` SSRF, JWT key resolution, TTL handling.
4. **`/protocol/openid-connect/auth`** — redirect_uri validation, `request` / `request_uri` JAR, `prompt=none` / silent flows, response_mode=`form_post.jwt`.
5. **`/broker/{alias}/endpoint/...`** — SAML and OIDC IdP callback handlers, account-linking and first-broker-login flow joins.
6. **`/login-actions/reset-credentials`** + **`/login-actions/action-token`** — action-token signature/scope/replay, redirect_uri pivot.
7. **`/clients-registrations/saml2-entity-descriptor`** + **`/clients-registrations/openid-connect`** — XXE on SAML descriptor; SSRF via metadata `jwks_uri` / `request_uris` pulled later.
8. **`/admin/.../client-description-converter`** + **`/admin/.../identity-provider/import-config`** + **`/admin/.../testSMTPConnection`** — admin-side XXE and SSRF triplet.
9. **`/realms/{realm}/account/{path:.*}`** + `LinkedAccountsResource.buildLinkedAccountURI` — referrer / redirectUri verification, deprecated linking flow.
10. **`/admin/realms/{realm}/users/{id}/{sent-registration-link,execute-actions-email,reset-password-email}`** — admin-triggered emails carrying user-supplied `redirect_uri` to action tokens.

---

*Generated 2026-05-07 from source-tree audit. Cross-reference each entry
against the live container before acting on a finding — endpoints can move
between releases.*
