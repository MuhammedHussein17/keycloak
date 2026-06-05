# CVE-2026-9794 — Keycloak SAML ECP Client Enumeration

Security research leading to CVE-2026-9794 (CVSS 5.3, Medium).

## Summary
Unauthenticated client ID enumeration via SAML ECP faultstring oracle
in Keycloak 2.0 through 26.6.1. Fixed in 26.6.3.

## Findings
- VULN-001: Client ID enumeration (CVE-2026-9794) ✅ Fixed
- VULN-002: Response format oracle — #49022
- VULN-003: Version fingerprinting
- VULN-004: SSRF via request_uri — Fixed in 26.6.1

## Researcher
Muhammed Hussein & Asaad Mostafa
