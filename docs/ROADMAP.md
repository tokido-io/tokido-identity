# Tokido Identity — Roadmap

> A framework/SDK for building your own OIDC/OAuth 2.x identity provider in Java — pluggable, conformant, native-ready.

> **Status (2026-07-18): v0.1 released (`0.1.0`).** Discovery + JWKS served by a running Spring Boot IdP; RS256 signing; method-aware route table; optional dev keystore; OIDF discovery conformance + native-image smoke gating CI. **Next: v0.2 — `client_credentials`.**

This is the canonical roadmap for the project. It captures the direction, the locked decisions, the architecture, and the increment-by-increment plan from the first foundation through v1.0. Each `0.x` is an independently valuable, fully-tested slice; we build them in order, no skipping.

---

## What this is (and isn't)

Tokido Identity lets you build your own OIDC/OAuth provider (and a basic identity broker) **in code** — the way Duende IdentityServer does for .NET, for the Java ecosystem. You supply storage and authentication; the framework owns the protocol.

It is a **library/framework**, not a configure-and-run product like Keycloak. Its core value is an **extensible pipeline**: authentication, grant handling, claims, and events are plugin extension points on a framework-free, deterministic protocol engine.

**Differentiator vs. Spring Authorization Server** (the incumbent for "build your own OIDC in Java"): a uniform, fully pluggable pipeline — including pluggable grant types — and a framework-free core designed for native-image / serverless portability, not bound to one web stack.

## Locked decisions

| # | Decision |
|---|----------|
| D1 | Build-your-own OIDC/OAuth provider + basic broker **in code**. Core is **framework-free, dependency-injected, deterministic** (calls injected storage SPIs synchronously). |
| D2 | v1 anchor = authorization server **+** one upstream-OIDC federation path. |
| D3 | **Plugin system is the core value.** Four extension SPIs: `AuthnStep`, `GrantHandler`, `ClaimsEnricher`, `EventListener`. Built-in grants are themselves `GrantHandler`s with secure, non-trivially-overridable defaults. |
| D4 | Persistence = storage SPIs + in-memory **dev module** + a **JPA** module. |
| D5 | Login/consent = **sample, overridable** UI in the Spring adapter; engine stays headless. |
| D6 | Strict OAuth 2.x/OIDC compliance; standard endpoints only; **OIDF conformance run continuously in CI from v0.1**; pursue **OpenID Basic OP certification** at/after v1.0. |
| D7 | v1 protocol surface = core flows **+ introspection (RFC 7662) + revocation (RFC 7009)**. Logout/session-management deferred. |
| D8 | MFA deferred; returns post-v1 as `tokido-identity-plugin-mfa`. No standalone MFA library. |
| D9 | First framework adapter = **Spring Boot**. |
| D10 | OSS monorepo **`tokido-identity`**; single SemVer line + BOM; `groupId io.tokido`; Apache-2.0; Java 21; artifacts `tokido-identity-*`. |
| D11 | v1 ships **Spring Boot standalone only**; `tokido-identity-http` + stateless state + native rules provision FaaS/native/Knative for later. |
| D12 | Engine I/O = **synchronous injected stores** (fits standalone + Lambda/Azure/GCP/Knative; reactive out of scope). |
| D13 | Session = **hardened stateless cookie** (no `SessionStore`; logout = cookie clear). |

## Architecture (summary)

Three layers; core is framework-free and deterministic (no HTTP/DI/framework imports — ArchUnit-enforced; no `ServiceLoader`/reflection).

```
adapters/  spring-boot-starter (endpoints + DI discovery + sample UI), jpa (storage)
   │
tokido-identity-http   transport-neutral: HttpRequest → engine → HttpResponse
   │
tokido-identity-engine framework-free engine + pipelines (authn/grant/claims/events) + Nimbus signer
   │  SPIs
tokido-identity-api    Storage: ClientStore·UserStore·GrantStore·KeyStore·ConsentStore
                       Plugin:  AuthnStep·GrantHandler·ClaimsEnricher·EventListener
                       Signing: TokenSigner + protocol value types
```

**Module map**

| Family | Artifacts |
|--------|-----------|
| core | `tokido-identity-api`, `tokido-identity-engine`, `tokido-identity-http`, `tokido-identity-dev` (in-memory, dev-only), `tokido-identity-test` (fixtures) |
| adapters | `tokido-identity-spring-boot-starter`, `tokido-identity-jpa` |
| plugins | `tokido-identity-plugin-federation` (v1), `tokido-identity-plugin-mfa` (post-v1) |
| meta | `tokido-identity-bom`, `tokido-identity-conformance` (test-only), `examples/idp-spring` |

Plugins are plain beans registered via a programmatic `.register()` builder; the Spring starter discovers them from DI and registers them — no reflection. Interaction state (login/consent) is carried in a hardened, signed+encrypted `__Host-` cookie keyed from `KeyStore`, so any instance/function resumes statelessly.

## Increment roadmap

**Phase 0 — Foundation & wind-down** *(executed first; see the working plan under `docs/superpowers/plans/`)*: rename `tokido-core → tokido-identity`, single-version monorepo + BOM, core module skeleton, ArchUnit/native-smoke/conformance scaffolds, CI green; in the private repo, pause SaaS and reframe the site as the framework homepage; harvest the working `auth-server` OAuth logic as the porting reference.

Each increment below delivers working, tested software and runs OIDF conformance for its scope.

### v0.1 — Discovery / JWKS + signing
- **Deliver:** `KeyStore` (signing **and** cookie-encryption keys, `kid`, rotation) + default Nimbus `TokenSigner`; `DiscoveryDocument` (full required field set) at `/.well-known/openid-configuration`; `jwks_uri`; minimal Spring starter wiring; dev in-memory `KeyStore`.
- **Accept:** fetch valid, conformant discovery + JWKS; discovery conformance module green in CI; native-smoke + ArchUnit green.

### v0.2 — `client_credentials`
- **Deliver:** `/token`; client authentication (`client_secret_basic`/`_post`); access-token minting (`jti`, `aud`); scopes; `ClaimsEnricher` SPI (targeted per token); `GrantHandler` pipeline (no UI).
- **Accept:** a machine client receives a signed, scoped access token; token conformance modules green.

### v0.3 — Authorization Code + PKCE
- **Deliver:** authn pipeline + built-in password `AuthnStep`; interactive `/authorize` + sample login UI; ID token (`nonce`, `at_hash`, `auth_time`, `acr`); `GrantStore` (codes, atomic single-use); hardened stateless interaction+session cookie; S256-only PKCE + downgrade rejection; authorize error/redirect rules (+ `iss`, RFC 9207).
- **Accept:** full OIDC login end-to-end with a real client; code+PKCE+id_token conformance green.

### v0.4 — refresh_token + UserInfo
- **Deliver:** `refresh_token` (rotation + family reuse-detection; `scope ⊆ original`); `/userinfo` (Bearer + RFC 6750 errors, `sub` consistency); standard scope→claims mapper (`profile`/`email`/…); claims on ID token.
- **Accept:** complete user token lifecycle; refresh + userinfo conformance green.

### v0.5 — Consent
- **Deliver:** `ConsentRequired` + sample consent UI (CSRF + anti-clickjacking) + `ConsentStore` (remembered consent); auto-grant for first-party clients.
- **Accept:** third-party client consents once and skips on return; consent recorded.

### v0.6 — Plugin system + Events + DI discovery
- **Deliver:** finalize all four extension SPIs; programmatic `.register()` builder + Spring auto-discovery; `EventListener` pipeline (sync, ordered, failure-isolated); reserved-claim allowlist; a sample custom `GrantHandler` proving extensibility.
- **Accept:** a dropped-in plugin bean is live; events stream to a listener; custom grant works without touching core.

### v0.7 — Introspection + Revocation
- **Deliver:** `/introspect` (RFC 7662) + `/revoke` (RFC 7009); `GrantStore` revocation state + hooks; code-replay → token revocation.
- **Accept:** a resource server introspects tokens; a client revokes; introspection/revocation conformance green.

### v0.8 — JPA persistence
- **Deliver:** `tokido-identity-jpa` implementing all stores against the final (post-revocation) contract; schema + optional migration scripts (Postgres); Testcontainers integration tests; private keys encrypted at rest.
- **Accept:** the example app runs on Postgres and survives restart.

### v0.9 — Federation plugin
- **Deliver:** `tokido-identity-plugin-federation` — an `AuthnStep` delegating to an upstream OIDC IdP with mix-up defenses (`state`/`nonce`/PKCE/`iss` validation), JIT provisioning, no auto-link by unverified email.
- **Accept:** log in to your app through tokido via an upstream OIDC provider.

### v1.0 — Hardening + certification
- **Deliver:** OIDF conformance green; **apply for OpenID Basic OP certification**; security pass; docs + 10-minute "hello IdP" quickstart; CONTRIBUTING / SECURITY.md / governance; native-readiness verification.
- **Accept:** the whole v1 design, conformant, certified, documented.

## Deferred (post-v1)

RP-initiated / back-channel logout + session management; MFA plugin; `private_key_jwt`/mTLS client auth; native standalone runtime + FaaS adapters (Lambda/Azure/GCP); Quarkus adapter; reactive runtime support; richer resource/audience modeling; admin tooling; community plugin registry.

## Engineering ground rules

- Every increment ships **fully tested**; no increment is "done" without tests. TDD throughout.
- Single SemVer line; BOM grows per increment; never publish empty modules.
- During `0.x`: no API-stability promise (revapi report-only for a drift changelog); `-api` treated as soft-stable for plugin authors with breaks called out.
- Strict standards: standard endpoints only; secure-by-default (S256 PKCE, exact `redirect_uri`, refresh rotation + reuse-detection, asymmetric signing + rotation, hashed secrets, CSRF/anti-clickjacking on sample UI).
- Core stays framework-free (ArchUnit) and native-friendly (native-smoke in CI from v0.1).
