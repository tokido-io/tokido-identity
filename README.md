# Tokido Identity

A framework/SDK for building your own OIDC/OAuth 2.x identity provider in Java — pluggable, conformant, native-ready.

**Status: 0.x, pre-release.** See [docs/ROADMAP.md](docs/ROADMAP.md) for the full architecture, locked decisions, and increment-by-increment delivery plan.

[![CI](https://github.com/tokido-io/tokido-core/actions/workflows/ci.yml/badge.svg)](https://github.com/tokido-io/tokido-core/actions/workflows/ci.yml)
[![OIDC conformance](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/tokido-io/tokido-core/gh-pages/badges/conformance.json)](https://github.com/tokido-io/tokido-core/actions/workflows/oidc-conformance.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What it is

Tokido Identity lets you build your own OIDC/OAuth 2.x provider **in code** — the way Duende IdentityServer does for .NET, for the Java ecosystem. You supply storage and authentication; the framework owns the protocol.

It is a **library/framework**, not a configure-and-run product like Keycloak. Its core value is an extensible pipeline: authentication, grant handling, claims, and events are plugin extension points on a framework-free, deterministic protocol engine.

## Modules

### Published (current reactor)

| Artifact | Description |
|---|---|
| `tokido-identity-bom` | Bill of materials — import to align all artifact versions |
| `tokido-identity-api` | Contracts: SPIs, protocol value types, plugin interfaces. Zero runtime deps. |
| `tokido-identity-engine` | Framework-free, deterministic OIDC protocol engine + pipelines + default Nimbus signer |
| `tokido-identity-http` | Transport-neutral HTTP protocol layer: HttpRequest → engine → HttpResponse |
| `tokido-identity-dev` | In-memory store implementations. **DEV ONLY — not for production.** |
| `tokido-identity-test` | Test fixtures for framework and plugin authors |

`tokido-identity-conformance` is also in the reactor but is test-only and is never published.

### Planned (roadmap)

| Artifact | Description |
|---|---|
| `tokido-identity-spring-boot-starter` | Spring Boot adapter: endpoints, DI discovery, sample login/consent UI |
| `tokido-identity-jpa` | JPA persistence adapter for all storage SPIs |
| `tokido-identity-plugin-federation` | Upstream OIDC federation plugin (AuthnStep, v0.9) |

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full increment plan.

## Quick start (BOM)

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.tokido</groupId>
            <artifactId>tokido-identity-bom</artifactId>
            <version>0.1.0-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>io.tokido</groupId>
        <artifactId>tokido-identity-api</artifactId>
    </dependency>
    <dependency>
        <groupId>io.tokido</groupId>
        <artifactId>tokido-identity-engine</artifactId>
    </dependency>
</dependencies>
```

- `groupId`: `io.tokido`
- License: Apache 2.0
- Java: 21+

## Architecture

Three layers; core is framework-free and deterministic (no HTTP/DI/framework imports — ArchUnit-enforced; no `ServiceLoader`/reflection):

```
adapters/  spring-boot-starter (endpoints + DI + sample UI), jpa (storage)
   │
tokido-identity-http   transport-neutral: HttpRequest → engine → HttpResponse
   │
tokido-identity-engine framework-free engine + pipelines (authn/grant/claims/events) + Nimbus signer
   │  SPIs
tokido-identity-api    Storage: ClientStore · UserStore · GrantStore · KeyStore · ConsentStore
                       Plugin:  AuthnStep · GrantHandler · ClaimsEnricher · EventListener
                       Signing: TokenSigner + protocol value types
```

## Building

```bash
git clone https://github.com/tokido-io/tokido-core.git
cd tokido-core
mvn verify
```

Requires Java 21+ and Maven 3.9+.

## Parked modules

The original TOTP/recovery MFA library source is preserved under [`parked/`](parked/README.md) and will be reworked into `tokido-identity-plugin-mfa` post-v1. It is not part of the current build.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) — the canonical architecture, locked decisions, and per-increment delivery plan (v0.1 through v1.0).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
