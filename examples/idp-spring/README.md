# Tokido Identity — Example IdP (Spring Boot)

A minimal IdP that serves OIDC discovery + JWKS. **v0.1 serves discovery and
JWKS only**; `/authorize`, `/token`, `/userinfo` return `501 Not Implemented`
until later increments. Not published to Maven Central — build and run from
source.

## Run

```bash
mvn -pl examples/idp-spring -am spring-boot:run
```

## Try it

```bash
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/jwks
```

## Configuration

| Property | Required | Notes |
|----------|----------|-------|
| `tokido.identity.issuer` | yes | Base URL; drives advertised endpoint URLs. |
| `tokido.identity.dev-keys` | no | Use the ephemeral dev key. This example instead pins a key via `ExampleKeyConfig` for a stable `kid`. |

The committed `dev-*.pem` files are a **dev-only** pinned key for reproducibility.
Never use them in production.
