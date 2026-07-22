# Tokido Identity — Example IdP (Spring Boot)

A minimal IdP that serves OIDC discovery + JWKS and issues **`client_credentials`**
access tokens. `/authorize` and `/userinfo` return `501 Not Implemented` until later
increments. Not published to Maven Central — build and run from source.

## Run

```bash
mvn -pl examples/idp-spring -am spring-boot:run
```

## Try it

Discovery and JWKS:

```bash
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/jwks
```

### Client credentials

The example registers a demo confidential client (`ExampleClientConfig`):

| Field | Value |
|-------|-------|
| `client_id` | `demo-client` |
| `client_secret` | `demo-secret` (DEV ONLY — well-known literal) |
| grant | `client_credentials` |
| scopes | `read`, `write` |
| auth methods | `client_secret_basic`, `client_secret_post` |

Request a token with **HTTP Basic** (`client_secret_basic`):

```bash
curl -u demo-client:demo-secret \
  -d grant_type=client_credentials \
  -d scope=read \
  http://localhost:8080/token
```

Or with credentials in the body (`client_secret_post`):

```bash
curl -d grant_type=client_credentials \
  -d client_id=demo-client \
  -d client_secret=demo-secret \
  -d 'scope=read write' \
  http://localhost:8080/token
```

Response (RFC 6749 §5.1), served with `Cache-Control: no-store`:

```json
{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600,"scope":"read"}
```

Decode the access token (a signed JWS) — the payload carries `iss`, `sub`,
`client_id`, `iat`, `exp`, a unique `jti`, `scope`, and `aud`:

```bash
TOKEN=$(curl -s -u demo-client:demo-secret \
  -d grant_type=client_credentials -d scope=read http://localhost:8080/token \
  | sed -E 's/.*"access_token":"([^"]+)".*/\1/')
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

The token is signed with the key published at `/jwks` (matching `kid`), so any
resource server can verify it against this issuer's JWKS.

Bad credentials return `401` with `WWW-Authenticate: Basic` (Basic) or `400`
(post), body `{"error":"invalid_client"}`. Requesting a scope the client is not
allowed returns `{"error":"invalid_scope"}`.

## Configuration

| Property | Required | Notes |
|----------|----------|-------|
| `tokido.identity.issuer` | yes | Base URL; drives advertised endpoint URLs. Use a host-root issuer — the adapter serves endpoints at root, so a path-bearing issuer (e.g. `https://host/auth`) would advertise URLs the adapter doesn't serve. |
| `tokido.identity.dev-keys` | no | Use the ephemeral dev key. This example instead pins a key via `ExampleKeyConfig` for a stable `kid`. |
| `tokido.identity.access-token-ttl` | no | Access-token lifetime (ISO-8601 duration); default `PT1H`. |
| `tokido.identity.token-audience` | no | Access-token `aud`; defaults to the issuer. |

The committed `dev-*.pem` files are a **dev-only** pinned key for reproducibility.
The demo client secret is a **dev-only** literal. Never use either in production.
