# Harvest reference — auth-server (Quarkus) → tokido-identity-engine

Read-only snapshot of the working Quarkus OIDC provider's OAuth logic. NOT compiled.
Port the *logic* (framework-agnostic), not the JAX-RS/Quarkus plumbing.

| Source | Ports into (increment) |
|--------|------------------------|
| AuthorizeResource.java     | engine.authorize() + authn pipeline (v0.3) |
| TokenResource.java         | grant handlers: client_credentials (v0.2), auth_code+PKCE (v0.3), refresh (v0.4) |
| JwtService.java            | default Nimbus TokenSigner (v0.1) |
| RedirectUriValidator.java  | exact redirect_uri matching (v0.3) |
| OidcResource.java          | discovery + jwks (v0.1) |
| AuthCode.java              | GrantStore code model (v0.3) |
