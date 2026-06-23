/**
 * The framework-free, deterministic OIDC protocol engine and its pipelines
 * (authn, grant, claims, events). Calls injected storage SPIs synchronously;
 * no HTTP, no DI, no framework imports (ArchUnit-enforced).
 */
package io.tokido.identity.engine;
