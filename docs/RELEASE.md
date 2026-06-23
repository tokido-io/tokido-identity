# Release runbook (0.x)

## One-time setup (do during Phase 0)
1. Claim the `io.tokido` namespace on the Sonatype Central Portal; verify domain/GitHub ownership.
2. Generate a GPG signing key; publish the public key to a keyserver; store the private key + passphrase as CI secrets (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`).
3. Configure the `release` profile (gpg + central-publishing plugin); run a throwaway publish of `tokido-identity-bom` to confirm the pipeline end-to-end.

## Tombstone for retired tokido-core-* artifacts
If `tokido-core-*` was published to Central, publish one final version whose README/POM `<description>` states it is deprecated in favor of `io.tokido:tokido-identity-*`. Maven coordinates are immutable; this is the only migration signal.

## Per-release (per 0.x increment)
1. Bump `tokido.version` (parent property) to `0.x.0`.
2. `mvn -P release deploy` from the tagged commit; tag `v0.x.0`.
3. Add the increment's new modules to `tokido-identity-bom` only if they have real content.
4. Return parent to `0.(x+1).0-SNAPSHOT`.
