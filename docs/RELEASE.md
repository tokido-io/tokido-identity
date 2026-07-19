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

## Owner handover checklist (one-time, manual — only the owner can do these)
1. Claim the `io.tokido` namespace on the Sonatype Central Portal; verify ownership.
2. Generate a GPG key; publish the public key to a keyserver.
3. Add CI secrets: `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD` (Central Portal user token), `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`.

## Tombstone check (run before the first release)
Check whether any retired `tokido-core-*` artifacts were ever published:
```bash
curl -s https://repo1.maven.org/maven2/io/tokido/ | grep -o 'tokido-core-[^/"]*' | sort -u
# or browse https://central.sonatype.com/namespace/io.tokido
```
If any `tokido-core-*` directory exists, publish one final deprecation release of that artifact whose POM `<description>` points to `io.tokido:tokido-identity-*`. If none, skip.

## Note: autoPublish is false
The first real release stages a VALIDATED bundle on the Central Portal for manual
inspection before release (coordinates are immutable). Promote it from the portal UI.
