# macOS Signing and Notarization

## Status

The Intel and Apple Silicon packages compile in native GitHub runners, but they are not Developer ID signed, notarized, stapled, or approved for production installation.

## Controlled process

1. Build each architecture on the matching protected macOS runner with deterministic version metadata.
2. Sign the agent with an organization-owned `Developer ID Application` identity and hardened runtime. Sign any package wrapper with the appropriate installer identity if a `.pkg` is introduced.
3. Submit the exact signed artifact to Apple notarization using protected App Store Connect credentials, wait for success, and retain the notarization request/log ID.
4. Staple the ticket and repackage; regenerate SHA-256/build identity because bytes changed.
5. Verify independently on macOS:

```bash
./agent/scripts/verify-macos-signing.sh \
  ./nextaura-agent-darwin-arm64.tar.gz \
  <64-hex-package-sha256>
```

The verifier runs strict `codesign`, Gatekeeper `spctl`, and stapler validation and emits signer/team evidence. Do not bypass Gatekeeper, SIP, or TCC.

## Missing prerequisites

- Apple Developer team and protected Developer ID identities.
- App Store Connect/notary credentials stored outside the repository.
- Hardened-runtime entitlement review.
- Disposable native Intel and Apple Silicon installation endpoints.
- Native LaunchDaemon install, enrollment, restart, upgrade, and uninstall evidence.
