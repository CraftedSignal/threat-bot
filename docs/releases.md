# Releases and publication

Preparing a useful source tree, publishing a supported artifact, changing repository visibility, and rolling out production are separate actions. This repository contains release automation; its presence is not evidence that a hosted release has run or that a container was published.

## Version and compatibility

Development builds report their version/revision through `threat-bot version`. Release tags use `vMAJOR.MINOR.PATCH`; pre-1.0 releases can change behavior with explicit notes. Review CLI/configuration, database migrations, feed protocol, shared Go APIs, and provider compatibility separately. Preserve feed identities and consumer contracts or provide a tested migration.

Only claim supported platforms actually built and tested. The initial workflow target is **Linux amd64**. See [SUPPORT.md](../SUPPORT.md) for maintenance scope; no v1 stability or indefinite backport commitment is implied.

## Source publication gate

Before publishing a prepared snapshot:

1. Select the exact reviewed commit and dependency graph; preserve copyright, attribution, and source provenance. Confirm the precise first-party AGPL grant with its rights holder without changing the existing license silently.
2. Export only the reviewed tracked tree. Exclude runtime material and private work reports; scan the exact exported source/archive and review every finding. Retain historical material privately unless separately reviewed for disclosure.
3. Verify a clean single-checkout build and default tests without credentials, private dependencies, or sibling repositories. Check examples, local links, and the synthetic first-run path.
4. Configure and verify repository rules, stable required checks, security reporting, dependency/secret scanning, fork-safe CI, release authority, and the permitted pinned Actions. CODEOWNERS and policy prose do not enforce these settings.
5. Review the exact visibility/identity changes and obtain the owner's authorization. Verify anonymous access and a genuine external fork check after launch.

Publication of a new source snapshot does not sanitize old Git objects, PRs, Actions logs, caches, or container layers. Do not mirror historical refs or advertise old images as audited release artifacts.

## Artifact release gate

The release workflow runs on a semantic-version tag whose commit is reachable from main. It reuses mandatory CI, builds the binary/source archives and Linux amd64 image, smoke-tests the image, scans artifacts, generates SPDX SBOMs and checksums, and publishes through the `public-release` environment with GitHub provenance attestations. Protect tags and configure that environment's reviewers/branch rules; the YAML alone cannot enforce an unconfigured environment.

An existing GitHub release or versioned container image blocks publication for that version. The guard also stops on API/authentication/network uncertainty and requires any existing container package to be linked to this repository's immutable ID. It must not inherit ownership from a historical package with the same name. If a run stops after pushing an image, use reviewed recovery or a new version; rerunning must not overwrite the version tag. Hosted API/token behavior remains a release integration check until observed in a real run.

Before advertising the result, inspect the completed run and exact artifacts. Confirm the source commit, toolchain, dependency versions, image digest, licenses/notices, scan dispositions, and attested workflow identity. Run `make licenses-check` and review the [notice index](../NOTICE.md), actual dependency inventory, embedded Go/time-zone attribution, and [TLS trust-store source](../LICENSES/runtime/certificates/README.md). Confirm the release archives/image contain the collected `LICENSES` tree and that the certificate source archive remains available; retain the exact source with release records. SBOM generation is an inventory step, not legal approval or a guarantee of vulnerability absence. License uncertainties and unreviewed notices block supported distribution.

Release notes must include user-visible changes, upgrade/rollback instructions, known limitations, supported platforms/providers, and verification instructions. A release is not a production deployment; use an immutable digest/source revision in the separately reviewed infrastructure rollout.

## Verify an actual release

After a release exists, download its archive, checksums, and provenance using GitHub's tooling. For example, replacing the version with an actual published tag:

```sh
gh release download v0.1.0 --repo CraftedSignal/threat-bot --dir release-v0.1.0
cd release-v0.1.0
sha256sum --check checksums.txt
gh attestation verify threat-bot_v0.1.0_linux_amd64.tar.gz --repo CraftedSignal/threat-bot
```

On macOS, `shasum -a 256 -c checksums.txt` provides the checksum check. Verify attestations for the source archive, SBOMs, and digest record as well. Inspect the verified statement: the expected signer is this repository's `.github/workflows/release.yml`, and the source commit must match the reviewed tag. A checksum downloaded beside an artifact alone does not authenticate its producer.

For a container, use the full immutable image reference in `image-digest.txt`:

```sh
gh attestation verify "oci://$(cat image-digest.txt)" --repo CraftedSignal/threat-bot
```

Then pull/run that same digest and check `version`. Do not replace it with a mutable tag during deployment. Attestation verification needs network and a compatible authenticated GitHub CLI where GitHub requires it. These are the intended checks for published artifacts, not a claim that a particular tag or digest already exists.
