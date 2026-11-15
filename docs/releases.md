# Releases and publication

Pushes to `main` automatically select a version and release after CI passes, without a separate approval. GoReleaser builds the binary and source archives; the publishing job publishes the verified artifacts and `ghcr.io/craftedsignal/threat-bot` image. Manual version tags are also supported. Repository visibility and production deployment are managed separately.

## Version and compatibility

Development builds report their version/revision through `threat-bot version`. Release tags use `vMAJOR.MINOR.PATCH`, starting at `v0.1.0`. Commits since the highest stable ancestor tag determine the next version: `feat:` or `feat(scope):` increments minor; a `!` in a Conventional Commit header or a `BREAKING CHANGE:` footer increments major; other changes increment patch. A retry reuses a tag already on that commit, and published versions cannot be overwritten. Review CLI/configuration, database migrations, feed protocol, shared Go APIs, and provider compatibility separately. Preserve feed identities and consumer contracts or provide a tested migration.

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

The release workflow runs on main pushes or manual semantic-version tags. It calls mandatory CI once, selects a version, builds GoReleaser archives and a Linux amd64 image, smoke-tests the image, scans artifacts, generates SPDX SBOMs and checksums, and publishes through the `public-release` environment with GitHub provenance attestations. PRs run CI before merging; main pushes run CI only through Release, avoiding a duplicate standalone run. The selected tag must point to the validated source commit on main and is created during publication if needed. A single release concurrency group serializes publication. The environment permits `main` and version tags without manual reviewers; its policy is managed in the organization's GitHub configuration.

An existing GitHub release or versioned container image blocks publication for that version. The guard also stops on API/authentication/network uncertainty and requires any existing container package to be linked to this repository's immutable ID. It must not inherit ownership from a historical package with the same name. If a run stops after pushing an image, use reviewed recovery or a new version; rerunning must not overwrite the version tag. Hosted API/token behavior remains a release integration check until observed in a real run.

Before advertising the result, inspect the completed run and exact artifacts. Confirm the source commit, toolchain, dependency versions, image digest, scan results, and attested workflow identity. Archives include the binary, project license, and example configuration. Review upstream distribution terms when preparing artifacts.

Release notes must include user-visible changes, upgrade/rollback instructions, known limitations, supported platforms/providers, and verification instructions. A release is not a production deployment; use an immutable digest/source revision in the separately reviewed infrastructure rollout.

`image-digest.txt` contains the immutable GHCR image reference. The attested `release-record.json` records its version, full source revision, image digest, platform, repository, and producing workflow. Infrastructure consumes that image by digest; where Artifact Registry is required, mirror the same image bytes instead of rebuilding source.

## Check packaging locally

Install the pinned tools with `make tools`, then run:

```sh
make release-check
make release-snapshot
```

The snapshot command builds Linux amd64 binary/source archives and checksums under `dist/goreleaser/` without creating tags or publishing. CI also runs the packaged binary's version and offline configuration checks on Linux.

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
