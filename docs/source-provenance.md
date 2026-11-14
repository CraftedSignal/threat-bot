# Source provenance

The initial public repository is a curated source import, with independent Git history. The original historical repository remains private. The preparation baseline was application commit `d0b4befa5c8a5d51740ac193939d1a8dffe3cb8b`; the public preparation includes the changes described in [CHANGELOG.md](../CHANGELOG.md). Subsequent committed quality and processing changes through `e0c9cafb6fd875f644e5b9c8154725cba6cd8a26` were integrated into the curated source before handoff; the original Git history is not imported into the public repository. The historical author names are retained in [AUTHORS.md](../AUTHORS.md), and existing source copyright notices remain intact.

The public source excludes runtime configuration, credentials, databases, local tools, private reports, and historical agent plans. Full third-party report excerpts and captured production/incident fixtures were replaced with original fictional evaluation data; their original upstream revision and hashes remain in [dataset provenance](../internal/eval/testdata/provenance.json). This boundary does not make an assertion about unpublished historical logs or artifacts.

The shared public packages have their own [import manifest](../pkg/PROVENANCE.md), upstream revision, hashes, and transformation record. The executable uses the versions in `go.mod` and `go.sum`; [dependency notices](../LICENSES/dependencies/manifest.json) and [runtime notices](../LICENSES/runtime/go/manifest.json) are checked against the supported build.

Selected follow-up first-party changes share narrative/action-plan readiness checks and retain bounded merge retries and durable editorial holds. The package manifest records the committed origin of the added readiness implementation and the fictional substitutions in its tests. It preserves the original feed import hashes alongside separate hashes for later adaptations. A local reliability adaptation in `internal/storage/merge_review.go` and the pipeline resume path commits quarantine visibility and one held-history record together, and repairs incomplete visibility without repeating assessment; its tests are original fictional fixtures. These curated changes do not import the historical repository's Git ancestry or captured production fixtures.

The public name is `threat-bot`. Persisted wire identifiers and production storage/identity names are compatibility boundaries; see [operations](operations.md). Production deployment source and the identity migration runbook belong in the separately managed infrastructure repository.

The bounded source-completeness follow-up is curated from first-party commit
`8c978278ab506cb3d9c2262401897488f9bc9f40`. Runtime policy, prompt and schema inputs
retain compatible processing keys; public regression inputs are fictional.
Supplemental evidence lookup failures use a fixed uncertainty category rather
than forwarding transport diagnostics into model input. This port also excludes
the historical Git ancestry, captured fixtures and internal planning files.

The final Sigma parser adoption follows first-party application commit
`2f91b308f590f17870ac6dc909642bc5b5c74606`, using the same pinned parser revision
`dc3a797a75a1`. Pipeline, publisher and shared Sigma checks retain warning-only
rules and reject parser limits and malformed authored values. The added
regressions use synthetic rules; processing schemas, policy keys, persisted
identifiers and checkpoint semantics are unchanged by this dependency adoption.
