# Development

Use Go **1.27.4** (the current pinned build toolchain), Python 3, Git, and Make. Docker or a compatible engine is needed only for container checks. The Go module is self-contained: no private sibling checkout, cloud identity, or model is needed for the default tests.

```sh
make build
make test
make test-race
make vet
make docs-check
```

Install the exact tool versions declared in the Makefile before running the complete local gate:

```sh
make tools
make check
```

`make check` enforces formatting, race tests, vet/build, configured static analysis, workflow validation, docs/examples, dependency license inventory, dependency vulnerabilities, and a redacted secret scan. Tool installation and dependency/vulnerability downloads need network. Missing tools and failures are errors. Run `make docker-smoke` separately when changing packaging; its offline config/version checks are not a live provider test.

## Deterministic first-run regression

```sh
go test ./cmd/threat-bot -run TestFirstRunFixtureCreatesDraftAndSurvivesRestart -count=1 -v
go test ./internal/eval -run TestEvalGate -count=1 -v
```

The first test uses synthetic source/model responses with the real runner, pipeline, SQLite, and draft commands. The second verifies the extractor replay/scoring contract. Both are credential-free. Tests that explicitly opt into live providers are separate and may cost money; inspect their opt-in variables and network requirements before running them. Passing replay is not a live-model qualification.

## Making changes

New scrapers should implement the existing source interface, normalize stable source IDs/timestamps, bound downloads and timeouts, honor rate limits, and use the safe transport for content-derived URLs. Exercise parsing with small sanitized fixtures and failure paths. Do not silently mark items seen when durable writes fail.

New model integrations should implement the existing LLM interface, preserve context cancellation and bounded responses, redact diagnostics, and make live tests opt-in. Provider-specific configuration must fail clearly when incomplete.

Publisher changes need identity/revision compatibility tests, complete-artifact validation, failure/retry tests, and regression sentinels at projection boundaries. Consumers should share `pkg/publicfeed`, `pkg/ioc`, and `pkg/mitre`; do not fork their rules. Document intentional protocol changes in an ADR and release notes.

Dependency changes must include provenance/license review, checksums, and vulnerability review for the actual released graph. Run `make licenses` with the pinned Go toolchain, review the copied upstream notices and inventory changes, then run `make licenses-check`. CI checks this same Linux amd64 binary graph, including embedded Go/time-zone notices. A missing source license fails the check. Container builder changes also require a fresh review of [certificate provenance](../LICENSES/runtime/certificates/README.md); the checker deliberately does not invent updated certificate evidence. Review unknown license classifications rather than blanket-allowing them. Keep temporary generated state, secrets, databases, private reports, and agent scratch files out of the publication tree.

See [CONTRIBUTING.md](../CONTRIBUTING.md), [evaluation](evaluation.md), and [release gates](releases.md).
