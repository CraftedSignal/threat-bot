# Architecture

threat-bot is a Go process with SQLite persistence and optional GitHub publication. Adapters under [internal/scraper](../internal/scraper) produce normalized source items. The [pipeline](../internal/pipeline) combines deterministic evidence checks with model-assisted extraction and brief assembly. It correlates source URLs, CVEs, content, and incident identity to avoid treating every update as a new event.

The workflow is fetch → evidence/quality → extraction → enrichment/correlation → grounding/schema validation → draft → publication. Some sources are contextual signals rather than authoritative evidence. Public-social claims carry likelihood, gaps, and corroboration; an enthusiastic post alone is not confirmation.

## Durable state

[SQLite storage](../internal/storage) holds drafts, seen-state, polling state, source replay material, cached model responses, quarantined output, publication queues, and related indexes. A database is part of the application's state, not disposable cache. Publication can update a remote repository before the local completion record is saved; retry and reconciliation logic therefore matter as much as successful writes.

The publisher constructs a complete release of related feed artifacts and uses a Git tree/commit/ref update for coordinated publication. Queue state is retained across failures so a process restart can retry. Stable brief IDs, canonical slugs, event IDs, and revisions have different roles; changing identity requires the correction/retirement workflow instead of an arbitrary filename edit.

## Modules and extension points

| Package | Responsibility |
| --- | --- |
| `cmd/threat-bot` | CLI, lifecycle, service wiring, draft operations |
| `internal/scraper` | Source adapters, polling, social resolution |
| `internal/pipeline` | Extraction, correlation, grounding, assembly |
| `internal/llm` | Ollama/Vertex clients, cache, batch, provider health |
| `internal/storage` | SQLite schema and durable transitions |
| `internal/publisher` | Feed segments, Markdown, STIX, Git transactions |
| `pkg/ioc`, `pkg/mitre`, `pkg/publicfeed` | Shared validation and lookup contract for producer/consumers |
| `internal/eval` | Dataset grouping, replay, extraction scoring |

The shared public packages live in this module so a single checkout builds. Their [provenance](../pkg/PROVENANCE.md) records imported source and transformations. Future feed consumers should reuse these packages rather than fork validator behavior. Public placement does not imply a v1 API stability promise.

`pkg/publicfeed` owns the deterministic narrative and action-plan readiness contract used by pipeline review and public-feed validation. Model-assisted evidence assessment remains in the pipeline. Keeping these checks separate prevents a structurally valid but incomplete brief from bypassing the final publication gate.

## Boundaries

Fetched text and model output are untrusted data. Structural validity does not establish truth, and grounding checks cannot guarantee correctness. The public Markdown field filter is separate from the bundle wrapper and STIX exporter. Each output surface needs its own disclosure review. See [security model](security-model.md), [feed protocol](feed-protocol.md), and the reviewed [decisions](adr/README.md).
