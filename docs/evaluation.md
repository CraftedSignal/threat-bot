# Evaluation and fixtures

Default evaluation is a **deterministic contract regression**, not a model accuracy benchmark. The committed corpus contains twelve original fictional sentences grouped into four documents, in the existing TRAM-compatible `text`, `label`, and `doc_title` layout. Duplicate sentence labels exercise document-level set union.

`fixtures.json` contains manually authored responses keyed by the extractor prompt/system hash. No live model generated those responses. `baseline.json` requires base and exact macro/micro F1 of 1.0 for this small, deliberately perfect replay. A prompt change or missing response fails the gate; missing fixture files do not skip it.

```sh
go test ./internal/eval -run TestEvalGate -count=1 -v
```

The same gate also runs twelve fictional publication-contract cases through manual validation, public rendering/backfill, durable outbox/restart, and same-identity updates. It requires every case and route, checks both acceptance and rejection, and includes an authored repair response with an omitted body. See [brief quality safeguards](brief-quality-safeguards.md) and the [publication fixture notice](../internal/eval/testdata/brief_quality/NOTICE). Captured production snapshots and third-party incident records are excluded.

## What is scored

Records are grouped by document title. Predictions and gold labels become sets. Exact scoring retains sub-techniques; base scoring maps a sub-technique such as `T1059.001` to `T1059`. Macro scores aggregate document scores; micro scores pool label decisions. An extraction error counts as an empty prediction, so it reduces recall rather than disappearing from the report. The extraction replay does not measure factual grounding, source coverage, IOC correctness, or useful detection content. Publication cases check deterministic structural and editorial contracts, not the accuracy of a live model.

The [fixture notice](../internal/eval/testdata/NOTICE) and [machine-readable provenance](../internal/eval/testdata/provenance.json) record the original upstream commit/hashes, complete replacement, and current file hashes. The full `multi_label.json` was removed. Upstream Apache license/NOTICE are retained; report excerpts and their embedded credential-like text are not part of the candidate corpus.

## Live experiments

The evaluation CLI makes real model calls and writes a report:

```sh
go run ./cmd/eval -config config.yaml -dataset internal/eval/testdata/single_label.json -out output/eval-report.json
```

It scores base and exact extraction separately, which can make multiple inference passes. This tiny synthetic corpus is useful for smoke checks, not representative performance claims. Record the source revision, dataset hash, prompt revision, exact model/provider version, parameters, date, and cost when comparing runs.

To use a broader corpus, explicitly obtain and review [TRAM at the recorded upstream revision](https://github.com/center-for-threat-informed-defense/tram/tree/f29793d8d665f7f552898696e00065ef24a29a20/data/tram2-data), keep it outside the repository, and pass its `single_label.json` through `-dataset`. Check its provenance hashes and license and inspect it for sensitive content before sending excerpts to a provider. The upstream license does not certify every quoted report's redistribution rights. Default tests never download external datasets.

`make eval-record` / `go run ./cmd/eval -record` invokes the configured live model and **overwrites** the committed fixture path. It does not create or approve a new baseline. Use a disposable branch/copy for experiments, review every response for sensitive data, and do not replace the manually authored CI contract with unreviewed recordings. A legitimate fixture refresh must review prompt changes, response semantics, baselines, and provenance hashes together; never lower the baseline merely to obtain a green check.
