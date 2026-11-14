# Getting started

The smallest useful setup is one local process, SQLite, Ollama, and publishing disabled. Use Go 1.27.4 and a supported local Ollama installation. Build from the repository root; no sibling checkout is required.

```sh
make build
cp config.example.yaml config.yaml
./threat-bot -config config.yaml config validate
./threat-bot version
```

Configuration validation exits successfully when the file is well formed and its settings are consistent. It does not prove that credentials work, a model is installed, or a source is reachable. `version` reports the version/revision embedded by the build; development builds may identify themselves as such.

## An offline regression result

The following exercise needs Go dependencies downloaded once, then runs without a provider or publisher:

```sh
go test ./cmd/threat-bot -run TestFirstRunFixtureCreatesDraftAndSurvivesRestart -count=1 -v
go test ./internal/eval -run TestEvalGate -count=1 -v
```

Expect `PASS`. The first test creates a draft with a synthetic source/model, restarts SQLite, and exercises draft list/show through the CLI. The second test replays four fictional documents through the actual extractor and scoring path. Neither calls Ollama or measures model accuracy. See [evaluation](evaluation.md).

## Process live content

Start Ollama using its installation instructions, then:

```sh
ollama pull qwen3:8b
./threat-bot -config config.yaml check-llm
./threat-bot -config config.yaml run
```

The model is an example selection. Memory requirements, latency, and extraction quality depend on the model and machine. `check-llm` makes a real inference request. The live runner polls CISA KEV in the example and fetches KEV/EPSS enrichment even if individual sources are disabled. It stores state under `./data/threat-bot.db`; it does not write a local folder of published Markdown.

Wait for source processing, stop the process with Ctrl-C, and inspect drafts:

```sh
./threat-bot -config config.yaml drafts list
./threat-bot -config config.yaml drafts show DRAFT_ID
```

Replace `DRAFT_ID` with an ID returned by the list. `No pending drafts.` is valid: a source can have no new items, items can fall outside the lookback, and quality checks can reject them. Review logs, model health, and enabled sources before retrying. Do not repeatedly reset seen-state just to force output; that causes more inference work.

The sample sets `pipeline.auto_publish: false` and no destination. Keep this setup while learning the workflow. To publish, configure your own repository and credentials using [integrations](integrations.md), then use the explicit publication commands in [commands](commands.md).

## Stop, keep, or reset

Ctrl-C requests a graceful shutdown; allow it to finish. Keep the entire database state for the next run. To reset this disposable example, stop every process and move the `data` directory to a backup location before starting again. Removing a live database, WAL, or outbox can lose pending publication state.

A container uses the same configuration contract; see [operations](operations.md). Cloud deployment, credentials, and production orchestration are the operator's responsibility.
