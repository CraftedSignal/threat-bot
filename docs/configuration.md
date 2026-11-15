# Configuration

Start from [config.example.yaml](../config.example.yaml). The CLI selects the file in this order: `-config PATH`, then `THREAT_BOT_CONFIG`, then `config.yaml`. Put global flags before the command. YAML keys are strict: unknown keys and duplicate fields are errors; environment substitution is not a general template feature.

```sh
./threat-bot -config config.yaml config validate
./threat-bot -config config.yaml config validate --command drafts
```

Validation is offline: it checks configuration and applicable credential presence, without creating a database or contacting services. It cannot prove API permissions, model availability, directory writability, or source health. Supported validation scopes are `run`, `check-llm`, `drafts`, `sources`, `publish`, `bundle`, `digests`, and `efficiency`.

## Core settings

| Setting | Meaning |
| --- | --- |
| `db.path` | Writable SQLite path; sample `./data/threat-bot.db`. Relative paths are relative to the process working directory. |
| `llm.provider` | Explicit `ollama` or `vertexai`. |
| `llm.endpoint`, `llm.model` | Ollama endpoint and installed model; sample `http://localhost:11434`, `qwen3:8b`. |
| `llm.project`, `llm.location`, `llm.model` | Vertex project, region, and model. |
| `llm.fast_model` | Optional separate model for cheaper quality screening; otherwise uses the primary model. |
| `llm.repair_model` | Optional targeted grounding repair model; otherwise uses the primary model. Readiness checks include a distinct repair model. |
| `pipeline.auto_publish` | False in the example. Enabling it permits remote writes for qualifying drafts. |
| `pipeline.quality_threshold` | Quality score threshold on the 1–5 scoring scale; sample 3.5. Zero is accepted; it is not a percentage. |
| `pipeline.initial_lookback` | Initial source lookback, sample `24h`. |
| `pipeline.max_grounding_attempts` | Maximum repair/grounding attempts; zero selects the default of 5. |
| `pipeline.retry_backoff` | Delay between failed processing-candidate retries; zero selects the default of `15m`. |
| `pipeline.source_confidence` | Optional per-source confidence multipliers. |
| `pipeline.source_signal_thresholds` | Optional per-source deterministic evidence floor before model scoring. |
| `pipeline.adaptive_polling` | Optional per-source maximum interval for quiet-source backoff. |
| `pipeline.roundup_consolidation`, `pipeline.campaign_consolidation` | Optional grouping behavior; evaluate identity and coverage effects before enabling. |
| `watchlist.vendors`, `watchlist.products`, `watchlist.keywords` | Optional prioritization context. |

The example enables only `sources.cisa_kev`. Other source entries are opt-in. Most use `enabled` and `poll_interval`; social discovery, bridges, and authenticated APIs have extra settings. The complete accepted key list is defined in [internal/config/config.go](../internal/config/config.go), and source wiring in [cmd/threat-bot/scrapers.go](../cmd/threat-bot/scrapers.go). Keys are not always the same as the runtime source ID shown in logs; use the runtime ID for replay and reseed.

## Publishing and optional services

`publish.repo_slug` uses `owner/repository`; `publish.site_url` sets the installation's public website origin. `publish.feed_public_key` must contain 64 hexadecimal characters (32 bytes). It is a **public compatibility value**, not a confidentiality key. Defaults for a configured publisher are branch `main`, author name `threat-bot`, and author email `threat-bot@users.noreply.github.com`; override them for your installation. See [examples/config.github.yaml](../examples/config.github.yaml) and [feed protocol](feed-protocol.md).

`publish.cache_dir` optionally enables the service's raw Git blob cache in a dedicated writable directory. It retains at most 128 MiB, verifies blob SHA and size, and keeps current Git metadata and publication conflict checks authoritative. Empty disables it; cache filesystem failures fall back to remote reads. Keep this directory separate from SQLite state.

`github.app_id`, `github.installation_id`, and `github.private_key_path` must be configured together. A configured App takes precedence; otherwise `GITHUB_TOKEN` can supply authentication. Local draft inspection does not require a publisher or model.

New `llm.batch` submissions are opt-in and require Vertex AI plus `bucket`. Timing defaults are `poll_interval: 30s` and `max_wait: 15m`; they also apply to explicit recovery when new submissions are disabled. `min_prompts` defaults to `5` when batching is enabled. Bucket retention and access controls are external responsibilities.

`epss.refresh_interval` defaults to `24h`, and `epss.min_score_delta` to `0.01`. `monitoring.public_feed_url` is empty/disabled by default; when configured, freshness defaults are a `45m` publication grace and `15m` check interval. `notifier.url` and a dispatch token enable optional notification, with default `6h` cooldown. Optional `watchlist.platform_sync` requires an operator-controlled endpoint and credentials.

## Secret inputs

| Input | Source |
| --- | --- |
| GitHub token | `GITHUB_TOKEN` |
| GitHub App key | File at `github.private_key_path` |
| Vertex credentials | Google Application Default Credentials outside this repository |
| Notifier token | `notifier.dispatch_token`, otherwise `NOTIFIER_DISPATCH_TOKEN` |
| Brave key | Environment named by `sources.public_web_social_search.api_key_env`; default `BRAVE_SEARCH_API_KEY` for Brave |
| abuse.ch key | Environment named by `sources.abuse_ch.api_key_env`; default `ABUSECH_AUTH_KEY` |
| Bridge URL / platform sync key | Private runtime YAML fields; never commit them |

Use `1m`, `24h`, and other Go duration strings for durations. Keep runtime YAML private, restrict filesystem permissions, and avoid shell tracing when loading secrets. See [integrations](integrations.md) for network/cost behavior and [operations](operations.md) for storage.
