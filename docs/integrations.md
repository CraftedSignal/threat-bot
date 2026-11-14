# Integrations

Enable only the sources and services you intend to contact. Availability, rate limits, provider models, terms, and costs can change; consult the service's own current documentation before enabling it. No integration credentials are required for the ordinary test suite.

| Integration | Purpose and network | Authentication / constraints |
| --- | --- | --- |
| Ollama | Local or operator-configured inference HTTP endpoint | Model must already be installed; source content goes to that endpoint |
| Vertex AI | Hosted inference; optional batch through GCS | Application Default Credentials, project/location/model; billed provider usage |
| Public RSS/HTTP sources | Advisories, research, detections | Source-specific limits and content rights apply |
| CISA KEV / EPSS | CVE enrichment | Live runner refreshes enrichment even with other sources disabled |
| GitHub | Optional source access and publishing to your feed repository | App installation or `GITHUB_TOKEN`; narrowly scoped repository access |
| abuse.ch | Authenticated source APIs | Environment selected by `sources.abuse_ch.api_key_env` |
| Brave search | Optional public-web social discovery | Environment selected by `api_key_env`; request charges may apply |
| RSS bridge | Optional bridged social feed | Treat the complete `feed_url` as sensitive |
| Bluesky / Mastodon / social resolvers | Optional discovery and context | Review instance/provider terms and request budgets |
| Notifier / watchlist sync | Optional operator services | Trusted endpoints and appropriate secret handling |

## Model providers

The example uses Ollama. To select Vertex AI, set `llm.provider: vertexai` with your project, location, and model and configure Application Default Credentials outside the repository. Batch requires Vertex AI plus a bucket accessible to the caller and service agent. Set bucket retention and billing controls yourself. A smaller `fast_model` can serve quality checks; evaluate its behavior separately from the extraction model.

A quality threshold, per-source evidence floor, adaptive polling, and discovery request budgets can reduce work. They are not an overall currency spending cap. Use provider quotas/budgets and start with few sources. `check-llm`, live evaluation, replay, enrichment, and live tests can all issue model requests.

## GitHub publishing

Use a repository you control. Configure `publish.repo_slug`, `publish.site_url`, `publish.feed_public_key`, and optionally `publish.branch`, `publish.author_name`, and `publish.author_email`. The configured branch must exist. A GitHub App configuration requires `app_id`, `installation_id`, and `private_key_path` together; otherwise the CLI can use `GITHUB_TOKEN`. A configured App takes precedence and does not silently fall back to the token.

Grant the publishing credential only the needed feed-repository contents access. The application uses GitHub.com APIs; GitHub Enterprise Server has no documented configuration contract here. Keep source-reading permissions separate where practical. Begin with auto-publish disabled and review a draft before using an explicit publishing command.

The public wrapper is not a secret; see [feed protocol](feed-protocol.md). The repository URL, branch, website URL, and author fields belong to your own installation and have no dependency on the project's production infrastructure.
