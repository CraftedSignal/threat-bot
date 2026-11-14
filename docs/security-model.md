# Security model and data handling

threat-bot processes untrusted reporting and model output. Treat generated facts, links, ATT&CK mappings, and detection content as proposals for review. A schema-valid brief can still be wrong or contain sensitive source material. Do not execute commands or detection content found in a draft without your normal review process.

## Data flow and retention

| Data | Destination | Operator responsibility |
| --- | --- | --- |
| Source text, URLs, author identifiers | Process memory; retained source/draft/replay data in SQLite where supported | Source terms, collection scope, access controls |
| Prompts and source content | Configured Ollama or Vertex AI endpoint; GCS batch requests when enabled | Provider policies, location, credentials, cost |
| Model responses, cache, quarantine | SQLite | Protect, back up, and define retention |
| Diagnostic events | Process logs | Restrict access; redact before sharing |
| Approved feed material | Configured GitHub repository and its consumers/caches | Review every output format before publishing |
| Batch request/output objects | Configured GCS bucket | Bucket lifecycle and deletion policy |

There is no universal automatic retention guarantee. In particular, batch processing does not establish a GCS lifecycle rule for you. Removing an item from SQLite does not erase upstream providers, Git history, backups, or public mirrors. Use separate credentials and private storage for configuration, database snapshots, and logs; keep them out of support bundles and container build contexts.

## Network and credentials

Source-derived HTTP requests use URL safety controls where implemented, including connection-time destination validation in the shared safe transport. Those controls reduce unsafe requests but do not replace an egress policy. Configured service endpoints are administrator-controlled inputs; only configure endpoints you trust. Restrict the service account and network to the sources and providers you need.

GitHub App private keys, `GITHUB_TOKEN`, provider credentials, bridge URLs containing subscription tokens, and notifier credentials are secrets. Mount them at runtime. Do not put them into examples, images, model prompts, issues, or Git history. Provider error redaction is a defense in depth measure; still review diagnostics before sharing.

Bind or firewall health endpoints appropriately. They are operational probes, not an authenticated management API. See [operations](operations.md).

## Publication trust

`publish.feed_public_key` is a legacy public compatibility value used to derive a symmetric AES-GCM key. Anyone with that public value can decrypt and construct valid wrapped payloads. This is **not** a confidentiality boundary, consumer authorization mechanism, or publisher signature. Trust comes from the distribution channel and repository permissions. Do not publish private material on the assumption that the wrapper protects it.

The Markdown projection excludes selected fields, but the complete bundle and STIX surfaces have separate contracts. Review those artifacts together. See [feed protocol](feed-protocol.md) and [SECURITY.md](../SECURITY.md) for reporting vulnerabilities.
