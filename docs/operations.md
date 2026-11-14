# Operations

Run one writer per SQLite state directory. Start with automatic publishing disabled, minimal sources, restricted filesystem permissions, and a bounded provider account. The application does not impose a universal monetary cap. Keep production orchestration, cloud IAM, credentials, registry configuration, and rollout controls in your own infrastructure project.

## Storage and shutdown

Persist the configured database and its SQLite companion files. Keep model cache, quarantined responses, source replay state, drafts, and publication outbox under the same protection as source text. Set a restrictive umask, use a dedicated user, and protect backups. Runtime configuration and databases must never become container build inputs.

Send SIGINT or SIGTERM and allow graceful shutdown to complete before stopping the service forcibly. A forced stop can leave pending work for restart; do not delete queues or mark items seen manually to silence failures.

For a simple consistent backup:

1. Stop the process and confirm it has exited.
2. Copy the database directory, including any `-wal`/`-shm` files, together with the deployed version/revision and a separately protected configuration record.
3. Restore into a different private directory and test with publishing disabled and outbound publication blocked.
4. Verify draft counts, pending queue state, and startup against the restored copy before relying on the backup.

Use SQLite's supported online backup mechanisms if downtime is unacceptable. Copying only the main database file while a writer is active is not a reliable backup procedure. Define retention, encryption, restore exercises, and access policy outside the application.

## Health and logs

The runner exposes `/healthz` and `/readyz` on port **8086**, listening on all interfaces. Health reflects poll-loop state; readiness reflects model health. Neither proves that all sources are current or that every feed artifact is published. The server uses bounded HTTP timeouts. Restrict probe reachability using the host/container network; do not expose it as a public management endpoint.

Logs go to the process output. Review provider health, source errors, repeated grounding failures, publication failures, and outbox recovery. When `monitoring.public_feed_url` is configured, freshness checks can detect delayed website updates; an empty URL disables those requests. Redact logs before sharing even though sensitive-error controls exist.

## Containers

Build and smoke-test the same Dockerfile used by CI:

```sh
make docker
make docker-smoke
```

The smoke test runs `version` and offline config validation without network. The initial target is Linux amd64. The image runs as UID/GID 1000 and contains the executable, TLS certificates, embedded timezone data, and license bundle. It has no shell.

For a live instance, mount a private config at `/app/config.yaml` read-only, set `db.path: /data/threat-bot.db`, and mount writable persistent storage at `/data` owned by the runtime user. Container `localhost` refers to the container itself: configure an Ollama endpoint reachable from its network. Inject credentials at runtime and expose port 8086 only to the monitoring network. A local image smoke test does not qualify hosted provider integration or production rollout.

## Upgrade and recovery

Read the exact version's release notes, back up state, validate the new configuration, and test the new binary against a restored copy before switching the live writer. Schema initialization can happen when opening a database; do not assume an older binary can read a database touched by a newer one. Rollback may require restoring the matching backup and then reconciling remote publication that occurred afterward.

For publishing failures, retain the database/outbox and inspect the configured branch and credential permissions. Restarting allows durable publication retry. Use `bundle drift` and the previewed correction commands to reconcile artifacts; do not reset source state or rewrite IDs as a generic repair.

A restore drill should show that an existing draft and pending publication state survive restart without sending anything to the production feed. Production rollout and restore approval are separate from building or releasing the application. See [commands](commands.md), [security model](security-model.md), and [releases](releases.md).

## Rename compatibility

The executable, module, configuration environment variable, and source repository use `threat-bot`. Existing SQLite publication receipts retain their original `ti-bot-draft-publication-v1` comment marker so both this version and the previous deployed version can recover them. It is a persisted compatibility identifier, not an application setting; do not rewrite it in a database. Restores and image rollbacks still require the schema and configuration checks described above.

Durable structured-request keys also retain their established `ti-bot-json-v2` namespace. Batch recovery recognizes both the old and current job display-name prefixes. These compatibility identifiers prevent completed or uncertain paid work from being submitted again during the rename; they are not branding or configuration choices. Inspect state with `efficiency`; use its explicit recovery flags only after reviewing the retained job reference.
