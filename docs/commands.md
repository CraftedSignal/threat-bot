# Commands and effects

Use `threat-bot [global flags] <command>`. Global flags are `-config PATH` and `-log debug|info|warn|error`; they must precede the command. Subcommand flags normally precede positional IDs. `help`/`-h` lists commands, and `version` reports build metadata.

An apparently read-only database command can open/create SQLite or apply schema initialization. Keep an operational backup and use a copy when investigating an unfamiliar version.

| Command | Effect |
| --- | --- |
| `config validate [--command SCOPE]` | Offline configuration validation; no DB or network. |
| `check-llm` | Real provider/model smoke request; may incur inference cost. |
| `run` | Polls sources, enrichment, and models; writes state; publishes when configured and enabled. |
| `drafts list [--status pending|approved|rejected]` | Lists local drafts; defaults to pending. |
| `drafts show ID` | Shows local draft and validation metadata. |
| `drafts find --slug SLUG` | Finds approved local drafts by exact public slug. |
| `drafts approve [--publish] ID` | Approves locally; `--publish` also publishes remotely. |
| `drafts approve --all-above-score N [--publish]` | Bulk approval; review the affected set first. |
| `drafts reject ID [--reason TEXT]` | Updates local rejection status. |
| `drafts republish [--id ID]` | Publishes approved drafts immediately; no preview default. |
| `drafts republish --since RFC3339 [--exclude-id ID]` | Publishes approved drafts in a time range. |
| `digests generate [--hours N] [--publish]` | Renders local approved-brief digest, default 24 hours; optional remote publication. |
| `sources replay [--dry-run] SOURCE_ITEM_ID...` | Refetches live source items and queues replay unless dry-run; later processing can incur model cost. Use `-` to read IDs from stdin. |
| `sources reseed [--days N] [--source-id ID] SOURCE` | Clears applicable seen-state and rewinds polling; default 14 days. It mutates state immediately. |
| `canonicalize-products --content-dir DIR [--apply]` | Previews local Markdown taxonomy changes; `--apply` writes files. |

## Reviewed corrections

Preview an amendment to an approved draft:

```sh
./threat-bot -config config.yaml drafts amend --id DRAFT_ID --file revised.yaml
```

Applying requires `--apply`, the preview's `--expect-sha256` and `--expect-proposed-sha256`, `--backup-dir`, `--operator`, and `--reason`. The original YAML is backed up; remote publication must succeed before the local snapshot is updated. The alternative `--set-brief-id ID --set-slug SLUG` changes identity and requires careful collision review. `--resolve-unpublished-identity-collision` is only for a draft whose original identity never published.

`drafts retire-duplicates --canonical-id ID --duplicate-id ID` previews duplicate consolidation; repeat `--duplicate-id` as needed. Applying adds `--apply --operator NAME --reason TEXT` and changes remote artifacts and local duplicate status.

## Bundle maintenance

These commands require publisher configuration and may access the remote repository even when a preview does not write.

| Subcommand after `bundle` | Effect |
| --- | --- |
| `drift` | Compares bundle/Markdown; exit 2 means drift detected. |
| `migrate` | Writes the legacy-to-segmented migration. |
| `repair-manifest` | Writes rebuilt manifest data. |
| `backfill-markdown [--slug a,b]` | Writes public Markdown, all matching historical briefs by default. |
| `publish-stix` | Writes a validated STIX projection. |
| `enrich-vendors [--slug a,b] [--dry-run]` | Uses model enrichment; writes unless dry-run. A dry-run can still incur inference cost. |
| `retire-briefs --survivor-id ID --retire ID=SLUG [--apply]` | Previews removal; `--apply` publishes it. Repeat `--retire` for multiple entries. |

`go run ./cmd/feed-identity-repair --help` describes the separate local feed-checkout repair utility. It previews by default and writes with `--apply`; it does not perform a production deployment. Treat its public-key flag as the same compatibility value described in [feed protocol](feed-protocol.md).

For evaluation CLI flags, see [evaluation](evaluation.md). For backup/retry/rollback procedures, see [operations](operations.md).
