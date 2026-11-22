# Grounding Retry Cycle Stop Implementation Plan

> **For agentic workers:** execute this plan natively in this session; the user explicitly asked to commit, push, and deploy the fixes.

**Goal:** Stop repeated grounding-repair cycles once a prior field-and-subject finding returns, while preserving retries that produce new findings.

**Architecture:** Store normalized grounding issue identities in the existing opaque processing checkpoint. Compare each failed repair recheck against prior failed rechecks; a repeated identity is quarantined for review immediately. Keep the existing maximum retry budget for changing findings and provider failures.

**Tech Stack:** Go, YAML checkpoint serialization, existing SQLite-backed pipeline tests.

**Spec:** Production log sequence for TeamCity CVE-2026-132904 showed affected-products → recommendation → affected-products, followed by further paid retries.

## Global Constraints

- Preserve durable checkpoints and restart behavior; no SQLite schema migration.
- Do not reduce the global retry limit for candidates making progress.
- Distinct affected-product subjects must remain distinct findings.

## Review Focus

- Same field and subject with changed version prose must count as the same unresolved issue.
- A different product under the same field must remain eligible for retry.
- Existing checkpoints without history must continue to load and resume.

### Task 1: Track repeated grounding findings

**Files:** `internal/pipeline/processing_resume.go`, `internal/pipeline/candidate_processing.go`, `internal/pipeline/grounding_cycle_test.go`.

- [x] Add tests showing two distinct findings followed by a repeated field and subject are recognized, including version-text normalization, numeric product qualifiers, distinct products, legacy empty history, checkpoint persistence, and candidate quarantine after a cycle.
- [x] Run the focused test before implementation; it failed to compile because the cycle tracker did not exist.
- [x] Persist normalized issue identities in the candidate checkpoint, compare failed rechecks with history, and quarantine on recurrence. Restrict normalization to explicit version-range qualifiers so numeric product names remain distinct.
- [x] Run `GOWORK=off go test ./internal/pipeline`, then `GOWORK=off go test -race -timeout=10m ./...`; both passed.
- [ ] Commit, open PR, pass CI/review, release, validate and deploy using the established release procedure.
