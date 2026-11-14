# Changelog

This file records user-visible changes. No tagged release is implied by an entry under Unreleased.

## Unreleased

- Adopt `threat-bot` as the command and Go module name, with `THREAT_BOT_CONFIG` as the configuration environment variable.
- Make builds independent of a sibling feed checkout by including the shared validation packages and provenance.
- Add strict configuration validation, an offline `config validate` command, version reporting, and installation-specific publishing settings.
- Prepare a draft-first example, operator/developer guides, contribution policies, and a public release workflow.
- Replace large imported report excerpts with a small original synthetic corpus and a required deterministic replay regression.
- Harden outbound requests, operational diagnostics, persistence failure handling, and build inputs during source preparation.
- Share deterministic narrative/action-plan readiness across pipeline and feed validation; retain editorial merge holds and bounded retries across restart.

Before upgrading an existing installation, review the exact release notes, validate configuration, back up SQLite, and test with publishing disabled. Existing feed identities and compatibility fields remain separate from the application's renamed command/module.
