# Changelog

This file records user-visible changes. No tagged release is implied by an entry under Unreleased.

## Unreleased

- Bind grounding-repair source references to their eligible product or CVE target in the response schema. Malformed cross-target selections can be corrected without dropping blockers or relaxing source-evidence validation.
- Adopt `threat-bot` as the command and Go module name, with `THREAT_BOT_CONFIG` as the configuration environment variable.
- Make builds independent of a sibling feed checkout by including the shared validation packages and provenance.
- Add strict configuration validation, an offline `config validate` command, version reporting, and installation-specific publishing settings.
- Prepare a draft-first example, operator/developer guides, contribution policies, and a public release workflow.
- Replace large imported report excerpts with a small original synthetic corpus and a required deterministic replay regression.
- Harden outbound requests, operational diagnostics, persistence failure handling, and build inputs during source preparation.
- Share deterministic narrative/action-plan readiness across pipeline and feed validation; retain editorial merge holds and bounded retries across restart.
- Restore validated material source facts within bounded grounding repair, keep partial-claim checks separate, and preserve compatible processing checkpoints during the rename.
- Adopt the final bounded Sigma parser used by the deployed application, rejecting malformed authored values while retaining warning-only rules and parser-limit publication checks.
- Follow the CISA KEV definition of exploitation: observed exploitation attempts count as `confirmed_active`, exploit-code listings do not evidence it (a listing-cited state is kept only when the brief's own text states exploitation, and flagged for review), and reports of attempts are routed as updates instead of skipped duplicates. Exploitation wording is read per clause, so negated or hedged statements and detection-rule wording no longer mark a CVE exploited.
- Reconcile published briefs with the CISA KEV catalog hourly (exploited state, per-CVE KEV flags, notifications only for listings from the last week) and withdraw exploitation states whose only evidence is an exploit-code listing, holding for review those whose text states exploitation.
- Ground only the claims a merge writes; findings on discarded context no longer hold merges for editorial review.
- Send update notifications with the brief's published type, severity, vendors, products, actors, tags and PoC flag. Update payloads were built from the draft, which has no public type, so they matched no subscription filtering on type. Briefs the publisher does not publish no longer send update notifications. Add `drafts notify-update` to preview or re-send one.
- Fix a crash in the hourly KEV reconciliation when auto-publish is off: the unset publisher looked configured, and validating a brief with an invalid Sigma rule through it panicked.
- Render CVE record ranges with an unbounded upper limit (`lessThan: "*"`), stop merges from stamping `claim_state: <nil>` on ordinary briefs, and allow GreyNoise, Rapid7 and the main security newsrooms (SecurityWeek, The Hacker News, BleepingComputer, The Record) to send update notifications; KEV flags caught up for listings older than a week no longer notify.

Before upgrading an existing installation, review the exact release notes, validate configuration, back up SQLite, and test with publishing disabled. Existing feed identities and compatibility fields remain separate from the application's renamed command/module.
