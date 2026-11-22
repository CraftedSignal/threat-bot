# Changelog

This file records user-visible changes. No tagged release is implied by an entry under Unreleased.

## Unreleased

- Merge compatible partial rows for the same CVE before publication, preserving all available metadata while keeping conflicting values under editorial review.
- Reject roundup briefs that list at least 50 distinct CVEs but title themselves as a single-CVE issue, preventing product-specific narratives from masquerading as the aggregate roundup.
- Keep source-revision narrative rebuilds within product briefs; rebuilding a roundup or other non-product canonical brief now holds for editorial review instead of replacing its aggregate narrative.
- Recompute a segmented feed release up to three times when concurrent publication changes a staged path; pending content remains queued if conflicts persist.
- Back off repeated source-evidence refresh failures exponentially, persisting attempts per input revision and capping automatic retries at 12 hours.
- Preserve unresolved grounding-finding history across changed-source rebuilds, including rebuilds interrupted before a replacement candidate is saved, so the same failed repair does not restart paid retry work.
- Publish a narrow, machine-recorded withdrawal when exploitation evidence is only a public PoC listing and the brief text does not claim observed exploitation, even if that already-published brief has unrelated narrative-quality gaps; structural publication checks remain enforced.
- Prefer complete CVE Program affected-version records over less precise NVD range projections for the same product, and render letter-prefixed release streams such as NGINX Plus `R33` without dropping the other supported branches.
- Preserve an explicit source-scope gap when primary CVE records use Git commit bounds or `original_commit_for_fix` markers that cannot be mapped safely to release-version ranges; do not infer affected or fixed releases from those markers.
- Stamp `lastmod` with the apply-time UTC timestamp when `drafts amend` publishes a correction whose replacement YAML omits it, keeping public index and JSON Feed modification timestamps current.
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
- Quarantine a candidate when a failed repair recheck cycles back to a previously rejected field and subject, avoiding repeated paid repair/recheck calls while preserving retries that surface new findings.
- Preserve unresolved grounding finding identities when changed source evidence forces a fresh candidate rebuild; repeated findings now reach editorial quarantine instead of silently resetting their retry budget. A grounded correction clears the history.
- Render CVE record ranges with an unbounded upper limit (`lessThan: "*"`), stop merges from stamping `claim_state: <nil>` on ordinary briefs, and allow GreyNoise, Rapid7 and the main security newsrooms (SecurityWeek, The Hacker News, BleepingComputer, The Record) to send update notifications; KEV flags caught up for listings older than a week no longer notify.

Before upgrading an existing installation, review the exact release notes, validate configuration, back up SQLite, and test with publishing disabled. Existing feed identities and compatibility fields remain separate from the application's renamed command/module.
