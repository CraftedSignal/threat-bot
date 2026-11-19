# Brief safeguards and efficiency

The mandatory offline gate combines the original twelve-sentence extraction
replay with twelve fictional publication-contract cases. The latter exercise
manual publication, public rendering/backfill, durable outbox/restart, updates,
and repair omissions. They cover missing operational guidance, marketplace
product labels, blocking QA, missing provenance and detection coverage, and
revision history. Missing required inputs fail CI.

The [fixture notice](../internal/eval/testdata/brief_quality/NOTICE) and
[provenance manifest](../internal/eval/testdata/provenance.json) identify the
original synthetic inputs. Captured production drafts and third-party incident
records were removed during public-source preparation. The tests enforce
publication contracts; they do not measure live model accuracy, source-grounding
accuracy, or production cost savings. See [evaluation](evaluation.md) for the
separate live-experiment workflow.

## Publication and evidence

All publication routes apply the same final semantic contract to the normalized
snapshot. Summary-only bodies, empty operational guidance, marketplace product
slogans, invalid detection coverage and blocking QA findings require review.
Canonical product names remain separate from affected-version qualifiers.
The deterministic narrative and action-plan checks live in `pkg/publicfeed` so
pipeline decisions and public-feed validation use the same readiness contract.

Source-derived version scopes require product-specific attribution. Ambiguous
branches and dependency ranges are not copied to another product. Repair-rejected
scope cannot be reintroduced by later deterministic/CPE enrichment. Severity
records whether its basis is a source rating, an operational policy, or model
judgment; a source that omits a rating does not trigger an endless repair loop.

Incoming merge claims are grounded against their own source, with deterministic
CVE/IOC/source-URL identity checks in addition to the semantic verdict. Only the
claims a merge writes are grounded; context the merge discards (summary,
platforms, tactics, techniques, a negative exploitation flag) cannot hold it.
Previously accepted claims are not grounded against an unrelated later article.
Missing or failed merge decisions retain the source rather than falling through
to a union.

`exploitation_evidence.status` follows the CISA KEV definition of exploitation:
`confirmed_active` covers attempted as well as successful exploitation of real
systems, including attempts recorded by honeypots or sensors and any KEV listing.
Scanning, lab research, predictions and a public exploit or proof of concept are
not exploitation, and an exploit-code listing (for example sploitus or Exploit-DB)
never evidences it. An hourly reconciliation marks approved briefs whose CVEs CISA
lists in KEV as exploited, with the catalog as evidence, and withdraws a state
whose only evidence is an exploit-code listing, unless the brief's own text states
exploitation: that brief is held for review instead. Exploitation wording is read
per clause, so negated, hedged or conditional statements and detection guidance
are not claims. Only listings from the last week send update notifications; a
brief whose update fails the publication contract is left unchanged and reported
for review.
Rumour promotion requires pipeline-issued provenance; model JSON cannot mint it.
Unverifiable publisher ownership or independence requires review.

Every CVE is checked in deterministic order, with CVE Program fallback when NVD
is missing. `cve_verification` records verified, unavailable, not_found, reserved
or rejected and the authority checked. Lookup absence is not proof that an ID is
invalid. Rejected/reserved identities block publication; source-listed IDs survive
propagation outages without invented CVSS/vector metadata.

Full-brief grounding also checks material source facts that change applicability
or the defender response, such as affected ranges, fixed releases, prerequisites
and impact limits. A blocking omission must quote the supplied source and match
the brief's product or CVE. Repair can restore that supported fact within the
existing bounded check/repair/recheck budget; it cannot invent an unspecified
fix or transfer another product's remediation. Minor background omissions remain
advisory. Partial merge claims and added hunt leads use a claims-only check, so
they do not acquire full-brief completeness requirements.

Verified source-listed CVEs can carry supplementary CVE Program evidence into
grounding. The optional lookup has a three-second deadline, shares in-flight
requests, and retains at most 80 facts and 12,000 encoded bytes per record.
Product and CVE attribution stay attached to each fact, and primary fields
precede long article text. Missing, truncated or unavailable evidence remains an
explicit uncertainty; an ordinary supplemental outage preserves a verified NVD
identity. An explicit rejected/reserved primary identity requires review.

## Durable processing

Stable source IDs and evidence revisions are separate. Synthetic publication
clocks do not change a revision; real upstream modification dates can trigger a
refresh. RSS/Atom updated dates and bounded NVD modified-record sweeps include
older corrections, downgraded records and withdrawals. Such low/rejected NVD
records can update existing coverage but do not create new low-value briefs.

Validated candidates, extraction provenance and the canonical rebuild target
survive restart. Model IDs, prompts, schemas, quality configuration and policy
versions invalidate incompatible work. Retries refresh fetched evidence before
reusing it. Fetch failures retain the prior candidate and budget. A timestamp-only
change reuses unchanged evidence; completed evidence consumes no extra model call.

Grounding attempts, including provider errors, consume a persistent bounded
budget. The default is five passes with 15 minutes between failed passes. Retry
resumes the candidate and known failed verdict rather than repeating assembly.
Successful processing clears the live counter while retaining 90 days of history.
Conflicting corrections are held with both the canonical draft reference and
candidate evidence; repeating an unchanged editorial hold makes no model calls.
A richer source rebuilds a thin brief through full assembly and grounding before
updating its canonical narrative.

A completed negative merge-claims verdict also creates an editorial hold, retaining
the selected extraction and target identity without marking the source seen or
changing the canonical draft, indexes or publication state. An unchanged hold
does not repeat model calls or warning logs after restart. Evidence, processing
policy or meaningful target identity/narrative/accepted-claim/status changes allow
reassessment. Polling timestamps, publication bookkeeping and YAML formatting do
not. Assessment failures keep their error, saved extraction and durable backoff;
the configured attempt limit moves exhausted work to review. Recovery is automatic
when those semantic inputs change. Quarantine visibility and held history commit
together. A resumed held checkpoint can repair an earlier storage failure without
repeating the assessment or consuming another attempt.

Checkpoint storage looks up the current candidate by source ID and returns its
stored input key. The pipeline owns policy and evidence compatibility: a delivery
timestamp change can rekey unchanged work while preserving its retry deadline or
editorial hold; changed evidence or policy invalidates that work.

Terminal completion commits the seen revision, evidence key and checkpoint
removal in one transaction. A cleanup failure rolls back completion so the source
remains retryable. Creating a candidate's draft also commits its dedup associations
and any publication intent in that transaction; failure leaves the candidate
available without a partial draft or queued publication. Draft completion requires
the saved input key to still match, so a stale caller cannot consume newer work
or recreate a completed result. External enqueueing follows the commit. Processing
history, grounding counters and pending model jobs are independent of checkpoint
removal.

Draft changes and publication intent commit atomically, including initial
roundups/campaigns and correlation updates. Exact-payload acknowledgements prevent
stale queue results from clearing newer work. Idle polls recover intents. A
snapshot that fails the current editorial gate moves to review without blocking
unrelated publications. Transient enqueue failures retain their durable intent.

## Model work and operations

Successful quality/extraction JSON uses persistent batch/live cache keys containing
model, schema, full prompts and cache policy. Typed validation rejects malformed,
partial or out-of-domain cached values. Grounding verdicts remain live. Cache
retention is 30 days and 50,000 rows, pruned at startup and daily. Unresolved remote
jobs and candidate checkpoints are not age-pruned.

Remote jobs are associated with exact request keys. Atomic creation claims prevent
overlapping service instances from submitting the same work. Restart recovers
existing jobs and partial results. Pending quality/extraction never falls through
to duplicate live inference. An ambiguous creation becomes explicit review after
one hour; it does not authorize resubmission. Verified reconciliation checks the
remote display name and uses compare-and-swap. Abandonment keeps a tombstone.

Read-only reporting:

```sh
threat-bot -config /path/config.yaml efficiency --since 168h
```

The report separates changed inputs from repeat passes and lists pending batch
references/states. Processing history begins with this version; it cannot recreate
older token accounting. Source/stage/attempt/model usage logs include provider
usage metadata, cache outcomes and stable usage-event IDs. Deduplicate batch usage
by `usage_event_id` when recovering the same output. Missing usage metadata is
explicit; a zero must not be treated as a billed-token measurement. Match billing
exports and current provider/model prices to compute actual spend.

Explicit operator recovery (after inspecting the listed reference and remote job):

```sh
threat-bot -config /path/config.yaml efficiency --keys KEY1,KEY2 --expected-ref REF --reconcile-job projects/PROJECT/locations/REGION/batchPredictionJobs/JOB
threat-bot -config /path/config.yaml efficiency --keys KEY1,KEY2 --expected-ref REF --abandon
```

Both actions reject stale references. Abandonment does not allow another inference
for unknown paid work. Editorial publication failures are retained in
`pipeline_quarantine` and pending draft review; canonical published corrections
continue through the existing `drafts amend` preview/compare-and-swap workflow.

Optional routing is configured with `llm.repair_model`; only grounding repair uses
it. The default model is unchanged. `pipeline.retry_backoff` and
`pipeline.max_grounding_attempts` control the bounded retry policy. Compare cost
per accepted grounded brief before changing model defaults; no paid benchmark or
billed-savings claim is implied by deterministic regression tests.
