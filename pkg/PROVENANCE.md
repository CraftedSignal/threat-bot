# Shared feed contracts

These packages are the canonical IOC, MITRE ATT&CK lookup and public-feed
validation implementation for Threat Bot. A feed consumer can import
`github.com/craftedsignal/threat-bot/pkg/ioc`, `pkg/mitre` and `pkg/publicfeed`
from a released Threat Bot version. Keep wire identities, validation semantics
and append-only revision behavior compatible; changes require fixtures and a
migration review across producer and consumer.

The implementation and tests were copied from the committed CraftedSignal
threat-feed tree at `8805c49b470aec2f2e214d3d5add49f0828dcb28`.
`provenance.json` records original and imported hashes. Intentional later changes
have separate adapted hashes; new first-party package files have their own local
inventory. The original import and upstream license identities remain intact.
The public-feed wrapper
was replaced by its real implementation, moved from `internal/publicfeed`;
its MITRE import now names this module. No sibling checkout, alternate module
replacement or duplicated validator is required. The upstream lookup table
identifies its source as MITRE ATT&CK Enterprise v16.

The upstream commit includes a GNU Affero General Public License, Version 3
`LICENSE` file, verified directly with `git show` against the full repository.
Its SHA-256 is recorded in `provenance.json`; the initial sparse audit checkout
had omitted that file. The project retains its root AGPL license and original
attribution.

ATT&CK is a registered trademark of The MITRE Corporation. The lookup uses
MITRE ATT&CK identifiers, names, and metadata under the
[MITRE ATT&CK terms of use](https://attack.mitre.org/resources/terms-of-use/).
Use does not imply MITRE endorsement.

Only the brief contract and its required helpers are imported here. The feed's
unused STIX/sitemap site validators assumed a particular deployment hostname;
they are intentionally outside this package. The existing publisher owns
Threat Bot's configurable STIX export and validation.

The shared public-feed contract also owns deterministic narrative and action-plan
readiness checks used by the pipeline and publisher. These first-party adaptations
are recorded separately from the original feed import. Their tests use authored
fictional inputs; captured production briefs are excluded. Structural/editorial
readiness does not establish that an intelligence claim is true.
