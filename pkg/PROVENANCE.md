# Shared feed contracts

These packages are the canonical IOC, MITRE ATT&CK lookup and public-feed
validation implementation for Threat Bot. A feed consumer can import
`github.com/craftedsignal/threat-bot/pkg/ioc`, `pkg/mitre` and `pkg/publicfeed`
from a released Threat Bot version. Keep wire identities, validation semantics
and append-only revision behavior compatible; changes require fixtures and a
migration review across producer and consumer.

The implementation and tests were copied from the committed CraftedSignal
threat-feed tree at `8805c49b470aec2f2e214d3d5add49f0828dcb28`.
`provenance.json` records original and imported hashes. The public-feed wrapper
was replaced by its real implementation, moved from `internal/publicfeed`;
its MITRE import now names this module. No sibling checkout, alternate module
replacement or duplicated validator is required. The upstream lookup table
identifies its source as MITRE ATT&CK Enterprise v16.

The upstream commit includes a GNU Affero General Public License, Version 3
`LICENSE` file, verified directly with `git show` against the full repository.
Its SHA-256 is recorded in `provenance.json`; the initial sparse audit checkout
had omitted that file. The project retains its root AGPL license and original
attribution; see root `NOTICE.md` for third-party notices.

Only the brief contract and its required helpers are imported here. The feed's
unused STIX/sitemap site validators assumed a particular deployment hostname;
they are intentionally outside this package. The existing publisher owns
Threat Bot's configurable STIX export and validation.
