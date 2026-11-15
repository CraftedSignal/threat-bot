# Governance

threat-bot is maintained in the CraftedSignal organization. The current code owner is [@hazcod](https://github.com/hazcod), as recorded in [CODEOWNERS](.github/CODEOWNERS). No backup maintainer or independent security response team is claimed.

Maintainers decide scope, review contributions, merge changes, and authorize releases. Contributors retain attribution for their work. Discuss architectural or compatibility changes in an issue/PR; record accepted long-lived decisions under [docs/adr](docs/adr/README.md). Resolve technical disagreements with concrete requirements and evidence.

Merging to `main` authorizes automatic version selection, artifact and container builds, and publication after the release checks pass. Routine OSS releases do not require a separate manual approval.

Changes should pass required checks and receive independent review when a qualified reviewer is available. A sole maintainer cannot approve their own PR as an independent reviewer. Any maintainer bypass or emergency merge must be explicit and auditable in the PR, with the reason, checks performed, and follow-up review. CODEOWNERS does not itself enforce branch protection; repository rules and bypass authority must be configured and verified separately.

Release authority does not automatically authorize a production deployment. Application releases, public repository visibility, feed publication, and deployment infrastructure are separate decisions. See the [release gates](docs/releases.md). Adding another maintainer or changing these policies requires a reviewed update to this document and repository access controls.
