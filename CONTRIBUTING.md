# Contributing

Bug reports, focused fixes, clearer documentation, and reproducible evaluation improvements are welcome. Start with [development](docs/development.md); use [support](SUPPORT.md) for setup questions and [security](SECURITY.md) for sensitive reports.

1. Describe the concrete problem, expected behavior, and a small reproduction. For a substantial change, discuss scope in an issue before investing in a large implementation.
2. Work on a branch. Keep changes focused and include tests for behavior that could regress; update commands/configuration docs when their contract changes.
3. Run the relevant local checks, then `make check` with the pinned tools installed. State what you ran and any limitations in the pull request.
4. Explain the resulting behavior, compatibility/migration impact, and how it was verified. Maintainers may request revisions or decline a change outside the project's scope.

Default tests must run without a model, production credential, paid service, or private repository. Live provider tests are opt-in. Use fictional fixtures, reserved example domains/IP ranges, and harmless sentinels. Never include real tokens, subscription URLs, private database content, or copied threat-report credentials.

Preserve source attribution and existing notices. By submitting a contribution, you represent that you can submit it under the applicable repository license. Clearly identify third-party material and its license; do not silently replace or relicense it. There is no additional CLA or sign-off requirement declared here.

Review and release authority are described in [governance](GOVERNANCE.md).
