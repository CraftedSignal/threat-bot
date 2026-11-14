# Security policy

Use GitHub's **Security → Report a vulnerability** for this repository: [private vulnerability reporting](https://github.com/CraftedSignal/threat-bot/security/advisories/new). Do not open a public issue containing an exploit, credential, private source text, or production details.

If GitHub does not offer that route, request a private contact channel from the maintainer without disclosing the vulnerability itself. Private reporting must be verified as part of public launch; the presence of this file alone does not enable it.

Include the affected revision/version, component, impact, and a minimal harmless reproduction where possible. Redact credentials and personal data. Do not test against deployments or third-party systems without authorization. A report about this project's code does not authorize access to any hosted service.

Before a first versioned release, reports are handled against the current main branch. After release, the latest published release is the starting point for triage; backports are case by case and announced in advisories or release notes. There is no guaranteed response or remediation deadline, bug bounty, or service-level agreement. Maintainers aim to coordinate disclosure with reporters and publish actionable remediation when available.

See the [security model](docs/security-model.md) for data flow, the public feed wrapper, network boundaries, and retention limits. A current source scan does not certify old Git history, logs, images, or external providers.
