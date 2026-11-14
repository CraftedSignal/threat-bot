# Support

Use [GitHub issues](https://github.com/CraftedSignal/threat-bot/issues) for reproducible bugs and setup questions. Include `threat-bot version`, OS/architecture, provider type, a minimal redacted configuration, the command, and relevant redacted output. Do not upload a database, credentials, or a full runtime configuration. Report vulnerabilities through [SECURITY.md](SECURITY.md).

Support is best effort. There is no response-time or hosted-service commitment.

| Surface | Current scope |
| --- | --- |
| Source builds | Go 1.27.4; default tests are credential-free |
| Local draft workflow | Ollama adapter and example configuration; model/hardware quality is operator-evaluated |
| Hosted inference | Optional Vertex AI adapter; caller supplies account, permissions, and budget |
| Publication | Optional GitHub.com feed repository |
| Release artifacts | Linux amd64 is the initial release workflow target; support begins only for actually published, verified artifacts |
| Other platforms / providers | Contributions welcome; no artifact or compatibility promise without tests |

The project is pre-1.0. Consult each release's notes for configuration, database, and feed changes. Keep a database backup before upgrades. A fixed maintenance lifetime or multi-version backport policy has not been established; security support is described in [SECURITY.md](SECURITY.md).
