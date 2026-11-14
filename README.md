# threat-bot

Collect security advisories, research, detection content, and social signals, then turn them into structured threat intelligence with an LLM.

Run locally with Ollama or use Vertex AI. Drafts are stored in SQLite for review; an optional GitHub publisher produces a versioned feed, Markdown briefs, and STIX 2.1 bundles. Review generated content before using or publishing it.

## Quick start

Requires Go 1.27.4 and a running [Ollama](https://ollama.com/) server.

```sh
make build
cp config.example.yaml config.yaml
ollama pull qwen3:8b
./threat-bot -config config.yaml config validate
./threat-bot -config config.yaml run
```

The example uses CISA KEV and keeps automatic publishing off. Stop with Ctrl-C, then inspect drafts with `./threat-bot -config config.yaml drafts list`.

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md) and [integrations](docs/integrations.md)
- [Commands](docs/commands.md) and [operations](docs/operations.md)
- [Architecture](docs/architecture.md) and [feed protocol](docs/feed-protocol.md)
- [Development](docs/development.md) and [contributing](CONTRIBUTING.md)
- [Example brief](examples/brief.md) and [STIX bundle](examples/stix-bundle.json)

Report vulnerabilities through [Security](SECURITY.md).

Validated pushes to `main` automatically produce [versioned releases](docs/releases.md) and a `ghcr.io/craftedsignal/threat-bot` image.

## License

GNU Affero General Public License v3. See [LICENSE](LICENSE).
