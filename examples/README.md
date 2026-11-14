# Examples

- [brief.md](brief.md) is an illustrative analyst summary, not a full import schema.
- [stix-bundle.json](stix-bundle.json) is a synthetic output from the actual STIX exporter.
- [config.github.yaml](config.github.yaml) shows optional publishing settings. Adapt the destination and supply credentials outside the file; automatic publishing remains disabled.

Regenerate the STIX example from the repository root after reviewing an exporter change:

```sh
go run ./examples/stix > examples/stix-bundle.json
go test ./examples/stix
```

The regression validates the committed bundle and checks that the exporter still produces it. All incident content is fictional; example.org links are placeholders and are not fetched by generation or tests.
