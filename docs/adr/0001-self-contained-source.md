# 0001: Keep the source checkout self-contained

Status: accepted for the source preparation, 2026-11-14.

A local replacement of a sibling feed repository made ordinary builds depend on a private workspace layout. threat-bot now owns the small shared IOC, MITRE lookup, and public-feed validation packages under `pkg/`. The implementation and tests move together; provenance records the imported revision and modifications.

Producer and consumers should import this common contract rather than maintain independent validator copies. Source, container, CI, and release builds use the same Go module and Dockerfile. A separate shared module can be extracted later if ownership or release cadence warrants it. This decision does not claim that a consumer cutover or a hosted public release has occurred.
