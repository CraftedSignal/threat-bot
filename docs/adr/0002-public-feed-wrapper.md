# 0002: Preserve the public feed compatibility wrapper

Status: accepted compatibility constraint, 2026-11-14.

Existing feed consumers derive an AES-GCM key from `feed_public_key` and a public salt. Replacing this mechanism during repository preparation would change the feed protocol. Preserve the compatible bytes and name, and document that possession of the public value allows both decryption and payload construction.

The wrapper provides no private-feed confidentiality or publisher signature. Distribution integrity depends on the publication channel. A confidential feed or signed publisher protocol requires a separate design, migration, and review.
