# MAP — rustfs-gateway-corpus

Agent entry point. File → responsibility → when you need to open it.

The gate in `redact.rs` is fail-closed by design: it refuses, it never repairs. Read its
module docs before changing anything there.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and the public surface. | Start here. |
| `src/schema.rs` | The versioned entry shape, its JSONL codec, and the refusal of an unknown schema version. | A field is accepted or rejected wrongly, or the schema version changes. |
| `src/redact.rs` | What counts as credential material, and the refusal when it is present. | Adding a detector, a sensitive field, or a sanitizable carrier. |
| `src/dedup.rs` | The value-free fingerprint, per-operation bucketing, and the retention rule. | Deduplication collapses too much or too little, or the cap evicts the wrong entry. |
| `src/store.rs` | On-disk layout, generated `MANIFEST.toml`, provenance allowlist, size ceilings, whole-corpus verification. | A corpus file, the manifest, or a recording source is judged wrongly. |
| `src/case.rs` | Conformance case **drafts** and the lossless round-trip assertion. | Chunk timing or termination stops surviving the conversion. |
| `src/bin/corpus.rs` | The `ingest` / `verify` / `to-case` CLI and its exit classes. | The command line accepts or reports something incorrectly. |
| `tests/integration.rs` | Every refusal, the fingerprint contract, the retention rule, and the checked-in corpus. | Changing any behaviour above. |
| `../../corpus/README.md` | Where the corpus comes from, how to update it, why never production traffic. | Adding or refreshing recorded traffic. |
| `../../corpus/MANIFEST.toml` | Generated version record: per-bucket counts, hashes, provenance census. | Never edit by hand; regenerate with `corpus ingest`. |
| `../../scripts/check_corpus_no_secrets.sh` | The independent second scanner over `corpus/**`. | A leak reached the tree, or the two scanners disagree. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-corpus
cargo run -p rustfs-gateway-corpus --bin corpus -- verify corpus --strict
```
