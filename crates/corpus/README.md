# rustfs-gateway-corpus

The store behind `corpus/`: a versioned schema for recorded S3 requests, a **fail-closed**
redaction gate that refuses anything it cannot prove clean, value-free deduplication, and
per-operation bucketing with a retained cap.

It does not record. Recording is a feature-gated tower layer in the RustFS main repository and
never compiles into a production build; this crate only ever sees the JSONL that layer wrote.

The gate's polarity is the point: `ingest` **refuses** an entry that still carries credential
material rather than quietly repairing it, because a repair nobody sees is how a leak becomes
invisible. Repair is a separate, explicit `--sanitize` pass that records every field it touched.
