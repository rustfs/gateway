# rustfs-gateway-http crate map

Agent entry point for bounded, signature-aware HTTP wire ingestion.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and public wire types. | Start here for an HTTP task. |
| `src/head.rs` | Request-head validation and normalized views. | Header/query/path metadata is accepted wrongly. |
| `src/host.rs` | Host and addressing parsing. | Virtual-hosted/path addressing differs. |
| `src/limits.rs` | Wire budget vocabulary. | A header/query/body ceiling changes. |
| `src/metadata.rs` | Metadata-header validation. | User metadata is malformed or oversized. |
| `src/framing.rs` | Body framing selected from authenticated payload mode. | Content length or chunk framing is wrong. |
| `src/chunk.rs` | aws-chunked syntax and decoding. | A chunk boundary or trailer is rejected wrongly. |
| `src/verify.rs` | Chunk signature-chain verification seam. | A signed streaming body verifies wrongly. |
| `src/ingest.rs` | Bounded body ingestion coordinator. | Bytes move through framing/verification incorrectly. |
| `src/conn.rs` | Connection close/reuse observations. | Wire lifecycle reporting is wrong. |
| `tests/ingest_chunk_rules.rs` | Chunk grammar negative matrix. | Change chunk syntax or limits. |
| `tests/ingest_framing.rs` | Framing decision matrix. | Change payload/framing selection. |
| `tests/ingest_verify.rs` | Streaming signature matrix. | Change signature-chain verification. |
| `tests/ingest_perf_gates.rs` | Ingestion allocation/cost gates. | Change the hot path. |
| `tests/host.rs` | Host parsing matrix. | Change addressing. |
