# rustfs-gateway-http crate map

Agent entry point for bounded, signature-aware HTTP wire ingestion. The public acceptance boundary is
`WireRequest::accept` in `src/wire.rs`; everything else is either what it reads through or what runs
after it has accepted.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and public wire types. | Start here for an HTTP task. |
| `src/wire.rs` | `WireRequest::accept`: the first stage of the pipeline and the last place a raw HTTP request exists. | A request is accepted or refused wrongly at the head, or the acceptance order is in question. |
| `src/header_view.rs` | The borrowed, allocation-free header view every layer above reads through. | Header lookup, canonicalization, or duplicate handling is wrong. |
| `src/query_view.rs` | The query string, indexed once and read without allocating. | Query parameters are indexed or read wrongly. |
| `src/host.rs` | The one effective-host determination, made once per request. | Virtual-hosted/path addressing differs. |
| `src/limits.rs` | The size ceilings `WireRequest::accept` enforces, and the name of the one that was hit. | A header/query/body ceiling or the chunk overhead limit changes. |
| `src/reject.rs` | Every way the acceptance layer can refuse a request, and what each refusal is on the wire. | A refusal's status, wording, or connection disposition is wrong. |
| `src/framing.rs` | Where the body ends, decided once from HTTP's own framing headers. | Content length or chunk framing is selected wrongly. |
| `src/checksum.rs` | The one authority on request-body integrity: `Content-MD5` and `x-amz-checksum-*` arbitration, the digests, and the `ChecksumVerified` witness. | A digest is claimed and not compared, or two layers disagree about which checksum a request made. |
| `src/metadata.rs` | User-metadata header rules, including the one that survives decoding. | User metadata is malformed or oversized. |
| `src/text.rs` | Byte-level predicates and the small ASCII buffer this crate stores strings in. | A character class or a bounded string is judged wrongly. |
| `src/ingest/mod.rs` | Reading an upload body once: decode, verify, digest and deliver in a single pass. | Bytes move through decoding, verification, or digesting incorrectly. |
| `src/ingest/pipeline.rs` | The single pass over an upload: read, decode, sign, digest, verify, deliver. | The order of the pass, or what is handed over before verification, is in question. |
| `src/ingest/decoder.rs` | The `aws-chunked` state machine, working in place on the socket buffer. | A chunk boundary or size line is decoded wrongly. |
| `src/ingest/signer.rs` | The chunk signature chain: one derivation per scope, one HMAC per chunk, no allocation. | A signed streaming body verifies wrongly. |
| `src/ingest/trailer.rs` | Strict bounded `aws-chunked` trailer parsing and declared-set matching. | A trailer name, size, count, or EOF boundary is accepted wrongly. |
| `src/ingest/reject.rs` | Every way an `aws-chunked` body is refused, and what each refusal is on the wire. | A chunked-body refusal's status or wording is wrong. |
| `src/form/mod.rs` | The POST Object form, read so that the file's ceiling is known before the file is. | The policy-before-file order is in question. |
| `src/form/reader.rs` | The text fields before the file, and the door to the part after it. | A POST form text field or its ceiling changes. |
| `src/form/file.rs` | The file part, read under a ceiling named before it started. | The file read path or its ceiling changes. |
| `tests/integration.rs` | The one Cargo test target every `tests/*.rs` source is a module of; `check_http_test_target_consolidation.sh` pins it. | A test source is added, or `cargo test -p rustfs-gateway-http` links more than one integration binary. |
| `tests/support/mod.rs` | Request builders shared by the acceptance suites. | A suite needs a new request shape. |
| `tests/support/ingest.rs` | Wire-shaped ingest fixtures: raw `aws-chunked` bytes and a scripted socket. | An ingest suite needs new wire bytes. |
| `tests/host_ambiguity.rs` | Cases `c-wire-0001`..`0004`, `0007`, `0033`..`0039`: the ways a request can name two hosts. | Change addressing. |
| `tests/header_and_query.rs` | Cases `c-wire-0005`, `0006`, `0040`..`0045`: header tolerance, header ambiguity, metadata. | Change header or query acceptance. |
| `tests/framing_smuggling.rs` | Cases `c-wire-0008`, `0020`..`0032`: rules W-1 to W-6, the framing ambiguities. | Change framing selection or a smuggling refusal. |
| `tests/checksum_arbitration.rs` | The integrity matrix: which claims a head may carry and what each costs at end-of-body. | Change `src/checksum.rs`. |
| `tests/reject_wording.rs` | What a refusal may say to a client, and what it must not. | Change a refusal's body or wording. |
| `tests/boundary_guards.rs` | Source-level guards for properties no type signature can state. | Change a boundary a type cannot express. |
| `tests/allocation_budget.rs` | The allocation budget the acceptance layer promises, asserted rather than claimed. | Change request-head parsing. |
| `tests/ingest_chunk_rules.rs` | Chunk grammar negative matrix and the ceilings that bound a chunk. | Change chunk syntax or limits. |
| `tests/ingest_framing.rs` | Whether the chunk parser runs at all, and whether the two declared lengths agree. | Change payload/framing selection. |
| `tests/ingest_verify.rs` | The chunk signature chain and the promise that nothing unverified is handed over. | Change signature-chain verification or trailer parsing. |
| `tests/ingest_known_answer.rs` | `ChunkSigner` verified against AWS's published chunked-upload example, not our own builder. | Change the chunk string-to-sign or its HMAC chain. |
| `tests/chunked_decode_replay.rs` | Replays the committed `fuzz/seeds/chunked_decode/` seeds through the `chunked_decode` fuzz property on stable. | Change the ingest pipeline, or add a minimised fuzz regression seed. |
| `tests/header_accept_replay.rs` | Replays `fuzz/seeds/header_accept/` and 20,000 fixed-seed samples through the `header_accept` property: exact header ceilings, repeats, readability, metadata. | Change a header acceptance rule, or add a minimised fuzz regression seed. |
| `tests/ingest_perf_gates.rs` | Ingestion allocation and cost gates, stated as equalities rather than wall clocks. | Change the hot path. |
| `tests/form_limits.rs` | POST Object form ceilings and the order in which they are decided. | Change `src/form/`. |
| `tests/form_allocations.rs` | Measures that reading a file part costs a heap independent of the file. | Change the file read path. |
| `benches/parse.rs` | Asserts zero allocations for eight-query indexing and signed-header canonicalization. | Change request-head parsing or canonical-header writing. |
