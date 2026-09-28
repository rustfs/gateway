# rustfs-gateway-corpus-recorder

A tower layer that records every S3 request a server serves as a corpus entry, in the JSONL
format `corpus ingest` reads (`crates/corpus`). It exists for **test builds only**: point a
synthetic suite (Ceph s3-tests, mint, the client matrix) at a server with the recorder mounted,
and the suite's traffic becomes corpus input — including real `STREAMING-AWS4-HMAC-SHA256`
signed-chunk bodies, which no hand-written entry can stand in for.

Without the `corpus-record` feature this crate compiles to **nothing**: every module and every
dependency sits behind the feature.

## Three lines of defence

A recorder in a production build writes every request it serves to disk, so it is fenced three
times, and each fence has a check that goes red when it is removed.

| Line | What it is | What proves it |
| --- | --- | --- |
| Compile time | Everything is behind `corpus-record`, which is never in any `default` feature set, and a crate may depend on this one only as an `optional` dependency | `scripts/check_recorder_not_default.sh`; `tests/recorder/symbols.rs` compiles the crate without the feature and finds no `CorpusRecorderLayer` symbol, with the featured test binary as the control |
| Runtime | `CorpusRecorderLayer::new_checked` refuses unless `RUSTFS_CORPUS_RECORD=1` exactly **and** every configured access key is on `TEST_ACCESS_KEYS` (RustFS's shipped `rustfsadmin` is deliberately not). The host must propagate the error and **not start** | `tests/recorder/gate.rs` |
| Before disk | The writer thread runs the corpus crate's fail-closed gate on every entry: `redact::sanitize` replaces `Authorization`, `Cookie`, `Set-Cookie`, `x-amz-security-token`, both SSE-C key headers, presigned `X-Amz-Signature` / `X-Amz-Credential`, and the `chunk-signature` / `x-amz-trailer-signature` values of an aws-chunked body with `__REDACTED__` and lists them in `redacted`; `redact::admit` then refuses anything still carrying credential material, and a refused entry is counted and never written | `tests/recorder/capture.rs`, `tests/recorder/signed_chunks.rs` |

## What an entry holds

- `capture = "head_full"` — every request header, in `http::HeaderMap` order (duplicates of one
  name are grouped, which is the one way that order can differ from the wire). A head with a
  non-UTF-8 header value is not recorded and is counted as `unrepresentable_head`.
- `op` — the operation the gateway's own generated route table names for the request, with the
  host's addressing rule (path-style unless `with_host_resolver` installs another). A request no
  S3 route names (an admin API, a health probe) is passed through unrecorded and counted as
  `unrouted`.
- `sut` and `src` — from the configuration. The source must be on the corpus allowlist, or the
  recorder refuses to start.
- `chunks` — the **whole** request body exactly as the inner service received it (aws-chunked
  framing included) as one data chunk with no `delay_ms`. A passive tap sees when the service
  pulled bytes, not when the client sent them, so it claims neither timing nor frame
  boundaries. A body that exceeded a cap, or that the service stopped reading before its end,
  is not recorded at all (`body_not_recorded`) rather than recorded as a prefix posing as the
  whole.
- `resp` — status and headers. The response body is never recorded.

The pass-through is untouched: the inner service polls the same frames, in the same order, with
the same backpressure and the same terminal outcome it would see without the recorder. Only the
copy is bounded — per entry by `max_body_bytes` (1 MiB), across all in-flight requests by
`max_in_flight_bytes` (64 MiB), and in the writer queue by `queue_capacity` (256). A full queue
drops the record and counts it (`dropped_queue_full`); it never blocks a request. Read the
counters with `CorpusRecorderLayer::stats()` and log them at shutdown.

## Integrating it into RustFS

These are the exact steps; nothing else in RustFS changes.

1. **Dependency, optional.** In `rustfs/Cargo.toml`:

   ```toml
   [dependencies]
   rustfs-gateway-corpus-recorder = { git = "https://github.com/rustfs/gateway", rev = "<pinned>", optional = true, features = ["corpus-record"] }

   [features]
   # Never add this to `default` or to any release feature set.
   corpus-record = ["dep:rustfs-gateway-corpus-recorder"]
   ```

2. **Construct at startup, and refuse to start on error.** Pass every access key the server is
   configured with (the root credential, plus any static test identities):

   ```text
   #[cfg(feature = "corpus-record")]
   let corpus_recorder = Some(
       rustfs_gateway_corpus_recorder::CorpusRecorderLayer::new_checked(
           rustfs_gateway_corpus_recorder::RecorderConfig::new(
               std::env::var("RUSTFS_CORPUS_RECORD_OUTPUT")?,   // e.g. /tmp/corpus/s3-tests.jsonl
               std::env::var("RUSTFS_CORPUS_RECORD_SRC")?,      // e.g. s3-tests@5522d1c351f75bc00ae0f64f742f3f095f5939d9
               rustfs_gateway_corpus_recorder::Sut::RustfsServer,
               vec![root_access_key.clone()],
           ),
       )?, // a RecorderRefused here must stop the process
   );
   #[cfg(not(feature = "corpus-record"))]
   let corpus_recorder: Option<tower::layer::util::Identity> = None;
   ```

3. **Mount it, one line, outermost** in `build_external_stack` (`rustfs/src/server/http.rs`), right
   after the two `AddExtensionLayer`s, so it records the request as the client sent it and the
   response as the client received it:

   ```text
   .option_layer(corpus_recorder.clone())
   ```

   A server that serves virtual-hosted buckets passes the same `HostResolver` it routes with:
   `layer.with_host_resolver(resolver)`.

4. **Workflows.** In `e2e-s3tests.yml`, `mint.yml` and `minio-interop.yml`, build with
   `--features corpus-record`, set `RUSTFS_CORPUS_RECORD=1`, `RUSTFS_CORPUS_RECORD_OUTPUT` and
   `RUSTFS_CORPUS_RECORD_SRC`, keep the existing `rustfsadmin-ci` / `rustfsalt` identities (both
   are on the allowlist), and upload the JSONL as an artifact. Then, in this repository:

   ```bash
   cargo run -p rustfs-gateway-corpus --bin corpus -- ingest <artifact>.jsonl --into corpus
   cargo run -p rustfs-gateway-corpus --bin corpus -- verify corpus --strict
   ```

   `--sanitize` is not needed: the recorder already sanitized every entry and the gate admitted
   it. Entries carry `sut = "rustfs-server"`, which `scripts/check_corpus_provenance.sh`
   cross-checks against `entries_from_production_server` in the manifest.

5. **Release symbol check.** In the RustFS repository, a release build without the feature must
   contain no recorder symbol:

   ```bash
   cargo build --release -p rustfs && ! nm -C target/release/rustfs | grep -q CorpusRecorder
   ```

   RustFS's own `scripts/check_recorder_not_default.sh` should assert that `corpus-record` is in no
   `default` feature list and that the dependency stays `optional = true`; this repository's
   script of the same name does exactly that for the gateway workspace and is the template.

## Using it anywhere else

The layer is generic over the inner service and the body: any `tower::Service<Request<TapBody<B>>>`
with `B: http_body::Body<Data = Bytes>` works, so the client-matrix `compat-sut` or a test harness
can mount it the same way.
