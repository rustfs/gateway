# Client compatibility matrix

What real third-party S3 clients do against this repository's filesystem reference backend, and a
machine-readable record of it. `compat/matrix.json` is the record; the table in the top-level
`README.md` is generated from it.

## Why this exists next to the conformance corpus

The conformance corpus asserts what the protocol requires. It cannot tell you what an SDK *chooses*
to send. Only a real client decides on its own whether to use chunked framing, how many chunks to
send, whether to attach a trailer, whether to ask for a bucket's region first, and how to paginate.
Hand-written tests only ever cover the cases somebody thought of.

The concrete gap this closes: before this matrix existed, nothing in the RustFS lineage had ever
sent a `STREAMING-AWS4-HMAC-SHA256` upload at a server. The chunk-signature state machine is one of
the easiest parts of an S3 rewrite to get wrong, and it had no real-SDK traffic at all.

## Why each client is here

| Client | Why it is in the matrix |
| --- | --- |
| `restic` | The only client here that signs uploads as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`. Its S3 backend is minio-go with an explicit region, so it reaches `PutObject` without a region lookup first. Its object layout — hundreds of small writes plus multi-megabyte packs read back by byte range — is a workload no single-object scenario produces, and it is the client that found `GetObject`'s missing `Range` support. |
| `mc` | The MinIO ecosystem's own client and what RustFS users reach for first. Same transport as restic, without the region setting, which is what makes it the client that notices a missing `GetBucketLocation`. |
| `boto3` | Python's de-facto S3 client and the SDK whose historical bug reports the s3s regression suite was built from. Driven at the raw API level, so a failing cell names one operation rather than a workflow. It generates presigned URLs for both GET and PUT and redeems them with a plain HTTP client, so presigning is measured across implementations rather than round-tripped through one. |
| `rclone` | Drives aws-sdk-go-v2 at high concurrency and produces the list-then-copy traffic of a real mirroring deployment. It declares `UNSIGNED-PAYLOAD` for its uploads, a payload mode the botocore clients never send. |
| `aws-cli` | AWS's own command-line client (v2) and the reference most users measure a server against. botocore underneath, but its `s3` commands pick part sizes, concurrency and sync decisions of their own. Over TLS its uploads are `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with a CRC64NVME trailer, so it is a second, independently configured trailer writer beside boto3. |
| `s3cmd` | A hand-written signer and XML layer with no AWS SDK underneath, and the oldest widely deployed S3 CLI. It is the client here that writes an ACL back after a copy without an integrity header, and whose `signurl` produces a SigV2 presigned URL. |
| `aws-sdk-go` | AWS's Go SDK, v2: the SDK under rclone and mint's `aws-sdk-go-v2` suite, driven here at the API level so a failing cell names one operation rather than a sync workflow. It has no signed-chunk mode; over TLS, with an unseekable body and an explicit checksum algorithm, it sends a `STREAMING-UNSIGNED-PAYLOAD-TRAILER` upload. |
| `aws-sdk-js` | AWS's JavaScript SDK, v3, on Node.js: the SDK behind most server and browser JavaScript that talks to S3, and the one most sensitive to presigning. It is the client here that frames a stream as `STREAMING-UNSIGNED-PAYLOAD-TRAILER` even over plaintext. |
| `aws-sdk-dotnet` | AWS's .NET SDK (AWSSDK.S3 v4), the S3 client of the .NET ecosystem, driven at the API level. With its defaults it sends every PutObject and UploadPart over plaintext as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` with a signed CRC32 trailer: an independent signed-chunk and signed-trailer implementation. It also percent-encodes the whole `x-amz-copy-source`, separator included. |
| `aws-sdk-java-v2` | AWS's Java SDK 2.x, under most JVM data tooling that speaks S3. With its defaults it signs single-part uploads over plaintext as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` with a signed CRC32 trailer, and its built-in multipart client sends each part as `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with the part checksum in the trailer. |
| `aws-sdk-java-v1` | AWS's Java SDK 1.x: out of support, still linked by a long tail of deployed JVM applications, and a signer separate from 2.x. It frames every PutObject and UploadPart as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` signed chunks with no `Content-Encoding: aws-chunked` header and no trailer — a shape no other client here sends. |
| `aws-sdk-rust` | AWS's Rust SDK (`aws-sdk-s3`), the same language as this project and the client s3s's own end-to-end tests use. A file body is sent over plaintext as `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` with a signed CRC32 trailer by default, while an in-memory body is signed whole, so it covers both shapes from one signer. |
| `opendal` | Apache OpenDAL, the Rust data ecosystem's storage layer and the client that found s3s's stalled-request hang (s3s-project/s3s#316). Driven through its Python binding over the same Rust `services-s3` backend. It has no bucket operations, so its driver creates each cell's bucket with boto3 and measures everything else through the operator. |

An SDK is a library, so each SDK row is a small driver program under `drivers/<name>/`, built from
its own lock file by `ci/compat/install_clients.sh` (the `program` install method in
`versions.toml`) and asked at runtime which SDK version it actually linked.

## What answered these rows

`compat/matrix.json` names its system under test in a machine-readable `sut` block: the package,
the binary, the assembly, a `generation` number, and whether that identity is provisional.

Generation 1 was measured against `compat-sut`, the launcher this task added under `compat/sut/`.
It is not a mock — it is the production `S3Service` with the real `rustfs-gateway-fs` handlers,
real SigV4 verification, and the real `rustfs-gateway-server` listener — but it exists because the
workspace shipped no runnable S3 server binary at all (rustfs/gateway#624). When the
general-purpose binary that issue asks for lands, point the matrix at it, bump `generation`, and
re-measure: the rows below describe server answers, and server answers belong to a named server.

Client-side facts do not depend on that. Which payload mode an SDK chooses, and whether it frames a
body as `aws-chunked`, is a property of the client and holds against whatever answered.

## What a status means

| Status | Meaning |
| --- | --- |
| `pass` | The client did the thing, the bytes matched, and any wire assertion the scenario declares was satisfied by what the server recorded. |
| `fail` | The client tried and the server answered wrongly, or a wire assertion was not met. A `fail` listed in `known-fail.txt` is `KNOWN`; one that is not is a `REGRESSION` and fails the job. |
| `unsupported` | Either the client has no way to express the scenario, or the system under test does not register an operation the scenario needs. **Never a pass.** It is counted separately, printed as `—` in the README table, and always carries a reason. |

Recording a client's inability as a failure would pollute the manifest and stop the ratchet from
ever moving; recording it as a pass would claim coverage that does not exist. That is why there are
three statuses and not two.

## Scenarios and drivers are separate on purpose

`scenarios/*.yaml` describe what to do in client-independent terms. `drivers/<client>/run.sh`
translates one scenario into one client's commands and prints one result object. Ten independent
scenario suites could not be compared with each other, which is the whole point of a matrix.

A driver never judges wire behaviour. The system under test records what it received — payload
mode, whether the body was `aws-chunked`, how many signed chunks arrived, whether a trailer
followed — and `ci/compat/report.py` evaluates the scenario's `wire_assertions` against that. A
driver grading its own traffic would be reporting its intention rather than an observation, and
`streaming-chunked-upload` would go green for any client that merely uploaded successfully.

## Running it

```bash
cargo build --release -p rustfs-gateway-compat-sut
bash ci/compat/install_clients.sh                     # installs exactly the pinned versions
export PATH="$(go env GOPATH)/bin:$PATH"              # the runner adds target/compat-clients/bin itself
GATEWAY_COMPAT_SUT_BIN=target/release/compat-sut ci/compat/run_matrix.sh

# The fastest feedback loop: one client, one scenario.
GATEWAY_COMPAT_SUT_BIN=target/release/compat-sut \
  ci/compat/run_matrix.sh --clients restic --scenarios streaming-chunked-upload
```

Exit codes are `0` no regression, `1` at least one regression, `3` the environment or a driver is
broken. The third is not the same as "everything failed": a matrix that cannot reach its server
must say so rather than record 56 failures and poison the baseline.

## Corpus recording

Every scheduled run also records itself as corpus material, the second corpus source P8-04
describes: `ci/compat/record_corpus.sh` converts the run's probe records with
`corpus/tools/from_compat_probe.py`, ingests them with the `corpus` CLI (sanitized, deduplicated,
refused if any credential survives) into `target/compat/corpus`, verifies that strictly, and
uploads both with the run's artifact. A full run must record at least one aws-chunked request and
fails if it does not. Nothing is written into the repository's `corpus/`; refreshing that stays a
reviewed pull request.

```bash
cargo build --release -p rustfs-gateway-corpus --bin corpus
ci/compat/record_corpus.sh --run-dir target/compat --corpus-bin target/release/corpus --require-chunked
```

## Files

| File | What it is |
| --- | --- |
| `versions.toml` | The only place a client version is written down, and how each client is installed and its version read back. |
| `capabilities.toml` | The operations the system under test registers. Checked against the launcher's own registry before every run. |
| `scenarios/*.yaml` | Client-independent scenarios, with the wire facts some of them assert. |
| `drivers/<client>/run.sh` | One client's translation of those scenarios. |
| `../ci/compat/record_corpus.sh` | Turns a run's probe records into a verified corpus under the run directory. |
| `known-fail.txt` | Excused failures. Shrinks only. |
| `matrix.json` | The generated manifest. A protected file: it is an external promise. |
| `sut/` | The `compat-sut` binary: puts `rustfs-gateway-fs` behind a real socket and records what crossed it. It is the runnable server rustfs/gateway#624 says the workspace lacked. Started through `ci/lib/sut.sh`, the launcher shared with the P8-05 external-suite runner (rustfs/backlog#1764). The matrix also starts its TLS listener (`--tls-port`, `--tls-self-signed`) and hands drivers `COMPAT_TLS_ENDPOINT` and `COMPAT_CA_BUNDLE`; only a scenario a client can express solely over TLS uses them (rustfs/gateway#719). |
