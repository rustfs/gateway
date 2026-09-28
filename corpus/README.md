# corpus/

Recorded S3 requests, deduplicated and bucketed by operation, with a generated
`MANIFEST.toml` that records where every entry came from.

Read this file and you know where the corpus comes from, how to update it, why it never
contains production traffic, and what it does **not** cover.

## Zero production traffic — the one rule that has no exception

No entry here may come from a production system. The reason is not squeamishness, it is
that there is no working sanitised form of a production request: bodies carry user data,
heads carry authentication material, and a SigV4 request whose headers are rewritten no
longer verifies, so it cannot be replayed. Recording synthetic test traffic instead costs
nothing and produces something that still works.

The rule is enforced, not merely stated. Every entry's `src` must name a source on the
allowlist in `crates/corpus/src/store.rs`, and `scripts/check_corpus_provenance.sh`
refuses anything else — `production` included — in CI and in pre-commit.

### And every entry says what it was actually talking to

`src` says which suite drove the traffic. The separate `sut` field says what answered, from
a closed vocabulary the deserializer enforces:

| `sut` | Meaning |
|---|---|
| `gateway-fs-reference` | the `rustfs-gateway-fs` reference backend behind a real listener — real sockets, real SigV4, real wire bytes, none of the production storage stack |
| `rustfs-server` | the production RustFS server |
| `none` | hand-authored input bytes; no server was involved |

Today **every** captured entry is `gateway-fs-reference` and `MANIFEST.toml` records
`entries_from_production_server = 0`. That is not a placeholder: rustfs/gateway#624
measured that this repository ships no runnable production server binary, so there is
nothing to point a client at yet. "A real client spoke S3" and "a real client spoke to the
production server" are different claims, and without this field the corpus would be read
as the stronger one. `scripts/check_corpus_provenance.sh` checks the count against the
entries, so the claim cannot rot.

## What is in here today

134 entries in 82 buckets, 0.3 MB. 128 of them are **real captured traffic** against the
`rustfs-gateway-fs` reference backend; 6 are hand-authored inputs carrying chunk framing and
abnormal termination. The captured traffic comes from two recorders:

- 43 `head_partial` entries converted from the four-client compatibility matrix's probe log
  (rustfs/backlog#1765), deduplicated down from 340 probe records;
- 85 `head_full` entries written by the `CorpusRecorderLayer` (`crates/corpus-recorder`)
  mounted in `compat-sut`, from real `mc` and boto3 sessions: the whole head, the whole body as
  the service received it with every signature redacted, and the response head.

| Source | Entries | Chunk-framed |
|---|---|---|
| `client-matrix:boto3@1.42.96` | 94 | 3 |
| `client-matrix:mc@v0.0.0-20250416181326-b00526b153a3` | 16 | 2 |
| `client-matrix:rclone@v1.74.0` | 11 | 0 |
| `client-matrix:restic@v0.19.1` | 7 | 3 |
| `handwritten:gateway` | 6 | 3 |

### Client diversity is not signing diversity

The manifest counts `chunked` and `trailers` per bucket because the answer is not what the
client list suggests. Over cleartext, rclone and boto3 never emit aws-chunked framing at any
object size; minio-go (restic and `mc`) emits signed `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
chunks. botocore reaches the aws-chunked wrapper only on the unsigned-payload path, which
requires TLS, and there it sends `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with an
`x-amz-checksum-*` trailer. Bucketing therefore records the framing rather than the client.

Blind spot B is closed with **recorded** bodies, not only hand-authored ones:
`object/PutObject.jsonl` holds `mc` uploads whose wire body is
`<size>;chunk-signature=__REDACTED__\r\n<data>\r\n…` exactly as received, and boto3 TLS
uploads (`PutObject`, `UploadPart`) whose body ends in the declared `x-amz-checksum-crc32` or
`x-amz-checksum-sha256` trailer. `the_checked_in_corpus_holds_recorded_signed_chunks_and_trailers`
in `crates/corpus/tests/integration.rs` asserts both.

### Operations with no entries

Measured against every operation in `OPERATIONS.md`, eleven have no entry:
`DeleteObjectAnnotation`, `GetBucketAbac`, `GetBucketMetadataConfiguration`,
`GetBucketMetadataTableConfiguration`, `GetObjectAnnotation`, `ListDirectoryBuckets`,
`ListObjectAnnotations`, `PostObject`, `PutObjectAnnotation`, `RenameObject`,
`UpdateObjectEncryption`. `PostObject` waits on the form-field credential rule
(rustfs/gateway#922): before it, the gate would have admitted a live POST-policy signature.

Coverage of the others is thinner than the bucket list suggests. The reference backend answers
`501 NotImplemented` for about forty operations (CORS, encryption, bucket tagging, website,
replication, logging, notification, accelerate, request payment, ownership controls, object lock
and retention, `GetObjectAttributes`, `GetObjectTorrent`, `RestoreObject`,
`SelectObjectContent`, `UploadPartCopy`, and the analytics, intelligent-tiering, inventory and
metrics configurations) without reading the request body, so their entries carry the head only:
the recorder records a body it did not observe whole as no body. Those bodies need a recording
against a server that reads them.

These are the targets for the next round of client-matrix scenarios and for the hand-written
negative corpus.

## Do not read entry counts as coverage

The recording sources are the existing synthetic suites, and the corpus inherits their
gaps rather than closing them: the end-to-end suite is not a required check, a pull
request runs a subset of it, and the multi-node suites do not run at all. Real client
behaviour — SDK retry shapes, part-size strategies, header-order dialects — comes only
from the cron client matrix. An entry count is a count of inputs, never evidence that a
behaviour is covered.

A third of what is here is `capture = "head_partial"`: the compat probe observes a named
subset of the request head, so absence of a header in such an entry is not evidence that
the header was absent on the wire. `corpus to-case` refuses to build a conformance case
from a partial capture for exactly that reason.

## How to update it

Corpus changes go through an explicit pull request. They are never an automatic commit,
because a corpus change silently changes every differential result computed from it.

```bash
# 1. Record with the CorpusRecorderLayer (see "Recording" below), or convert a
#    client-matrix probe log into corpus JSONL.
corpus/tools/from_compat_probe.py <run-dir>/results \
    --pins compat/versions.toml --recorded 2026-09-02 > /tmp/matrix.jsonl

# 2. Ingest. Without --sanitize this refuses any entry that still carries
#    authentication material and writes nothing; with it, the carriers it knows how to
#    rewrite are replaced with __REDACTED__ and listed in the entry's `redacted` array —
#    including the chunk-signature and trailer-signature values inside an aws-chunked body.
cargo run -p rustfs-gateway-corpus --bin corpus -- ingest /tmp/matrix.jsonl --into corpus --sanitize

# 3. Verify, then run the guards CI will run.
cargo run -p rustfs-gateway-corpus --bin corpus -- verify corpus --strict
scripts/check_corpus_no_secrets.sh
scripts/check_corpus_provenance.sh
scripts/check_corpus_size.sh
```

`MANIFEST.toml` is generated by step 2 and regenerated from the files on disk by step 3,
which compares the two byte for byte. Never edit it by hand.

The pull request's description carries a `## Corpus change` section with the line
`Entries: <before> -> <after>`, the `entries` count `MANIFEST.toml` records at the base and at
the head; `scripts/check_corpus_change_reviewed.sh` checks both numbers, and on `main` it turns a
corpus commit that did not come from a pull request red. `MANIFEST.toml` is deliberately not a
protected file: that process demands `BREAKING` and a version bump, and a corpus refresh breaks
no downstream — marking every refresh `BREAKING` would only teach reviewers to ignore the word.

## Layout

```
corpus/
  MANIFEST.toml          generated: schema version, per-bucket counts and hashes, source census
  <family>/<Op>.jsonl    one operation per file, one entry per line
  tools/                 converters from a runner's own capture format into corpus JSONL
```

The repository holds a deduplicated **sample**, capped per operation. A full capture goes
to a CI artifact: tens of thousands of requests reach hundreds of megabytes, and the
in-repository tree targets under 20 MB with a hard ceiling of 50 MB
(`scripts/check_corpus_size.sh`).

## Recording

`crates/corpus-recorder` holds the `CorpusRecorderLayer`: a tower layer compiled only with its
`corpus-record` feature, refusing to start unless `RUSTFS_CORPUS_RECORD=1` and every configured
access key is a test credential, and running this crate's gate before anything reaches disk. Its
README has the RustFS integration steps. In this repository it is mounted in `compat-sut`:

```bash
cargo build -p rustfs-gateway-compat-sut --features corpus-record
RUSTFS_CORPUS_RECORD=1 target/debug/compat-sut --data <dir> --port 9100 \
    --access-key compatmatrixkey --secret-key <secret> \
    --corpus-record /tmp/mc.jsonl --corpus-src 'client-matrix:mc@<pinned version>'
# ...drive one client against it, stop it with Ctrl-C (it prints the recorder's counters)...
cargo run -p rustfs-gateway-corpus --bin corpus -- ingest /tmp/mc.jsonl --into corpus
```

One `compat-sut` process records one `--corpus-src`, so each client gets its own run.
`--sanitize` is not needed for recorder output: the recorder already sanitized every entry and
the gate admitted it. `tools/from_compat_probe.py` still converts the matrix's probe log, which
observes only part of the head.
