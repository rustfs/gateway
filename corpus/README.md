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

49 entries in 18 buckets, 26 KB. 43 of them are **real captured traffic** from the
four-client compatibility matrix (rustfs/backlog#1765), deduplicated down from 340 probe
records; 6 are hand-authored inputs carrying chunk framing and abnormal termination.

| Source | Entries |
|---|---|
| `client-matrix:boto3@1.42.96` | 23 |
| `client-matrix:rclone@v1.74.0` | 11 |
| `client-matrix:restic@v0.19.1` | 7 |
| `client-matrix:mc@v0.0.0-20250416181326-b00526b153a3` | 2 |
| `handwritten:gateway` | 6 |

### Client diversity is not signing diversity

The manifest counts `chunked` and `trailers` per bucket because the answer is not what
the client list suggests. Across the whole captured run, **only restic** emitted
aws-chunked framing:

| Source | Chunk-framed | Plain |
|---|---|---|
| `client-matrix:restic@v0.19.1` | 3 | 4 |
| `client-matrix:boto3@1.42.96` | 0 | 23 |
| `client-matrix:rclone@v1.74.0` | 0 | 11 |
| `client-matrix:mc@…` | 0 | 2 |

boto3 and the AWS CLI do not emit `STREAMING-AWS4-HMAC-SHA256` against a cleartext
endpoint at any object size; botocore only reaches the aws-chunked wrapper on the
unsigned-payload path, which requires TLS. restic (minio-go, explicit region) does emit
it. Four clients therefore bought one signing mode plus one, not four — which is why
bucketing records the framing rather than the client, and why the three hand-authored
chunk-framed entries exist at all.

### Operations with no entries

Measured against the compatibility matrix's own capability list, nine of its operations
produced nothing the corpus retained: `AbortMultipartUpload`, `DeleteBucketLifecycle`,
`DeleteObjectTagging`, `GetBucketLifecycleConfiguration`, `GetObjectTagging`,
`ListMultipartUploads`, `ListParts`, `PutBucketLifecycleConfiguration`,
`PutObjectTagging`. `CopyObject` is present only as a hand-authored entry: the compat
probe does not record `x-amz-copy-source`, so a captured copy is indistinguishable from a
plain `PutObject` and the converter refuses to guess.

These are the targets for the next round of client-matrix scenarios and for the
hand-written negative corpus.

## Do not read entry counts as coverage

The recording sources are the existing synthetic suites, and the corpus inherits their
gaps rather than closing them: the end-to-end suite is not a required check, a pull
request runs a subset of it, and the multi-node suites do not run at all. Real client
behaviour — SDK retry shapes, part-size strategies, header-order dialects — comes only
from the cron client matrix. An entry count is a count of inputs, never evidence that a
behaviour is covered.

Half of what is here is `capture = "head_partial"`: the compat probe observes a named
subset of the request head, so absence of a header in such an entry is not evidence that
the header was absent on the wire. `corpus to-case` refuses to build a conformance case
from a partial capture for exactly that reason.

## How to update it

Corpus changes go through an explicit pull request. They are never an automatic commit,
because a corpus change silently changes every differential result computed from it.

```bash
# 1. Convert a client-matrix run into corpus JSONL.
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

## What lives elsewhere

Recording itself. The `CorpusRecorderLayer` that writes the JSONL is a feature-gated
tower layer in the RustFS main repository, compiled only into test builds, and it is not
part of this repository. Until it lands, `tools/from_compat_probe.py` bridges the
client-matrix probe records into this format.
