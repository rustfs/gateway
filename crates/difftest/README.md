# RING 2 — migration-only, deleted with the compat feature

`rustfs-gateway-difftest` compares the gateway with the s3s revision RustFS main links
(`0.17.0`) as two pure functions (rustfs/backlog#1762): the same raw request bytes decoded by
both, and the same handler output encoded by both. It
exists only for the migration from s3s to the gateway and is deleted together with the
`compat-s3s` feature of `rustfs-gateway-types` (P9-09). It is never published, and nothing that
ships depends on it.

"Ring 2" names its lifetime and its purpose, not a dependency on RustFS: the workspace ring rule
admits only ring 0 and 1 under `crates/`, so the manifest declares ring 1, links no RustFS crate,
and reaches s3s only through the types crate's `compat-s3s-0-17-0` seam.

## What one decode diff compares

One raw request goes through two real stacks, each with a backend that records what its handler
was handed and then refuses, so no output is ever encoded:

- the gateway: the assembled `rustfs-gateway` service — host resolution, the generated route
  table, acceptance, the security floor, the codec and the handler hand-off;
- s3s: the pinned `S3Service`, with an auth provider so its access hook names the operation it
  routed to for every request, anonymous ones included.

Four things are compared, and a difference in any is a finding:

1. **The operation each stack routed to.** A different operation is ranked above everything
   else: every later comparison is then between two operations.
2. **Every input member, by field path** (`GetObjectInput.range`), in one canonical spelling per
   value (see `src/fields.rs`). A member one model has and the other lacks counts only when it is
   set.
3. **The refusal** — status, `<Code>`, `<Message>` — when a stack did not reach its handler, and
   which stack refused when only one did.
4. **The body left for the handler**, by length and SHA-256, and whether it ended in an error.

Twenty-two operations are compared member by member (`DIFFED_OPERATIONS`); every other operation
is still route-diffed, and its refusals still compared.

## What one encode diff compares

One s3s output — what a RustFS handler returns — goes to both stacks as their handler's answer to
the same request: to s3s as it is, and to the gateway converted to the gateway output
(`src/convert/`; PutObject and GetBucketLocation go through the production seam, so for them the
diff measures what RustFS will run). A member the gateway output cannot hold is a finding naming it,
never a dropped value. Both answers are then compared on:

1. **the status**;
2. **every header line** — name, value, the order of repeated lines, and presence (a header only
   one stack writes is a difference);
3. **the body**: the XML declaration apart, then the document element by element — attributes
   (`xmlns`), whether an empty element is `<X/>` or `<X></X>`, the order of the children both
   sides wrote, presence, text, and the whitespace between children — and, where the structure is
   the same, byte for byte, so an escape or spacing inside a tag still shows.

A streaming output (GetObject) carries a deterministic placeholder body — fixed bytes in fixed
pieces with an exact length — so both stacks write the same stream and the joined bytes compare.
Cadence, trailers and mid-stream errors are conformance cases, not this.

Header names are compared as the `http` crate hands them over, which is lowercased on both sides;
their spelling on the wire is the shadow proxy's to observe.

### Normalisation, not exemption

Four headers legitimately differ between the stacks — `x-amz-request-id`, `x-amz-id-2`, `Date`
and `Server` are the service's, not the answer's. Each is replaced by a placeholder **and its
format is asserted on its own** (`src/normalize.rs`): the request id is 16 uppercase hex digits,
the host id 32, `Date` an IMF-fixdate, `Server` a bare product name. An exemption would hide a
change of format; a placeholder with its own check does not.

Values that come from the output both stacks were handed — version ids, upload ids, instants — are
not replaced at all: they are asserted (an upload id is unpadded base64url of `<deployment>.<UUID>`
as RustFS mints it, an XML instant always carries milliseconds, and so on) **and** compared as
written, so a conversion that changed one within its format — an upload id re-encoded as hex, a
truncated millisecond — is caught twice. `Connection`, `Keep-Alive` and `Transfer-Encoding` are
removed as framing; `Content-Length` on an answer with a body is held to that side's own body and
compared across sides only over identical bodies, and on a `HEAD` answer — the size of the object
not sent — is compared like any other header.

## What the seam diff compares

The decode diff compares the gateway's own input with the legacy one, member by member in one
spelling. The seam diff (`src/seam/`, rustfs/gateway#1076) compares what the RustFS app layer is
finally handed: the gateway, assembled with the RustFS profile's decode options because the seam is
only ever reached behind that profile, converts its request through the production migration seam
exactly as the RustFS adapter does (the authorized copy source supplied, the authorized delete list
patched in, the raw request handed to the members only the legacy decoder reads), and the result is
compared whole with the input the legacy stack's handler received, through the generated member
census. It covers every operation of the seam but `SelectObjectContent`, runs the decode matrix's
rows as well as its own, and proves every member of every covered legacy input is either handed over
identically by some row or named by a finding in its register, with the RustFS evidence for why the
difference cannot change what RustFS does or stores.

## The RustFS profile

The two stacks above run with their defaults. A second pairing, `Profile::Rustfs`
(`Differ::for_profile`, `rustfs_decode_diff`), stands for the deployment the gateway is replacing:
the gateway with the RustFS profile's addressing switches on (the slash rule, the key floor and the
path addressing), as `compat/sut` turns them on, against
the legacy stack configured the way RustFS main configures it (`rustfs/src/server/http.rs:166-172`,
`rustfs_s3_config`: forward-slash normalisation and SigV2 on, `s3tables` signing admitted). Its rows
(`src/samples/rustfs.rs`) are the requests whose bucket and key RustFS's storage must be handed
byte for byte as legacy RustFS hands them, and they are judged exactly as the generic rows are:
every row names the register ids it produces, and most name none. Two controls pair a gateway
without a switch with the RustFS-configured legacy stack, and the RustFS-profile gateway with a
legacy stack left at its defaults, and each must find the key difference, so a row cannot agree
by accident.

## Unregistered differences fail

Every finding must match an entry of [`known-diffs.toml`](known-diffs.toml), which says what
differs, why that is accepted, and when it is reviewed again. A message-wording difference is
reported as information once registered; unregistered, it fails like any other. An element-order
entry pins both complete orders, and a finding matches when the children written are that order
with some left out — so a gateway that starts writing another order is a new difference. When an
entry pins both sides with a `*`, the two stand for the same text. An entry with `when_query`
applies only to a request carrying that query parameter: the `x-id` routing entries accept a route
difference only where an `x-id` hint caused it, so the same difference from any other request —
a real misroute — fails. `when_bucket` does the same for text the first path segment must hold (the escaped
bucket separator `%2F`).

When an s3s output member cannot be held by the gateway output, the diff reports that member and
compares nothing else for that output: there is no gateway answer to compare it with.

The register itself is held in place by three guards. `scripts/check_known_diffs_ratchet.sh` fails
a pull request that adds an entry or changes one (a wider pattern, a later review date) unless its
description carries `known-diff <id>: <why>` for it, and every entry must have a `reason` and an
`expires` date at most a year out; a change to the code that decides what matches or what the
runner skips (`known.rs`, `normalize.rs`, `corpus.rs`, `runner.rs`) needs a `Difftest-matching
change: <why>` line instead. `scripts/check_known_diffs_expiry.sh` warns thirty days before a review date and
fails past it; the weekly `known-diffs-review` workflow keeps one issue listing what is due.
`scripts/check_difftest_readonly.sh` asks a pull request that changes this crate and anything the
gateway is built from (a crate, the model and overlays, generated code — everything but docs, CI
and the evidence directories) together for a `Difftest-coupled change: <why>` line, so a decoder
bent to make a diff green is never silent. `scripts/check_difftest_not_published.sh` keeps the
crate `publish = false`, this file's first line, and every other package free of a normal or
build dependency on it, direct or through another package; only the fuzz crate may link it.

## Why this is not an in-process dual stack

The first plan ran both stacks over one backend and compared response bytes. It cannot work, for
five reasons, and the shape of this crate follows from them:

1. **The two stacks cannot share a backend and still run the same request.** Requests change
   state: after one stack executes a `PUT`, the other executes it against a different store
   (another version, another modification time, another multipart state). Comparable answers
   would need two independent stores kept in lockstep, and the RustFS store is not a pure
   function of its inputs — erasure layout, data-directory UUIDs and timestamps all differ.
2. **Nondeterminism has no injection point.** RustFS mints version ids, data directories and
   upload ids with direct random-UUID calls inside its storage layer. Making the two stacks agree
   on them would first need an injectable id and clock seam across the whole storage layer.
3. **The application layer speaks s3s types.** The RustFS app bodies take and return s3s requests
   and responses, not HTTP. During the migration the gateway path converts into those same types,
   so a response comparison would cover the least dangerous half (wire decoding and encoding) and
   none of the most dangerous half (DTO semantics and persistence), which the four-way persistence
   goldens own.
4. **There is no replayable production corpus.** Bodies carry user data, heads carry credentials,
   and a SigV4 request whose headers are rewritten no longer verifies. The corpus is recorded from
   synthetic traffic instead.
5. **Streaming responses cannot be compared byte for byte.** Chunk boundaries follow the backend's
   read cadence, which differs between stacks; only the joined bytes are comparable, and large
   objects cannot be held in memory to do so.

So the stateful comparison is split into pure functions — decode here, encode next — with no
backend, no clock and no randomness, which can run over every recorded request and under fuzzing.
Streaming cadence, trailer timing and mid-stream errors belong to conformance cases.

## Fuzzing

Two cargo-fuzz targets drive the same differential with generated inputs (`fuzz/fuzz_targets/decode_diff.rs`, `encode_diff.rs`). `decode_diff` reads its bytes as a raw request (`METHOD target`, header lines, a blank line, the body) and fails when the two stacks name different operations for it with no register entry accepting that; it is seeded with the built-in matrix (`fuzz/seeds/decode_diff/`). `encode_diff` builds a listing and a head answer from its bytes and fails on any unregistered encode difference. Each property leaves out, and names, the known classes it found — the `x-id` hint, an escaped slash in the bucket segment, control characters in listing members, over-long encoded metadata words — each pinned by a matrix row and a register entry instead. Both properties also run on stable in `src/tests/fuzz.rs` over the committed seeds and a fixed-seed sample of mutated inputs, so CI exercises them without a nightly toolchain.

```bash
cargo +nightly fuzz run decode_diff fuzz/corpus/decode_diff fuzz/seeds/decode_diff
cargo +nightly fuzz run encode_diff fuzz/corpus/encode_diff
```

A decode finding becomes a conformance case draft with `fuzz-to-case` (`conformance/cases/_from_fuzz/README.md` has the steps); `conformance/cases/naming/c-naming-0033.toml` is the first case made that way.

## Shadow proxy

`shadow-proxy` sits in front of a real S3 server, forwards every byte both ways unchanged, and on the side decodes a copy of each request with both stacks, logging one verdict per request: `agree`, `known <ids>`, `DIFF <findings>`, or `skip: <why>`. The copy is judged on its own thread through a bounded queue the traffic never waits on; a full queue sheds the copy and counts it. A request the client signed is signed again with the credential both stacks hold (the client's key is unknown to them), so it takes the authenticated path it took upstream; chunked transfer framing is replaced by a length, and a signed chunk framing is skipped. Only requests are compared: the upstream's answers go to the client untouched.

```bash
cargo build --release -p rustfs-gateway-difftest --bin shadow-proxy
# In front of a local RustFS (slot A: point clients at 9001 instead of 9000):
target/release/shadow-proxy --listen 127.0.0.1:9001 --upstream 127.0.0.1:9000 --log shadow.log
grep -v ' agree$' shadow.log   # every request that was not identical on both stacks
```

`--queue N` bounds the copies waiting to be judged (default 1024), `--body-cap BYTES` the largest body compared (default 16 MiB; larger bodies are forwarded and logged as skipped). It speaks plaintext HTTP/1.1 only: put it behind the TLS terminator, or in front of a plaintext listener.

## What it does not cover

- **DTO semantics and persistence.** This crate compares what each stack decodes from the wire,
  not what RustFS then does with it. Whether a converted input means the same thing to the RustFS
  handlers, and whether what they persist reads back identically in both directions, is owned by
  the four-way persistence goldens (`rustfs-gateway-goldens`, P9) and the RustFS adapter's own
  proofs.
- Authentication itself: a replayed request is signed again with the diff's own credential
  (recorded signatures are redacted), so the diff compares what each stack does once a request is
  admitted, not how it verifies a client's signature; the request-context and signed-body proofs
  in `rustfs-gateway-goldens` cover signing.
- Anything RustFS installs around s3s (its tower layers, extensions and access hook), and the
  RustFS handlers themselves.
- List elements beyond the rows that send lists: the member census holds each operation's own
  members; `parts[0].checksum_crc32c` is compared whenever a row sends it.

## Run

```bash
cargo test -p rustfs-gateway-difftest
cargo run -p rustfs-gateway-difftest --bin decode-diff -- --corpus corpus --budget-seconds 180
cargo run -p rustfs-gateway-difftest --bin encode-diff -- --builtin --budget-seconds 180
```

Both runners take `--corpus DIR` (the recorded corpus) or `--builtin` (the matrix in `src/samples`),
`--per-bucket N` (the first N entries of every operation) and `--budget-seconds S`. They exit `0`
when every difference is registered, `1` on an unregistered one, `2` on an environment problem —
an empty or missing corpus is one, never "zero differences" — `3` when the harness failed on an
input, and `4` when the run outgrew its budget: sample the pull-request gate with `--per-bucket`
and run the full set nightly rather than letting the gate grow.

A recorded request is changed before both stacks see it, and the report counts each change: a
redacted signature (header or presigned query) is signed again with the credential both stacks
hold, so the request takes the authenticated path it took on the recorded server — unsigned, an
aws-chunked upload would take the anonymous path, where the legacy stack does not decode its framing; an
`__UNRECORDED__` or `__REDACTED__` header is removed; chunked transfer framing is replaced by the
recorded body's length; a partial head capture's missing
`Content-Length` is set from the recorded body, and `flush`/`stall` timing is ignored. An entry
whose body ends abnormally, claims a signed chunk framing whose signatures were redacted, or
declares a length its recorded body does not have, or declares aws-chunked framing over an unframed,
hand-authored payload, is skipped with that reason, and so is
a request of an operation the diff does not project (named in the skip), and a partial
head capture either stack routes elsewhere than its recorded operation (a header the recorder did
not see can change the route). Sampling counts only inputs that are sent, per operation; an
operation none of whose inputs was compared is named (`UNCOMPARED`). A difference outranks the
budget: a slow run with an unregistered difference exits `1`. The corpus holds requests only, so
`encode-diff --corpus` is an environment exit that says so.
