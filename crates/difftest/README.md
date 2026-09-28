# RING 2 — migration-only, deleted with the compat feature

`rustfs-gateway-difftest` compares the gateway with the s3s revision RustFS main links
(`f3e17541`), on the same raw request bytes, one pure decode at a time (rustfs/backlog#1762). It
exists only for the migration from s3s to the gateway and is deleted together with the
`compat-s3s` feature of `rustfs-gateway-types` (P9-09). It is never published, and nothing that
ships depends on it.

"Ring 2" names its lifetime and its purpose, not a dependency on RustFS: the workspace ring rule
admits only ring 0 and 1 under `crates/`, so the manifest declares ring 1, links no RustFS crate,
and reaches s3s only through the types crate's `compat-s3s-f3e17541` seam.

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

## Unregistered differences fail

Every finding must match an entry of [`known-diffs.toml`](known-diffs.toml), which says what
differs, why that is accepted, and when it is reviewed again. A message-wording difference is
reported as information once registered; unregistered, it fails like any other.

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

## What it does not cover

- **DTO semantics and persistence.** This crate compares what each stack decodes from the wire,
  not what RustFS then does with it. Whether a converted input means the same thing to the RustFS
  handlers, and whether what they persist reads back identically in both directions, is owned by
  the four-way persistence goldens (`rustfs-gateway-goldens`, P9) and the RustFS adapter's own
  proofs.
- Authentication: the diff sends requests unsigned (recorded signatures are redacted); the
  request-context and signed-body proofs in `rustfs-gateway-goldens` cover signing.
- Anything RustFS installs around s3s (its tower layers, extensions and access hook), and the
  RustFS handlers themselves.
- List elements beyond the rows that send lists: the member census holds each operation's own
  members; `parts[0].checksum_crc32c` is compared whenever a row sends it.

## Run

```bash
cargo test -p rustfs-gateway-difftest
```
