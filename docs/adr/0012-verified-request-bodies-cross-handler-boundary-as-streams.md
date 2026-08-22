# ADR-0012: Verified request bodies cross the handler boundary as streams

- Status: Accepted
- Date: 2026-08-22
- Trigger: RustFS Gateway axiom A3 (ordering contracts are fixed by types)
- Supersedes / Superseded by: none

## Context

The request gate currently consumes every body before decoding or dispatch. The framed path pulls
through the bounded `aws-chunked` pipeline but appends every verified run to one `BytesMut`; the
unframed path appends every transport frame to another `BytesMut`. The codec then turns the
complete `Bytes` into a `ByteStream`. This removes duplicate copies but still retains the decoded
size of one upload and prevents a handler from applying back-pressure to the socket.

The existing type boundary already distinguishes buffered request documents from streaming
payloads. `OperationCodec::decode` accepts `RequestBody::Buffered` or `RequestBody::Stream`, and
generated streaming fields hold the protocol-neutral `rustfs-gateway-stream::ByteStream`. The
missing contract is therefore not another body type. It is ownership and ordering: which layer
drives the socket, when a run becomes visible, how terminal integrity failure outranks a handler
result, and what wakes the request when a handler stops polling its body.

## Decision

For an operation whose generated request-body mode is `Streaming`, pass an owned
`ByteStream` to the decoder before the body is complete. A gateway-owned producer holds the
transport body, ceilings, digest state, and optional `IngestPipeline`; a handler poll drives that
producer directly. Do not spawn a pump, add a read-ahead channel, or place protocol vocabulary in
`rustfs-gateway-stream`. Buffered XML, form, and other explicitly bounded document bodies remain
fully collected before decoding.

The producer exposes a run only after every verdict decidable for that run has succeeded. Signed
framing retains exactly the existing one-chunk `VerifyBeforeDeliver` lookahead. Whole-body length,
payload-hash, and checksum claims remain terminal obligations: the gateway owns a single-assignment
terminal verdict beside the protocol-neutral stream error, and no handler response may commit
until the stream reaches a successful EOF and that verdict permits commit. A handler that returns
without consuming or dropping the body cannot turn an incomplete or failed upload into success.

Body progress is raced beside handler execution, not implemented by polling the socket in a
background task. Each successful producer poll rearms the progress deadline. If the handler stops
polling, the wrapper still polls the deadline, signals a distinct
`HandlerCancellation::BodyIdle`, gives the handler the existing bounded cleanup grace, and closes
the request path without draining the peer. Dropping the handler or stream drops the sole transport
owner, so cancellation cannot leave an ingest task detached.

The complete live ownership of one streaming request includes its transport frame, verification
window, delivery buffer, digest state, and metadata. It must remain at or below 4 MiB with the default
limits. Process ownership under concurrent large logical uploads must be linear in that same
bound plus a fixed measured baseline. Acceptance uses synchronized live-socket subprocesses whose
unique pages are resident at the measurement barrier; it may not substitute allocation counters,
pre-built shared bodies, or a timed RSS sample with no proof that every request is at the intended
state.

## Evidence

Measured with `rustc 1.97.1 (8bab26f4f 2026-07-14)` at gateway main
`b30ae0b2e25e14c67662ab517ce0086e310cc8b3`.

- `rg -n 'Result<Bytes, S3Error>|let mut (decoded|collected) = BytesMut::new\(\)|ByteStream::from_bytes\(body.clone\(\)\)' crates/gateway/src/gate.rs crates/gateway/src/chunked.rs crates/core/src/static_dispatch.rs`
  found both gateway readers returning complete `Bytes`, one whole-body collector in each path,
  and the codec boundary rebuilding a stream from the completed body.
- `rg -n 'Stream\(ByteStream\)|pub fn from_reader|pub const DEFAULT_MAX_CHUNK_SIZE|max_chunk_meta_size: 256' crates/core/src/codec/view.rs crates/stream/src/body.rs crates/http/src/limits.rs`
  found the existing streaming request-body variant, the protocol-neutral owned reader
  constructor, a default chunk ceiling of 1 MiB, and 256-byte chunk metadata.
- `IngestPipeline::new` computes one default verification window as one 1 MiB chunk plus two
  256-byte metadata regions and the three-byte terminal metadata minimum: 1,049,091 bytes. Its
  `VerifyBeforeDeliver` policy reports one lookahead chunk.
- `BodyTimeouts::S3` sets a 30-second between-frame deadline, while `WireFrames` owns that delay
  inside the body poll path. [inferred] When the handler ceases polling the body, that future is no
  longer driven; racing the progress deadline beside the handler is required to retire the request
  without reading ahead.
- [inferred] A direct handler-to-producer poll chain is the only arrangement in which "the handler
  did not poll" necessarily means "the socket was not polled". A spawned pump or buffered channel
  makes those observations independent and therefore cannot prove back-pressure.

## Rejected alternatives

- Keep collecting into `Bytes`: it preserves the decoded body as resident memory and makes
  handler back-pressure unobservable.
- Spawn a body pump and send verified runs through a channel: channel capacity is read-ahead, and
  cancellation can detach the task that owns the socket.
- Deliver a chunk before its signature verifies: a bad chunk becomes visible to storage and moves
  rollback from a terminal safeguard into the ordinary data path.
- Treat a handler return as success without a terminal body verdict: a handler could ignore a
  truncation, checksum mismatch, or unread tail and commit a partial object.
- Put an S3-specific verified-body type in `rustfs-gateway-stream`: it violates the stream kernel's
  protocol-free boundary and recreates the dependency cycle that crate exists to prevent.
- Reuse only the handler execution deadline: it cannot distinguish a slow handler from a handler
  stalled on body progress, and it does not rearm when bytes arrive.
- Infer the concurrency bound from counters or shared fixture buffers: neither proves how many
  unique pages the live requests own at the same instant.

## Consequences

- The implementation changes the gateway-to-codec handoff from complete `Bytes` to the existing
  `RequestBody` streaming variant for streaming operations. Buffered operation modes do not move.
- Adding `HandlerCancellation::BodyIdle` changes the public core vocabulary. The implementation
  advances affected versions and documents the `BREAKING` match-arm migration.
- Exact ingest rejection remains gateway-owned even though the handler sees only a
  protocol-neutral `StreamError`; response resolution must prefer that terminal verdict over any
  handler result.
- Guards reject a whole-body collector on the streaming path, more than one signed chunk of
  lookahead, a background pump, and a success path that lacks the terminal commit verdict.
- `c-ing-0061` proves both back-pressure directions and body-idle cancellation over a real socket.
  `c-ing-0063` proves the per-connection and concurrent-process ownership bounds with synchronized
  resident-state controls. Mutations must make read-ahead, unverified delivery, swallowed terminal
  failure, missing cancellation, and an over-wide buffer turn those cases red.
