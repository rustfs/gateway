# RustFS Gateway conformance suite

This directory holds the conformance corpus: the data files that define what correct S3 behaviour
looks like on the wire. It contains no Rust code. The runner that executes these files lives in
`crates/conformance/` and can be pointed at any S3 implementation, not only this one.

- `case.schema.json` — the frozen case schema (JSON Schema, draft 2020-12).
- `cases/<domain>/c-<domain>-<NNNN>.toml` — one case per file.
- `goldens/` — byte-exact response bodies referenced by cases.

## The schema is frozen

`case.schema.json` was frozen on **2026-08-05** at `schema_version = 1`, before the first line of
protocol code was written. Schema version 2 adds `connection.concurrent`; the runner continues to
accept version 1 cases, while a case using the new dimension must opt into version 2 or later.
Version 3 adds computed Content-MD5 for resolved request payloads. Version 4 adds ordered
HTTP/2 control-frame observations, a pre-header stream-reset outcome, and socket receive termination. That order is
deliberate. A case file is not a test that can be rewritten
cheaply — it is a record of a behavioural fact, and every case written against a schema is invalidated
by a change to that schema. Freezing after thirty cases exist means rewriting thirty cases; freezing
after three hundred means the schema never changes again and the suite stops being able to express
new failure modes.

Freezing does not mean the schema is complete. It means the cost of changing it is paid deliberately,
by the procedure below, rather than accidentally by whoever writes case thirty-one.

### What "frozen" forbids

- Adding, removing, or renaming a field, or widening or narrowing any enum.
- Changing the meaning of an existing field, even when its shape is unchanged.
- Relaxing `additionalProperties: false` anywhere. Silent tolerance of an unknown key is how a
  mistyped assertion becomes a case that passes without asserting anything.

### What "frozen" allows without a schema change

- New tag values. The tag vocabulary lives in this README and in a lint, deliberately not in the
  schema, so that naming a new domain is not a schema change.
- New domains, directories, cases, and golden files.
- New quirk ids in `case.quirks`; the schema constrains their shape, not their existence.
- Documentation and description edits inside `case.schema.json` that do not alter validation.

### Change procedure

1. Open an issue that names the behaviour the current schema **cannot express**, with a concrete
   case that would need it. "It would be tidier" is not an admissible reason.
2. Prefer an additive optional field. Adding an optional field keeps every existing case valid;
   removing or repurposing one does not.
3. If existing cases must change, the issue must list them and the pull request must change them in
   the same commit. A mixed-version corpus is not a supported state.
4. Bump `schema_version` only for a breaking change. The runner rejects any case whose
   `schema_version` it does not recognise with an explicit "update the runner" error. It must never
   skip such a case, and must never ignore fields it does not understand.
5. Two reviewers, one of whom must not have written the case that motivated the change.

### Version 1 to version 2 migration

Existing version 1 cases need no edit. A case that needs independent clients in flight together
changes `case.schema_version` to `2`, replaces the single-connection `pipeline` declaration with
`connection.concurrent = true`, and keeps each exchange at `repeat = 1` with no inter-exchange
delay. The runner opens one fresh socket per exchange, dispatches every request before awaiting a
response, and returns observations in declaration order. `concurrent` cannot be combined with
`pipeline`, `reuse`, TLS, backpressure, or idle-time controls.

### Version 2 to version 3 migration

Existing version 1 and 2 cases remain valid. To derive a digest, set `case.schema_version = 3`,
remove the explicit `Content-MD5` request header, and set `content_md5 = "computed"` in the
corresponding request table. This applies to both `[request]` and `[exchanges.request]`.
The runner resolves captures and payload sources, computes the digest of the resulting body bytes,
and adds the header before signing. Concurrent exchanges remain supported in version 3.

Keep explicit headers in cases that test malformed or incorrect digests. A computed digest cannot
be combined with an explicit Content-MD5 header, a raw request head, raw chunk instructions, or scripted HTTP/2 frames;
these combinations fail instead of silently changing the authored wire bytes. Response assertions
are unchanged by this migration.

### Version 3 to version 4 migration

Rust callers constructing `ExchangePlan` must add `deadline: None` for the existing relative-timeout
fallback, or propagate the runner's absolute deadline unchanged through exchange initialization.
Fixture setup remains outside the target budget: the runner creates its deadline after `prepare`
returns and supplies the remaining budget in `timeout_ms`; sequential exchanges share that deadline.
Callers constructing `Observation` must add `deadline_expiry: None` unless forwarding an actual
executor receipt. `Observation::response` supplies that default. A crate-produced expiry receipt
records the monotonic boundary observed by the bounded executor; an arbitrary `Outcome::Hang`
does not exempt the target from its whole-case budget. Measured authored waits extend the deadline
by their actual duration, and no later request may restart an already expired case.

Version 4 widens the permitted purpose of `hang`: a scripted HTTP/2 case may require bounded
incompletion when the client withholds flow-control credit. Versions 1–3 reserve that expectation
for documented foreign-implementation defects. This use requires an explicit positive
`case.timeout_ms`; every version-4 scripted HTTP/2 Hang observation requires a valid measured
expiry receipt. An early synthetic Hang is rejected even if it fits inside the budget. Status,
received body bytes, control frames and socket-state expectations remain independently checked.
Custom concurrent targets must supply valid receipts for each version-4 scripted HTTP/2 Hang
observation; receipts on non-Hang observations are rejected. A receipt for one exchange does not
establish the completion boundary of the whole batch. Production scripted
HTTP/2 remains limited to sequential execution.

The legacy `connection_reset` outcome includes EOF before a complete response; its name alone
is not evidence of a TCP reset. Version-4 `socket_read_after` distinguishes measured EOF, reset
and absence of an observed termination.

Existing version 1, 2 and 3 cases remain valid without edits. To assert received HTTP/2 controls,
set `case.schema_version = 4` and add `expect.h2_control_frames`, an exact ordered list such as
`[{ type = "rst_stream", stream_id = 1, error_code = 8 }]`. An empty list asserts that the observer
received none of the supported controls other than connection-level grants; an unavailable
observation fails this assertion. Numeric error codes preserve unknown wire values. Missing, extra,
reordered, or different frames fail the comparison, with one exception: a connection-level
WINDOW_UPDATE (stream zero). HTTP/2 leaves when a receiver sends WINDOW_UPDATE, and what it grants,
to the implementation (RFC 9113 section 5.2.1), so whether a peer's grant goes out before a
connection error depends on when its reader sees the offending frame. Each listed connection-level
grant must therefore have been received with exactly that increment, wherever it arrived, and an
unlisted one is not a mismatch. Stream-level WINDOW_UPDATE frames stay in the exact ordered list.

The list covers RST_STREAM, GOAWAY and WINDOW_UPDATE until the selected exchange ends. It does not claim to
capture every HTTP/2 frame: DATA and headers keep their existing response representation. Other-stream resets are recorded without terminating
the selected stream. GOAWAY uses `{ type = "goaway", last_stream_id = 1, error_code = 0 }`;
multiple GOAWAY and RST_STREAM frames retain their common arrival order. The last-stream identifier
excludes the reserved high bit; opaque debug data is discarded, not retained in diagnostics.
A received GOAWAY may instead use `error_code_any_of = [1, 2, 3]` when its cited protocol
permits alternatives. This is a unique nonempty array of u32 values, mutually exclusive with
`error_code`, and is forbidden on authored frames and other received frame kinds. Numeric
`error_code` remains exact; alternatives do not relax frame count, order, last-stream identifiers,
or independently measured EOF. Case c-h2-0006 originally asserted only FLOW_CONTROL_ERROR;
that assertion omitted RFC 9113 section 5.4's allowance for applicable generic PROTOCOL_ERROR
or INTERNAL_ERROR. Its explicit alternatives correct the expectation without changing wire facts.

A GOAWAY does not end an in-flight response: the observer continues until a response completes,
the selected stream resets, a read actually terminates, or the exchange deadline expires.

WINDOW_UPDATE uses `{ type = "window_update", stream_id = 0, increment = 7 }`; stream zero
names connection credit, and the selected nonzero stream names its own credit. Increments in
observations are positive 31-bit values. The observer refuses malformed updates, unknown stream
credit, and credit overflow rather than claiming those facts were usable. DATA consumes both receive
windows, including padding, before END_STREAM is accepted. An exhausted window is not itself an
error: without an authored grant, the observer may reach the exchange deadline.

Authored WINDOW_UPDATE frames use either `increment` or `payload_hex`, never both. Zero increment
and raw malformed payload lengths remain executable protocol-negative scripts. Authored DATA is
always literal, including deliberate over-credit frames; the runner does not wait for protocol
credit, split frames, or generate WINDOW_UPDATE. Receive credit increases only after an authored
update is actually written. An authored grant that makes credit unknowable still permits observing
peer control frames; subsequent DATA, including empty END_STREAM, is refused rather than certified
against an invalid ledger. One cleartext socket owner interleaves reads with partial literal writes,
so already available DATA is checked before later grants and an early stream reset can end an
unfinished request. GOAWAY alone does not end the selected stream. Request progress records actual
unpadded DATA payload writes at the first response head or a pre-head reset; padded authored DATA
leaves that application-byte count unavailable. An unfinished script is reported explicitly.
An external `--endpoint` runs authored frame scripts too: `http://` over cleartext with prior
knowledge (RFC 9113 section 3.3), and `https://` over TLS offering only ALPN `h2` (section 3.2),
with the same certificate trust as HTTP/1.1 (`--ca-cert`). Connection setup, TLS included, is the
target's time, as for HTTP/1.1. A TLS peer that selects no protocol, or ends the handshake with
`no_application_protocol`, is reported as an environment failure before any frame octet is
written. Inside TLS a write hands plaintext to the session rather than to the wire, so request-body
progress, `socket_read_after` and `connection_after` are reported unavailable instead of inferred
from TLS records; a TCP reset stays a measured `reset`. An end of stream without a `close_notify`
alert is noted on the case, and TLS records still queued when the exchange ends count as unwritten
authored frames. The in-harness production drivers still refuse `[connection.tls]`. While `--allow-external-fixtures` has an owned fixture active, the
read-only guard decodes every authored header block and allows only a GET, HEAD or OPTIONS
`:method`; `request.method` is not what the peer receives, and an undecodable block is refused as
unclassified. An interrupted block or an orphan CONTINUATION is not classified, because the peer
must end the connection there rather than run it. A server that does not speak cleartext HTTP/2 answers the preface as it sees fit, and
the case reports that answer rather than a capability the runner assumed.

A script may open more than one stream. The observed stream is the last one an authored HEADERS
frame opens; request trailers on an earlier stream do not move it. Each other stream a HEADERS frame
opened is read but not observed: nothing records whether it was answered. Its header blocks
are decompressed in order, because every block can change the shared HPACK dynamic table (RFC 9113
section 4.3); its DATA spends the shared connection window, whose limit still holds, while its own stream
window is not tracked, so a peer overrunning another stream's window is not detected; and its
WINDOW_UPDATE and RST_STREAM frames are recorded in `h2_control_frames` like the observed stream's.
A peer frame on a stream no authored HEADERS opened is still refused. Only the observed stream's
own credit and request progress are tracked: authored DATA on another stream spends connection
credit and is not the observed request's body. Stream identifiers are written exactly as authored,
so a lower identifier after a higher one, or a HEADERS frame inside another stream's unfinished
header block, stays an executable protocol violation. Reusing an identifier whose earlier request
has already been answered cannot be observed this way, because that answer ends the observation.

Authored `rst_stream`, `goaway`, `priority` and `raw` frames are written exactly as declared, and
the peer's reaction is observed like any other: a status, the received controls, and measured
termination. `rst_stream` and `goaway` take either `error_code` or a literal `payload_hex`, never
both. `error_code` is an RFC 9113 section 7 name such as `CANCEL` or `NO_ERROR`, or `0x` followed by
one to eight hexadecimal digits for an unregistered code. A `goaway` built from `error_code` carries
last-stream identifier zero, because a client has accepted no server-initiated stream, and defaults
to stream zero; spell any other last-stream identifier or debug data with `payload_hex`. `priority`
always spells its five-octet payload. None of the four accept `flags` or `increment`. A `raw` frame's
`payload_hex` is one complete frame, header included, whose declared length must equal the octets
that follow; it takes no `stream_id` or `error_code`, keeps the reserved stream-identifier bit as
written, and may not spell DATA, HEADERS, SETTINGS, WINDOW_UPDATE or CONTINUATION, whose typed forms
drive the runner's stream and credit accounting. Unknown extension types and deliberately unusual
flags are written as `raw` frames. When an authored violation follows the peer's initial grant,
delay it so the grant's arrival order is not left to scheduling.

Version 5 adds three things. An authored `ping` frame defaults to stream zero, accepts only the
`ack` flag, and always spells its `payload_hex`, written literally. A received PING acknowledgement
is recorded in `h2_control_frames` as `{ type = "ping", payload_hex = "<eight octets>" }`; a peer's
own PING without ACK is read and neither recorded nor answered. Acknowledgements are recorded only
for scripts that author a typed `ping`, so a version-4 script, which can spell PING only as `raw`,
keeps its version-4 control-frame list. And `expect.kind = "client_reset"`
names the one way a client reset of the selected stream becomes observable: a well-formed
(four-octet) authored RST_STREAM of the selected stream followed by a typed, eight-octet, stream-zero
PING. That PING is the reset barrier; a `raw` PING never is one. HTTP/2 processes a connection's frames in order, so its
acknowledgement shows the peer handled the reset first, and the observation ends when it arrives,
with the status and body received before it. Without such a PING, a client reset is not an end
condition and the observation ends only on a peer fact or the deadline. Two authored PINGs, typed or
raw, carrying the barrier's octets are refused, because an acknowledgement could not say which one
it answers. The acknowledgement shows the peer read the reset first; it does not by itself show what
the peer did with a response it had already queued.
`client_reset` requires a PING acknowledgement in the exact control-frame list and forbids
`stream_termination` and `body_bytes_before_error`.

Authored `rst_stream`, `goaway`, `priority` and `raw` frames are written exactly as declared, and
the peer's reaction is observed like any other: a status, the received controls, and measured
termination. `rst_stream` and `goaway` take either `error_code` or a literal `payload_hex`, never
both. `error_code` is an RFC 9113 section 7 name such as `CANCEL` or `NO_ERROR`, or `0x` followed by
one to eight hexadecimal digits for an unregistered code. A `goaway` built from `error_code` carries
last-stream identifier zero, because a client has accepted no server-initiated stream, and defaults
to stream zero; spell any other last-stream identifier or debug data with `payload_hex`. `priority`
always spells its five-octet payload. None of the four accept `flags` or `increment`. A `raw` frame's
`payload_hex` is one complete frame, header included, whose declared length must equal the octets
that follow; it takes no `stream_id` or `error_code`, keeps the reserved stream-identifier bit as
written, and may not spell DATA, HEADERS, SETTINGS, WINDOW_UPDATE or CONTINUATION, whose typed forms
drive the runner's stream and credit accounting. Unknown extension types and deliberately unusual
flags are written as `raw` frames. When an authored violation follows the peer's initial grant,
delay it so the grant's arrival order is not left to scheduling.

Version 5 adds three things. An authored `ping` frame defaults to stream zero, accepts only the
`ack` flag, and always spells its `payload_hex`, written literally. A received PING acknowledgement
is recorded in `h2_control_frames` as `{ type = "ping", payload_hex = "<eight octets>" }`; a peer's
own PING without ACK is read and neither recorded nor answered. Acknowledgements are recorded only
for scripts that author a typed `ping`, so a version-4 script, which can spell PING only as `raw`,
keeps its version-4 control-frame list. And `expect.kind = "client_reset"`
names the one way a client reset of the selected stream becomes observable: a well-formed
(four-octet) authored RST_STREAM of the selected stream followed by a typed, eight-octet, stream-zero
PING. That PING is the reset barrier; a `raw` PING never is one. HTTP/2 processes a connection's frames in order, so its
acknowledgement shows the peer handled the reset first, and the observation ends when it arrives,
with the status and body received before it. Without such a PING, a client reset is not an end
condition and the observation ends only on a peer fact or the deadline. Two authored PINGs, typed or
raw, carrying the barrier's octets are refused, because an acknowledgement could not say which one
it answers. The acknowledgement shows the peer read the reset first; it does not by itself show what
the peer did with a response it had already queued.
`client_reset` requires a PING acknowledgement in the exact control-frame list and forbids
`stream_termination` and `body_bytes_before_error`.

`expect.socket_read_after` independently asserts `no_termination_observed`, `eof`, or `reset`.
These values describe receive-side reads and a bounded final socket probe, not both TCP directions,
future socket state, or connection reusability. Missing measurements fail even an expectation of
`no_termination_observed`. GOAWAY while no termination is observed leaves `connection_after`
unavailable: it cannot honestly satisfy the older `open` assertion, which means reusable.

Use `expect.kind = "stream_reset"` only when the selected stream receives RST_STREAM before its
response head. This requires a control-frame expectation containing RST_STREAM and forbids a response status.
After a response head, use `stream_error`, `stream_termination = "reset"`, the received unpadded
`body_bytes_before_error`, and the exact control-frame expectation. A TCP reset alone cannot satisfy
that frame expectation. Neither form infers socket closure or connection reusability from a frame.

Versions 1 through 3 reject both new expectation fields and the new outcome; versions 1 through 4
reject authored `ping` frames, received `ping` control frames and `client_reset`. Existing version
1-4 cases need no edit; to use a version-5 addition, set `case.schema_version = 5`. Runners older than
this one refuse version 5 with the explicit "update the runner" error. Rust callers constructing an
`Observation` must initialize `h2_control_frames` to `None` unless their transport actually measures
supported controls; `Some([])` means measured absence. Initialize `socket_read_after` to `None`
unless receive-side termination is independently observed; never derive it from GOAWAY or a
Connection header. Exhaustive `ObservedH2ControlFrame` matches must handle `GoAway`, `WindowUpdate`
and, from conformance 0.13.0, `PingAck`. Exhaustive `Outcome` matches must handle `StreamReset`
separately from `ConnectionReset`, and from 0.13.0 `ClientReset`, which a transport may produce only
after it received the acknowledgement of a PING written after its own reset of the selected stream.
An HTTP/2 stream that ends abruptly after its head now reports the unpadded DATA octets received
before the end as `body_bytes_before_error` instead of leaving it unavailable.

### Comparing production transports

```bash
cargo run -p rustfs-gateway-conformance --bin rustfs-gateway-conformance -- \
  diff-transports --filter c-h2-0001 --profile aws
```

The parent independently loads and selects the corpus before comparing its two child reports.
Both reports must contain every selected case exactly once, with no extra cases. Shared capabilities
require identical results. Matching failures remain visible as common failures; parity alone does
not establish conformance success.

An applicable scripted HTTP/2 case has a separate capability contract: Hyper must actually pass,
and the self-held driver must report its exact HTTP/1.1-only refusal. The output retains both
observations under `capability difference`, outside the identical-result count. Case names and
child refusal text cannot create this exception; the parent derives it from validated case metadata.
Missing cases, unexpected skips, failed Hyper observations and unexplained child exits fail the
comparison. A self-held child exit of 3 is accepted only when every selected case satisfies that
complete capability contract; an empty selection or a Hyper environment failure cannot satisfy it.

## Why the schema looks like this

A static request/response pair cannot express the failures that actually take production down.
Arrival timing, mid-stream errors, cancellation, connection reuse, backpressure, clock skew, and
frame-level behaviour are all outside its reach — and the hardest known bugs in this space, the ones
where a client hangs forever rather than getting an error, live entirely in that space. The second
trap is assertion strength: a suite that checks status codes stays green through a rewrite that
changes element order, drops the XML namespace, or alters the `Content-Type`.

Each dimension below therefore has a field on day one.

| Dimension | Where it lives | What it exists to catch |
|---|---|---|
| Chunk arrival timing | `[[request.chunks]] delay_ms` | Chunked signing state machines, backpressure, timeouts |
| Abnormal termination | `[[request.chunks]] action` = `close` / `rst` / `half_close` / `tls_close_without_notify` | Truncated uploads accepted as complete; clients left hanging |
| Timeout and cancellation | `expect.timing.terminate_within_ms`, `controlChunk.action = "stall"` | The hang family, which no status assertion can see |
| Connection reuse | `connection.reuse` + `[[exchanges]]` + `expect.connection_after` | Keep-alive corruption, state leaking between requests |
| Backpressure | `connection.read_window_bytes`, `stop_reading` / `resume_reading` | Servers that buffer without limit when the client stops reading |
| Clock injection | `[clock] fixed`, `skew_ms`, `request_time`, `presign_expires_s` | Clock skew, presigned expiry — and determinism for any body containing a timestamp |
| TLS and h2 framing | `case.applies_to.http_versions` / `tls`, `connection.tls`, `request.h2_frames` | Cases meaningful only over h2 or only in cleartext; TLS truncation |
| Expectations beyond status | `expect.kind` = `response` / `stream_error` / `event_stream` / `hang` / `connection_reset` | Errors delivered inside a 200; bodies that simply stop |
| Failure after the head | `[setup.fault] at = "after_commit"` | The refusal a client cannot see in the status line, because the status line was already sent |
| Byte-exact bodies | `expect.body.exact_utf8` / `exact_hex` / `golden` | Element order, `xmlns`, empty-element rendering, whitespace |
| Header set assertions | `expect.headers_exact` / `headers_absent` / `header_order` | Headers that must **not** be present; casing and ordering |
| Traceability | `case.rationale`, `case.evidence[]` | Cases nobody dares delete; assertions nobody can justify |
| Quirk back-reference | `case.quirks[]` | The mutation gate's coverage matrix |
| Polarity | `case.polarity` | The negative-cases-outnumber-positive requirement |

### Why a fault is declared rather than arranged

Every other `[setup]` entry describes state that was already true when the request arrived: a bucket
that is not there, a key that is not there, an upload with one part in it. A backend discovers all of
those while a status is still choosable, so all of them are refused with a status of their own. That
is the behaviour most of the corpus is about, and it is why `[setup.objects] absent = true` cannot
express a copy that fails halfway.

`CompleteMultipartUpload`, `CopyObject` and `UploadPartCopy` send their head before they know the
outcome, because the work can outlast a client's timeout. After that point a failure has nowhere to
go but the body, under a status line that already says `200`. `[setup.fault]` is how a case says the
failure happens *there*:

```toml
[setup.fault]
operation = "CopyObject"
at = "after_commit"
code = "NoSuchKey"
```

The alternative — rearranging an implementation until one of its ordinary refusals arrives late — is
the thing this field exists to stop. It produces the same bytes and it moves the boundary every other
case in the family stands on: `c-copy-0034` and `c-mpu-0020` … `c-mpu-0026` each pin a refusal that
must be decided *before* the head goes out, and each of them turns into a `200` carrying an `<Error>`
the moment that check moves down. The two ledgers assert both halves together for that reason.

Only an operation that commits its head early may be named; `lint/fault-after-commit` denies any
other, because a fault at a point the operation never reaches is an assertion that cannot fail. The
list is held equal to the `ERROR_AFTER_200` table `cargo xtask codegen` lowers from the model.

One dimension is deliberately **not** in the schema: the internal assembly path
(`--transport hyper|conn`) is injected by the runner. Every case runs on both paths and the two runs
must agree case for case; a case that could name a path would be a case that hides a divergence.

## Conventions the schema cannot enforce

- **Naming.** `c-<domain>-<NNNN>`, four digits, allocated in order within a domain. The domain
  segment must equal the directory name, and the file must be named `<id>.toml`. Ids are permanent:
  a deleted case's number is never reused, because evidence and changelogs cite it.
- **Truncation is compositional.** There is no `truncate` action. Declare a length in the headers,
  send fewer bytes, then use a control chunk. One mechanism, no ambiguity about which one applies.
- **`close` versus `half_close`.** `close` makes the outcome unobservable, so a case using it can
  only assert "no success was received". Prefer `half_close`, which lets the server answer and lets
  the case assert the actual required error.
- **Two byte counters, deliberately distinct.** `expect.body_bytes_before_error` counts *response*
  bytes received before a stream failure. `expect.request_progress.body_bytes_sent_at_response`
  counts *request* body bytes the client had written when the response head arrived — that is the
  one that proves a request was refused before its payload was consumed. Conflating them produces
  cases that assert nothing.
- **Golden files.** Paths are relative to `conformance/`. One trailing newline in a golden file is
  stripped before comparison, because editors and CI add it; every other byte is significant.
- **Redaction.** `expect.body.redact` replaces the text of the named elements with `__REDACTED__` in
  both sides before comparison. Element presence and position are still asserted byte for byte. It
  exists so that a response containing a server-minted opaque value — upload id, continuation token,
  request id — can still be pinned to bytes. Redact the smallest possible set.
- **Interpolation.** `${capture.<name>}` is substituted in a `request` **before** signing, so an
  interpolated value is covered by the signature, and in an `expect` **before** the exchange is
  judged, so an assertion may name a value an earlier exchange produced. Captures come from
  `expect.capture` on an earlier exchange or from `setup.multipart_uploads[].capture_upload_id_as`;
  an expectation cannot name the capture its own exchange binds, because the expectation is judged
  first. Substitution applies to **values only** — a `${...}` written in a field name, such as a
  header name, is refused rather than left in place, so every reference in a case is either
  substituted or reported and none is silently ignored.
- **A captured `xml_text` is the value, not the wire form.** `expect.capture.<name>.xml_text` expands
  the XML entities in the element's text, so a captured `<ETag>&quot;abc-1&quot;</ETag>` is spendable
  as an `If-Match`. Assertions are the other way round: `contains_utf8`, `exact_utf8` and the `xml`
  block all judge the bytes that arrived, escaping included.
- **`headers_exact` excludes** the hop-by-hop headers the transport itself manages: `connection`,
  `keep-alive`, `transfer-encoding`, `date`. Assert those explicitly via `headers_present` when they
  are the subject of the case.
- **Signing is computed, never pasted.** Cases declare `sign.mode` and let the runner sign. Negative
  signature cases sign correctly and then alter exactly one canonical component via `sign.tamper`, so
  a failure names the component instead of reporting that a hex string did not match.
- **`timeout_ms` budgets the target, not the harness.** The runner measures its own waiting — authored
  `delay_ms` pacing, `stall` durations, teardown delays, the pauses between exchanges, and the window
  spent observing the connection after each answer — reports it as `harness_wait_ms`, and subtracts it
  before judging `case.timeout_ms`; the diagnostic prints the target's share, the whole, and the
  harness's share. A scheduler that overshoots one of those waits has not observed the target
  hanging. A declared delay must still fit the exchange's own timeout, which is checked before the
  bytes go out (rustfs/gateway#426).
- **Setup is not under test.** Fixtures may be established with normalised, correctly signed
  requests. Anything a case asserts must appear in `request` or `exchanges`.
- **Tag vocabulary.** `streaming`, `chunked`, `trailer`, `signature`, `sigv4`, `sigv2`, `presigned`,
  `xml`, `wire-bytes`, `etag`, `routing`, `vhost`, `conditional`, `preconditions`, `list`,
  `pagination`, `multipart`, `checksum`, `range`, `encoding`, `cors`, `preflight`, `encryption`, `lifecycle`, `replication`, `bucketconfig`, `region`, `security`, `dos`,
  `sse`, `timing`, `connection`, `event-stream`, `tls`, `h2`, `error-shape`, `known-divergence`, `tagging`,
  `object-lock`, `restore`, `select`, `acl`, `naming`, `object-attributes`, `read`, `validation`, `xml-shape`, `upload-id`, `limits`, `boundary`, `integrity`, `delimiter`, `versions`, `delete`, `framing`, `owner`, `root`, `storage-class`, `metadata`, `rfc9110`, `buckets`, `empty-elements`, `compatibility`, `round-trip`, `ordering`, `durability`, `head`, `batch`, `response-overrides`, `idempotence`, and `slow`. `slow` is reserved: it moves a case out of
  the pull-request gate and
  into the merge queue. `xml-shape` marks a case whose subject is the element layout of one response body — order, wrapping, which optional elements appear — where `xml` marks XML handling in general; `error-shape` likewise covers both the body and the diagnostic headers of a failed answer. `region` marks a case whose subject is the deployment's region posture — the
  location-constraint rules and the `x-amz-bucket-region` redirect contract. `object-lock` marks a
  case about the WORM family's codec — the lock configuration, retention and legal-hold documents;
  lock *enforcement* is later work and no case here asserts it. `restore` marks a case about
  archive retrieval — the four-state status mapping, the `RestoreRequest` document and the
  structured `x-amz-restore` header; how long a retrieval takes is the backend's and no case here
  asserts it. `select` marks a case about the select request codec or its answer, and
  `event-stream` marks a case that asserts the decoded frames of that answer: each
  `[[expect.events]]` selects frames by type — `event` messages by `:event-type`, or request-level
  error frames by `:error-code` when its `headers` name `message-type = "error"` — and asserts
  counts, a payload and per-frame headers, whose names are written without the leading colon. `acl` marks a case about the access control list family's
  codec — the two input channels, the canned-ACL sets, the grant-header grammar and the `xsi:type`
  discriminator; ACL *evaluation* is the deployment's authorizer's, and no case here asserts that a
  grant permits anything. `naming` marks a case about the single normalisation an object key
  and a bucket label go through — the slash policy, the one decode, the safety floor, and the
  two rules under which this gateway is deliberately stricter than AWS. `preflight` marks a case
  about the CORS **runtime** rather than its configuration codec — an `OPTIONS` answered from a
  stored document instead of being routed, the headers that answer carries, and the one refusal
  every failure shares; it appears beside `cors`, which stays on the codec cases as well.

## Cases and quirks reference each other

A quirk in `model/overlays/*.toml` is a protocol exception expressed as data — bare versus quoted ETag,
unwrapped versus wrapped XML output, an attribute rename. A case is an executable claim about
behaviour. Neither is trustworthy alone: a quirk nothing exercises is an unverified assertion, and a
case that cites no quirk cannot tell the mutation gate what it protects.

- **Case → quirk** is written by hand, in `case.quirks[]`. List every quirk the case would notice a
  change in, not merely the one that motivated it.
- **Quirk → case** is derived, never hand-maintained. The mutation gate inverts `case.quirks[]` into
  a quirk-to-case matrix, flips each quirk in turn, and requires that every quirk turns at least one
  case red. An unreferenced quirk fails CI, and so does a referenced quirk that no case actually
  detects — which is the failure a hand-written matrix would hide.
- A case may legitimately carry an empty `quirks` list while `model/overlays/` has no corresponding
  entry yet. The quirk ids in the cases here are forward references in exactly that sense: they are
  the names the quirk entries will be given, and the gate is what will hold the two sides together.

Consequences worth stating plainly: the mutation gate replaces any "minimum number of cases" guard,
which only prevents deletion and never detects weakness. And deleting a case file is a reviewed
event — `conformance/cases/**` is covered by the protected-files job precisely because deletion is
the cheapest way to make a suite green.

## Writing and validating cases

See [`cases/README.md`](cases/README.md) for the procedure. To check the corpus:

```bash
cargo xtask conformance validate          # schema + naming + golden references; executes nothing
cargo xtask conformance run --filter 'etag/'
```

Every case must be red or green for a stated reason. A case that cannot run yet is still committed:
a case that fails because the behaviour is unimplemented is useful, and a case that is missing
because the behaviour is unimplemented is how a gap becomes permanent.

## The baseline is complete, and a row is a claim

`baseline.json` holds one row per case — `"c-cond-0027": "passed"` — and **every case in the corpus
must have one**. That is a ruling, not an accident, and it is enforced by
`every_case_in_the_corpus_carries_a_baseline_row` in `crates/conformance/tests/corpus.rs`. Adding a
case means adding its row in the same commit; there is no allowlist.

The alternative — a curated file recording only the known-red cases — was rejected because it is
what the repository had, and it is unreadable. On `119570e` the file held 245 rows against 711
cases, and nothing anywhere said whether the other 466 were a deliberate omission or an oversight.
Four family ledgers had each grown a private copy of this same completeness check for their own
directory; twenty-one domains had none.

What a row does:

| row | meaning |
| --- | --- |
| `passed` | this case executes and holds. A run in which it **fails or skips** is a regression. |
| `skipped` | this case does not execute yet, and that is known. A run in which it fails is a regression; one in which it passes is an improvement. |
| `failed` | a tolerated known failure. Only this row excuses anything, and `scripts/check_baseline_ratchet.sh` refuses to let the set of them grow. |
| *(absent)* | read as `passed`, so forgetting a row is never quieter than writing one. |

The `passed` row is the one that had to be made load-bearing before completeness was worth
enforcing. Until rustfs/gateway#192 a skip could not be a regression, so a failing case with a
`passed` row and a failing case with no row took the identical branch: recording a case bought
nothing at all, and the file was a list of excuses wearing the shape of a table of expectations.
It also left the hole rustfs/gateway#203 and #214 both fell into — a domain that stops executing
turns into skips, and skips were free.

The in-process target that the gate runs cannot execute an authored HTTP/2 frame script and refuses
it by name. Recorded as `skipped`, every such row would be a ratchet that cannot fail, so the gate
re-runs exactly those refused cases on the production Hyper driver, the transport `conformance
baseline` itself uses, and their rows are measured verdicts.

Refreshing it:

```bash
cargo xtask conformance baseline > conformance/baseline.json
scripts/check_baseline_ratchet.sh
```

The ratchet only ever tightens: the `failed` set may shrink and never grow, and a case recorded
`passed` may not be re-recorded as `skipped`. A refresh that would violate either is a regression
being written down instead of fixed.

## Evidence and compliance

`case.evidence[]` records where a behavioural fact was observed: a URL plus one original sentence
written by the case author. Behavioural facts are not copyrightable, but the prose in an upstream
issue or pull request belongs to its author. The 200-character ceiling on `summary` is a compliance
control rather than a style rule — it makes pasting upstream text structurally impossible. Quote
nothing; describe the behaviour in your own words and link to the source.
