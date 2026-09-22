# rustfs-gateway-conformance crate map

Agent entry point for the data-driven conformance runner. Design reasons live in module docs and
ADRs; this map only selects files.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and public runner surface. | Start here for a conformance task. |
| `src/main.rs` | CLI arguments and process exit classes. | The binary accepts or reports an option incorrectly. |
| `src/corpus.rs` | Corpus discovery, loading and selection. | A case is missing, duplicated or filtered wrongly. |
| `src/schema.rs`, `src/schema/computed_md5_tests.rs` | Frozen schema validation and computed-digest version boundaries. | A TOML shape is accepted or rejected incorrectly. |
| `src/toml.rs` | Minimal TOML value parser used by the corpus. | Syntax parsing fails before schema validation. |
| `src/runner.rs` | Case/exchange execution order and timeout coordination. | A case runs in the wrong order or never reaches a verdict. |
| `src/runner/budget_tests.rs` | The `case.timeout_ms` verdict: the target is charged, the harness's own waiting is not. | A timeout is judged on the wrong share of the wall time. |
| `src/runner/lifecycle_tests.rs` | Post-prepare cleanup and failure-classification regression coverage. | A runner early return may bypass fixture cleanup. |
| `src/runner/shard_tests.rs` | The `--shard` partition: every selected case exactly once, in corpus order, and the partial-run note. | Shards overlap, skip a case, or run silently as a whole. |
| `src/expect.rs` | Expected observation matching. | A response, stream error or timing assertion is judged wrongly. |
| `src/expect/events.rs` | Event-stream count and byte-exact payload matching. | An event payload expectation is ignored or misjudged. |
| `src/inprocess.rs` | In-process facade transport. | Hyper-independent execution differs from the socket path. |
| `src/inprocess/computed_md5.rs`, `src/inprocess/computed_md5_tests.rs` | Derives Content-MD5 from resolved payloads and rejects conflicting wire instructions. | A computed digest is missing, stale, or overwrites an authored header. |
| `src/inprocess/computed_md5_transport_tests.rs` | Captured-body digests, signing, and refusal controls over real sockets. | Computed MD5 or capture interpolation changes. |
| `src/inprocess/payload_literal.rs` | Turns `sign.payload_hash_literal` into the exact digest the signer signs as stated. | A case must sign the digest of bytes it does not send (c-sig-0596). |
| `src/inprocess/profile.rs` | Maps conformance profiles and deadlines onto measured facade policy. | A profile or timeout appears in cases but does not change target behavior. |
| `src/inprocess/security.rs` | Fixed authorization, dispatch observations, and bucket-owner sources for security cases. | A security case needs a deterministic policy, dispatch count, or metadata-source outcome. |
| `src/observation.rs` | Response and event-stream observations, including frame validation. | An event-stream case is classified incorrectly. |
| `src/observation/select_error_tests.rs` | Independent Select error goldens, malformed-frame controls, and production transport tests. | The encoder or observer changes request-level error framing. |
| `src/parity.rs` | Per-case verdict, phase, failure and skip-reason comparison. | Production transport results disagree or a case is missing. |
| `src/production.rs` | Production Hyper and self-held server assemblies with request pacing. | A transport label does not select the production driver it names. |
| `src/cli/parity.rs` | Isolated child-process orchestration for production transport comparison. | The parity command launches or collects one driver incorrectly. |
| `src/cli/usage.rs` | The usage text: every command, option, and exit code as the reader sees them. | An option is added, renamed, or its wording changes. |
| `src/cli/shard_tests.rs` | The `--shard` command-line contract: parsing, forwarding to the parity children, the partial-run exit code. | A shard option is parsed, forwarded, or classified wrongly. |
| `src/socket.rs` | Real socket transport and connection observations. | A wire-level close/reuse fact is wrong. |
| `src/socket/connect.rs` | Plain and TLS client connection setup, including absolute setup deadlines. | A TCP connect or TLS handshake escapes the case budget. |
| `src/socket/response.rs` | Fixed-length and chunked HTTP/1.1 response decoding. | A raw response body is truncated or framed incorrectly. |
| `src/socket/stream.rs` | The client transport under one connection: plain socket or TLS session. | Authored bytes are altered, or the socket underneath a TLS session is unobservable. |
| `src/conn/` | Connection state and reusable transport helpers. | A multi-exchange case loses connection state. |
| `src/conn/control_chunks.rs` | Control chunks on a socket exchange: body catch-up, stalls, teardowns, and what they charge to the harness account. | A `stall`, `half_close`, or `close` control chunk is carried out or timed wrongly. |
| `src/conn/bind.rs` | Queues a pacing rendezvous before a fresh socket connects. | A socket case skips only under scheduler load. |
| `src/conn/external.rs` | Authored HTTP/1.1 exchange against an external endpoint. | `--endpoint` connects, writes, or reports unavailable observations incorrectly. |
| `src/conn/external/tests.rs` | Authored-byte capture, early-response, refusal, and CLI controls for external endpoints. | External exchange or fixture behavior changes. |
| `src/conn/external_pacing.rs` | Cleartext external-body delays and early-response observation. | A delayed chunk is sent too early or after a response already exists. |
| `src/conn/external_endpoint.rs` | Strict HTTP(S) endpoint parsing, resolution, and protocol selection. | An endpoint scheme, authority, host, or default port is handled incorrectly. |
| `src/conn/external_fixture.rs` | Opt-in external owned-bucket/object planning and read-only enforcement. | A remote fixture shape or authored mutation is accepted incorrectly. |
| `src/conn/external_fixture/clock.rs` | Current UTC signing time for external fixture controls. | A control request is rejected as stale or future-dated. |
| `src/conn/external_fixture/lifecycle.rs` | Applies validated external plans and cleans owned objects before buckets. | A remote create, ownership transition, rollback, or cleanup order is wrong. |
| `src/conn/external_fixture/object.rs` | Decodes and validates unversioned object fixture payloads, headers, and paths. | An external object fixture loses bytes or sends an unsafe control request. |
| `src/conn/external_fixture/object_tests.rs` | Real-socket ownership and refusal controls for external object fixtures. | Object fixture planning or cleanup behavior changes. |
| `src/conn/external_fixture/region.rs` | Fixture region validation, signing scope, and CreateBucketConfiguration XML. | A remote bucket is created or signed for the wrong region. |
| `src/conn/external_fixture/runner_tests.rs` | Full CLI-to-external-endpoint fixture lifecycle regression coverage. | The runner does not create, exercise, or clean up an opted-in remote fixture. |
| `src/conn/external_tls.rs` | Verified TLS client setup with public and explicit CA roots. | HTTPS trust, ALPN, or certificate failure classification is wrong. |
| `src/conn/h2.rs` | Authored `request.h2_frames` scripts: exact preface and frame envelopes to production Hyper, and the response read back off peer frames. | A frame script is refused wrongly, written differently from its declaration, or its response is misread. |
| `src/conn/h2/hpack.rs` | HPACK decoding of the peer's response header blocks, dynamic table included. | A decoded response header is wrong, or a malformed block is accepted. |
| `src/conn/h2/huffman.rs` | RFC 7541 Huffman decoding for HPACK string literals. | A Huffman-coded header name or value decodes wrongly. |
| `src/conn/h2/tests.rs` | Refusals, the exact wire image, the peer-frame reader, and HPACK controls for authored HTTP/2. | Authored HTTP/2 behavior changes. |
| `src/inprocess/h2_frames.rs` | Reads `request.h2_frames` into typed, ordered frame declarations. | A declared frame field is lost before a transport sees it. |
| `src/conn/server.rs` | Lazily assembles test and production listeners with the case clock and profile. | The socket transports assemble a different policy from in-process execution. |
| `src/sign.rs` | Request signing for corpus inputs. | A signed case sends the wrong request. |
| `src/fixture.rs` | Deterministic fixture backend used by local runs. | Setup state or a fixture operation behaves wrongly. |
| `src/fixture/committed.rs` | Late-failure work and frozen response heads for committed fixture operations. | Copy or multipart completion loses its pre-commit metadata. |
| `src/fixture/handlers_bucket.rs` | Bucket Handler entries for the deterministic fixture. | A bucket operation stops reaching existing fixture behavior. |
| `src/token.rs` | The continuation-token codec: an HMAC-authenticated page position bound to its listing. | A cursor is honoured that this service did not issue, or a real one is refused. |
| `src/fixture/pagination_properties.rs` | Generated set semantics for the fixture's paging. | A resumed page skips or repeats an entry. |
| `src/fixture/list_allocations.rs` | What one page of a listing costs, under a heap profiler. | A listing allocates in proportion to the bucket rather than the page. |
| `src/fixture/handlers_object.rs` | Object, multipart, listing, and event Handler entries for the deterministic fixture. | An object-family operation stops reaching existing fixture behavior. |
| `src/keys/` | Schema-key consumption audit. | A declared case key is parsed but ignored. |
| `src/external_junit_tests.rs` | Independently parses external CLI JUnit reports and tests write failures. | The external CLI reporting composition changes. |
| `src/report.rs` | Verdicts, the baseline table, and human/JSON/JUnit reports. | A verdict is rendered, grouped or compared against the baseline wrongly. |
| `tests/corpus.rs` | Corpus-wide invariants and the whole-corpus baseline gate. | A case has no baseline row, or the corpus regressed against it. |
| `tests/encryption_blocked_types.rs` | The SSE-C `BlockedEncryptionTypes` refusal over a declared TLS transport, which the cleartext corpus cannot reach, in both directions. | Changing how the fixture enforces a bucket's blocked encryption types. |
| `src/lint.rs` | Corpus conventions beyond the JSON schema. | Case naming or evidence lint fails. |
| `tests/` | Process and corpus integration contracts. | Change runner behavior or CLI output. |
| `../../conformance/cases/**` | Executable S3 behavior cases. | Add or diagnose one protocol behavior. |
| `../../conformance/case.schema.json` | Frozen case format. | Never edit without the Breaking Change process. |
