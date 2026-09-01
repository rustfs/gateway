# rustfs-gateway-conformance crate map

Agent entry point for the data-driven conformance runner. Design reasons live in module docs and
ADRs; this map only selects files.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and public runner surface. | Start here for a conformance task. |
| `src/main.rs` | CLI arguments and process exit classes. | The binary accepts or reports an option incorrectly. |
| `src/corpus.rs` | Corpus discovery, loading and selection. | A case is missing, duplicated or filtered wrongly. |
| `src/schema.rs` | Frozen schema validation. | A TOML shape is accepted or rejected incorrectly. |
| `src/toml.rs` | Minimal TOML value parser used by the corpus. | Syntax parsing fails before schema validation. |
| `src/runner.rs` | Case/exchange execution order and timeout coordination. | A case runs in the wrong order or never reaches a verdict. |
| `src/expect.rs` | Expected observation matching. | A response, stream error or timing assertion is judged wrongly. |
| `src/expect/events.rs` | Event-stream count and byte-exact payload matching. | An event payload expectation is ignored or misjudged. |
| `src/inprocess.rs` | In-process facade transport. | Hyper-independent execution differs from the socket path. |
| `src/inprocess/profile.rs` | Maps a claimed compatibility profile onto the measured facade policy. | A profile appears in reports but does not change target behavior. |
| `src/inprocess/security.rs` | Fixed authorization and bucket-owner sources for security cases. | A security case needs a deterministic allow, deny, or metadata-source outcome. |
| `src/observation.rs` | Response and event-stream observations, including frame validation. | An event-stream case is classified incorrectly. |
| `src/parity.rs` | Per-case verdict, phase, failure and skip-reason comparison. | Production transport results disagree or a case is missing. |
| `src/production.rs` | Production Hyper and self-held server assemblies with request pacing. | A transport label does not select the production driver it names. |
| `src/cli/parity.rs` | Isolated child-process orchestration for production transport comparison. | The parity command launches or collects one driver incorrectly. |
| `src/socket.rs` | Real socket transport and connection observations. | A wire-level close/reuse fact is wrong. |
| `src/socket/response.rs` | Fixed-length and chunked HTTP/1.1 response decoding. | A raw response body is truncated or framed incorrectly. |
| `src/conn/` | Connection state and reusable transport helpers. | A multi-exchange case loses connection state. |
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
| `src/report.rs` | Verdicts, the baseline table, and human/JSON/JUnit reports. | A verdict is rendered, grouped or compared against the baseline wrongly. |
| `tests/corpus.rs` | Corpus-wide invariants and the whole-corpus baseline gate. | A case has no baseline row, or the corpus regressed against it. |
| `src/lint.rs` | Corpus conventions beyond the JSON schema. | Case naming or evidence lint fails. |
| `tests/` | Process and corpus integration contracts. | Change runner behavior or CLI output. |
| `../../conformance/cases/**` | Executable S3 behavior cases. | Add or diagnose one protocol behavior. |
| `../../conformance/case.schema.json` | Frozen case format. | Never edit without the Breaking Change process. |
